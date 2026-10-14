"""
In-process health tracking and failover selection for upstream proxy servers.

This module is deliberately I/O-free and synchronous: all proxy connection
handlers run in the same asyncio event loop thread, so a plain state machine
gives every concurrent connection a single, consistent view of each upstream
proxy's health. Active probing is driven by the `upstream_health` addon, which
feeds probe results back into the registry.

Health is tracked per server specification (`(scheme, (host, port))`), so that
state is shared between all client connections and survives proxy mode
reconfiguration as long as the same upstream server is still configured.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable
from collections.abc import Sequence
from dataclasses import dataclass
from logging import INFO
from logging import WARNING
from typing import Literal

from mitmproxy.net import server_spec

ServerSpec = server_spec.ServerSpec

FailoverStrategy = Literal["sequential", "avoid-failures"]
"""
- ``sequential``: use the first server in declaration order that is not
  unavailable, even if it is degraded.
- ``avoid-failures``: prefer an available server over a degraded one, then the
  server with the fewest consecutive failures, then declaration order.
"""

RecoveryMode = Literal["auto", "manual"]
"""
- ``auto``: move new connections back to a recovered server automatically.
- ``manual``: keep using the current server until it becomes unavailable or an
  operator explicitly calls the ``upstream.recover`` command.
"""

LogEvent = tuple[int, str]


class UpstreamHealth(str, enum.Enum):
    """The health state of an upstream proxy server."""

    AVAILABLE = "available"
    """No outstanding failures, new connections may use this server."""

    DEGRADED = "degraded"
    """One or more consecutive failures, but below the failure threshold."""

    UNAVAILABLE = "unavailable"
    """The consecutive failure threshold has been reached, new connections avoid this server."""


class FailureKind(str, enum.Enum):
    """The kind of the most recent failure, used for status reporting."""

    CONNECT = "connect"
    """The TCP connection could not be established (unreachable, connection refused, ...)."""

    TLS = "tls"
    """The TLS handshake with the upstream proxy failed."""

    HANDSHAKE = "handshake"
    """The HTTP CONNECT handshake with the upstream proxy failed or was rejected."""


def classify_failure(error: str | None) -> FailureKind:
    """
    Best-effort classification of the aggregated error string produced while
    establishing a connection through an upstream proxy.
    """
    err = (error or "").lower()
    if "refused http connect" in err or err.startswith("error connecting to"):
        return FailureKind.HANDSHAKE
    if "ssl" in err or "tls" in err or "handshake" in err:
        return FailureKind.TLS
    return FailureKind.CONNECT


def format_spec(spec: ServerSpec) -> str:
    scheme, (host, port) = spec
    return f"{scheme}://{host}:{port}"


@dataclass
class UpstreamStatus:
    """Mutable health information for a single upstream proxy server."""

    spec: ServerSpec
    state: UpstreamHealth = UpstreamHealth.AVAILABLE
    consecutive_failures: int = 0
    total_failures: int = 0
    last_error: str | None = None
    last_error_kind: FailureKind | None = None
    last_changed: float = 0.0
    last_attempt: float | None = None
    last_success: float | None = None


@dataclass
class UpstreamSettings:
    """Configurable health policy, updated by the `upstream_health` addon."""

    enabled: bool = False
    probe_interval: float = 10.0
    failure_threshold: int = 3
    strategy: FailoverStrategy = "sequential"
    recovery: RecoveryMode = "auto"


class UpstreamRegistry:
    """
    Shared registry holding the health state of all configured upstream proxy
    servers and deciding which server a new connection should use.
    """

    settings: UpstreamSettings

    def __init__(
        self,
        settings: UpstreamSettings | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings or UpstreamSettings()
        self._clock = clock
        self._statuses: dict[ServerSpec, UpstreamStatus] = {}
        self._known: set[ServerSpec] = set()
        self._events: list[LogEvent] = []
        # The server currently carrying new connections, keyed by the declared
        # server list so that different upstream mode listeners stay independent.
        self._active: dict[tuple[ServerSpec, ...], ServerSpec] = {}
        # Remembers whether we have already logged the "all down" event for a
        # given server list, to avoid logging it for every client request.
        self._all_down: dict[tuple[ServerSpec, ...], bool] = {}

    # ------------------------------------------------------------------ config

    def is_active_for(self, servers: Sequence[ServerSpec]) -> bool:
        """Failover/health handling is active for multiple servers or if explicitly enabled."""
        return self.settings.enabled or len(servers) > 1

    def configure(
        self,
        settings: UpstreamSettings,
        known: Sequence[ServerSpec],
    ) -> None:
        self.settings = settings
        known_set = set(known)
        for spec in set(self._statuses) - known_set:
            del self._statuses[spec]
        self._known = known_set
        self._active = {
            servers: spec
            for servers, spec in self._active.items()
            if spec in known_set and all(s in known_set for s in servers)
        }
        self._all_down = {
            servers: down
            for servers, down in self._all_down.items()
            if all(s in known_set for s in servers)
        }

    # ----------------------------------------------------------------- queries

    def status(self, spec: ServerSpec) -> UpstreamStatus:
        try:
            return self._statuses[spec]
        except KeyError:
            entry = UpstreamStatus(spec=spec)
            self._statuses[spec] = entry
            return entry

    def unhealthy(self) -> list[ServerSpec]:
        """Servers that should be actively probed (degraded or unavailable)."""
        return [
            spec
            for spec, st in self._statuses.items()
            if st.state is not UpstreamHealth.AVAILABLE
        ]

    def drain_events(self) -> list[LogEvent]:
        """Return and clear log events produced by the last state-changing calls."""
        events = self._events
        self._events = []
        return events

    # --------------------------------------------------------------- selection

    def select(
        self,
        servers: Sequence[ServerSpec],
        tried: Sequence[ServerSpec] = (),
    ) -> ServerSpec | None:
        """
        Select the upstream proxy server to use for a new connection attempt.

        ``tried`` lists servers that have already been attempted for the
        connection currently being established and must not be selected again.
        Returns ``None`` if no eligible server remains.
        """
        if not servers:
            return None
        key = tuple(servers)
        candidates = [
            spec
            for spec in servers
            if spec not in tried
            and self.status(spec).state is not UpstreamHealth.UNAVAILABLE
        ]
        if not candidates:
            if not self._all_down.get(key, False):
                self._all_down[key] = True
                self._events.append(
                    (
                        WARNING,
                        f"All upstream proxy servers are unavailable: "
                        f"{', '.join(format_spec(s) for s in servers)}.",
                    )
                )
            return None
        self._all_down[key] = False

        active = self._active.get(key)
        if self.settings.recovery == "manual" and active in candidates:
            return active

        if self.settings.strategy == "avoid-failures":
            chosen = min(
                candidates,
                key=lambda spec: (
                    0 if self.status(spec).state is UpstreamHealth.AVAILABLE else 1,
                    self.status(spec).consecutive_failures,
                    servers.index(spec),
                ),
            )
        else:
            chosen = candidates[0]

        if active is not None and active != chosen:
            self._events.append(
                (
                    WARNING,
                    f"Upstream failover: new connections now use "
                    f"{format_spec(chosen)} instead of {format_spec(active)}.",
                )
            )
        self._active[key] = chosen
        return chosen

    # ---------------------------------------------------------------- outcomes

    def record(
        self,
        spec: ServerSpec,
        ok: bool,
        *,
        error: str | None = None,
        kind: FailureKind | None = None,
    ) -> None:
        """Record the result of a connection establishment attempt or a probe."""
        st = self.status(spec)
        now = self._clock()
        st.last_attempt = now
        if ok:
            recovered = st.state is UpstreamHealth.UNAVAILABLE
            if st.state is not UpstreamHealth.AVAILABLE or st.consecutive_failures:
                st.state = UpstreamHealth.AVAILABLE
                st.consecutive_failures = 0
                st.last_error = None
                st.last_error_kind = None
                st.last_changed = now
            st.last_success = now
            if recovered:
                self._events.append(
                    (
                        INFO,
                        f"Upstream proxy {format_spec(spec)} has recovered and is "
                        f"available again.",
                    )
                )
        else:
            st.consecutive_failures += 1
            st.total_failures += 1
            st.last_error = error or "unknown error"
            st.last_error_kind = kind or classify_failure(error)
            new_state = (
                UpstreamHealth.DEGRADED
                if st.consecutive_failures < self.settings.failure_threshold
                else UpstreamHealth.UNAVAILABLE
            )
            if new_state is not st.state:
                st.state = new_state
                st.last_changed = now
                if new_state is UpstreamHealth.UNAVAILABLE:
                    self._events.append(
                        (
                            WARNING,
                            f"Upstream proxy {format_spec(spec)} is now unavailable "
                            f"after {st.consecutive_failures} consecutive failure(s) "
                            f"(last error: {st.last_error}).",
                        )
                    )
                else:
                    self._events.append(
                        (
                            INFO,
                            f"Upstream proxy {format_spec(spec)} is degraded after "
                            f"{st.consecutive_failures} consecutive failure(s) "
                            f"(last error: {st.last_error}).",
                        )
                    )

    # ------------------------------------------------------------------ errors

    def aggregate_error(self, servers: Sequence[ServerSpec]) -> str:
        """One summary error listing each server's state and most recent failure."""
        lines = [
            "Could not establish the connection via any configured upstream proxy server:"
        ]
        for spec in servers:
            st = self.status(spec)
            reason = st.last_error or "no recent error"
            lines.append(
                f"  {format_spec(spec)}: {st.state.value} "
                f"({st.consecutive_failures} consecutive failure(s), "
                f"{st.total_failures} total), last error: {reason}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------- manual ops

    def recover(self, spec: ServerSpec | None = None) -> None:
        """
        Manually mark one (or all) upstream proxy servers as recovered and clear
        the sticky server selection so that the next connection is re-evaluated.
        """
        targets = [spec] if spec is not None else list(self._statuses)
        for target in targets:
            st = self._statuses.get(target)
            if st is None:
                continue
            st.state = UpstreamHealth.AVAILABLE
            st.consecutive_failures = 0
            st.last_error = None
            st.last_error_kind = None
            st.last_changed = self._clock()
            for key in list(self._active):
                if target is None or target in key:
                    del self._active[key]
                    self._all_down.pop(key, None)
            self._events.append(
                (
                    INFO,
                    f"Upstream proxy {format_spec(target)} has been marked as "
                    f"recovered by the operator.",
                )
            )

    def format_status(self, ordered: Sequence[ServerSpec]) -> str:
        """Human-readable overview, as returned by the `upstream.status` command."""
        lines = ["Upstream proxy servers:"]
        for spec in ordered:
            st = self.status(spec)
            line = (
                f"  {format_spec(spec)}: {st.state.value} "
                f"({st.consecutive_failures} consecutive failure(s), "
                f"{st.total_failures} total)"
            )
            if st.last_error:
                line += f", last error: {st.last_error}"
            lines.append(line)
        return "\n".join(lines)
