"""
Health checking and failover for upstream proxy mode.

This addon owns the process-wide `UpstreamRegistry`, validates the health
policy options, actively probes unhealthy upstream proxy servers, and exposes
their status through the `upstream.status` / `upstream.recover` commands. The
proxy layers make the actual per-connection selection, see
`mitmproxy.proxy.layers.http`.
"""

from __future__ import annotations

import asyncio
import logging
import math
import ssl

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy.net import server_spec
from mitmproxy.proxy import mode_specs
from mitmproxy.proxy import upstreams
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class UpstreamHealth:
    registry: upstreams.UpstreamRegistry
    _probe_task: asyncio.Task | None
    _running: bool

    def __init__(self) -> None:
        self.registry = upstreams.UpstreamRegistry()
        self._probe_task = None
        self._running = False

    def load(self, loader):
        loader.add_option(
            "upstream_health_check",
            bool,
            False,
            """
            Enable health-based upstream proxy selection: Track connection,
            TLS and CONNECT handshake failures, mark proxy servers as degraded
            or unavailable, fail new connections over to other servers declared
            in `upstream:` mode specs, and actively probe unhealthy servers.
            Has no effect outside upstream proxy mode.
            """,
        )
        loader.add_option(
            "upstream_probe_interval",
            float,
            10.0,
            """
            Interval in seconds at which unhealthy (degraded or unavailable)
            upstream proxy servers are actively probed. Must be greater than 0.
            """,
        )
        loader.add_option(
            "upstream_failover_threshold",
            int,
            3,
            """
            Number of consecutive connection failures after which an upstream
            proxy server is considered unavailable and skipped by new
            connections. Must be at least 1.
            """,
        )
        loader.add_option(
            "upstream_failover_strategy",
            str,
            "sequential",
            """
            Strategy used to select an upstream proxy server. "sequential"
            always prefers the first declared server that is not unavailable.
            "avoid-failures" prefers healthy servers over degraded ones and
            then the server with the fewest consecutive failures.
            """,
            choices=("sequential", "avoid-failures"),
        )
        loader.add_option(
            "upstream_recovery",
            str,
            "auto",
            """
            Controls when new connections move back to a recovered upstream
            proxy server. "auto" switches back as soon as a server is healthy
            again, "manual" keeps the current server and waits for an explicit
            `upstream.recover` command.
            """,
            choices=("auto", "manual"),
        )

    def _configured_servers(self) -> list[server_spec.ServerSpec]:
        ordered: list[server_spec.ServerSpec] = []
        for raw_mode in ctx.options.mode:
            try:
                mode = mode_specs.ProxyMode.parse(raw_mode)
            except ValueError:
                continue
            if isinstance(mode, mode_specs.UpstreamMode):
                for spec in mode.servers:
                    if spec not in ordered:
                        ordered.append(spec)
        return ordered

    def configure(self, updated) -> None:
        relevant = {
            "upstream_health_check",
            "upstream_probe_interval",
            "upstream_failover_threshold",
            "upstream_failover_strategy",
            "upstream_recovery",
            "mode",
        }
        if not relevant.intersection(updated):
            return

        interval = ctx.options.upstream_probe_interval
        if not math.isfinite(interval) or interval <= 0:
            raise exceptions.OptionsError(
                f"Invalid value for upstream_probe_interval: {interval!r}. "
                "The interval must be a finite number of seconds greater than 0."
            )

        threshold = ctx.options.upstream_failover_threshold
        if threshold < 1:
            raise exceptions.OptionsError(
                f"Invalid value for upstream_failover_threshold: {threshold!r}. "
                "The threshold must be at least 1."
            )

        self.registry.configure(
            upstreams.UpstreamSettings(
                enabled=bool(ctx.options.upstream_health_check),
                probe_interval=float(interval),
                failure_threshold=threshold,
                strategy=ctx.options.upstream_failover_strategy,
                recovery=ctx.options.upstream_recovery,
            ),
            self._configured_servers(),
        )

        if self._running:
            self._restart_probe_loop()

    def running(self) -> None:
        self._running = True
        self._restart_probe_loop()

    def done(self) -> None:
        self._running = False
        if self._probe_task is not None:
            self._probe_task.cancel()
            self._probe_task = None

    def _restart_probe_loop(self) -> None:
        if self._probe_task is not None:
            self._probe_task.cancel()
        self._probe_task = asyncio_utils.create_task(
            self._probe_loop(),
            name="upstream health probes",
            keep_ref=True,
        )

    async def _probe_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.registry.settings.probe_interval)
                await self.probe_once()
        except asyncio.CancelledError:
            return

    async def probe_once(self) -> None:
        """Actively probe every degraded or unavailable upstream proxy server."""
        for spec in list(self.registry.unhealthy()):
            ok, error, kind = await self._probe(
                spec, self.registry.settings.probe_interval
            )
            self.registry.record(spec, ok, error=error, kind=kind)
            self._log_events()

    @staticmethod
    async def _probe(
        spec: server_spec.ServerSpec, timeout: float
    ) -> tuple[bool, str | None, upstreams.FailureKind | None]:
        scheme, (host, port) = spec
        try:
            if scheme == "https":
                tls_ctx = ssl.create_default_context()
                tls_ctx.check_hostname = False
                tls_ctx.verify_mode = ssl.CERT_NONE
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host,
                        port,
                        ssl=tls_ctx,
                        server_hostname=host,
                    ),
                    timeout=max(timeout, 1.0),
                )
            else:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=max(timeout, 1.0),
                )
            # The probe only checks reachability, there is no need to half-close.
            writer.close()
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
            err = str(e) or "connection failed"
            return False, err, upstreams.classify_failure(err)
        return True, None, None

    def _log_events(self) -> None:
        for level, message in self.registry.drain_events():
            logger.log(level, message)

    @command.command("upstream.status")
    def status(self) -> str:
        """
        Show the health state, failure counts and most recent failure reason of
        every configured upstream proxy server.
        """
        servers = self._configured_servers()
        if not servers:
            return "No upstream proxy servers configured."
        return self.registry.format_status(servers)

    @command.command("upstream.recover")
    def recover(self, spec: str = "") -> None:
        """
        Mark an upstream proxy server as recovered and allow new connections to
        use it again. Without an argument, all upstream proxy servers are
        recovered. Specify the server as `http://host:port` or `https://host:port`.
        """
        target: server_spec.ServerSpec | None = None
        if spec:
            try:
                parsed_scheme, parsed_address = server_spec.parse(
                    spec, default_scheme="http"
                )
            except ValueError as e:
                raise exceptions.CommandError(str(e))
            target = (parsed_scheme, parsed_address)
            if target not in self._configured_servers():
                raise exceptions.CommandError(
                    f"{upstreams.format_spec(target)} is not a configured "
                    f"upstream proxy server."
                )
        self.registry.recover(target)
        self._log_events()
