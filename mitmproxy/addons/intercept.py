import asyncio
import logging
from typing import Optional

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import flowfilter
from mitmproxy import hooks
from mitmproxy.log import ALERT
from mitmproxy.utils import human

logger = logging.getLogger(__name__)


class Intercept:
    filt: flowfilter.TFilter | None = None
    timeout: float | None = None
    timeout_action: str = flow.INTERCEPT_ACTION_FORWARD

    def __init__(self) -> None:
        # Per-flow timeout handles, keyed by flow ID. Only flows that entered
        # interception while a timeout was configured appear here.
        self._timers: dict[str, asyncio.Handle] = {}

    def load(self, loader):
        loader.add_option("intercept_active", bool, False, "Intercept toggle")
        loader.add_option(
            "intercept", Optional[str], None, "Intercept filter expression."
        )
        loader.add_option(
            "intercept_timeout",
            Optional[str],
            None,
            """
            Maximum time an intercepted flow waits for a manual decision before
            the configured default action is applied. Understands s/m/h suffixes,
            i.e. 30s for 30 seconds. If unset, intercepted flows wait indefinitely.
            The timeout only applies to flows that enter interception after it is set.
            """,
        )
        loader.add_option(
            "intercept_timeout_action",
            str,
            flow.INTERCEPT_ACTION_FORWARD,
            "Action taken when an intercepted flow reaches its intercept_timeout: "
            "either forward or kill the flow.",
            choices=(
                flow.INTERCEPT_ACTION_FORWARD,
                flow.INTERCEPT_ACTION_KILL,
            ),
        )

    def configure(self, updated):
        if "intercept" in updated:
            if ctx.options.intercept:
                try:
                    self.filt = flowfilter.parse(ctx.options.intercept)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
                ctx.options.intercept_active = True
            else:
                self.filt = None
                ctx.options.intercept_active = False
        if "intercept_timeout" in updated:
            try:
                timeout = human.parse_duration(ctx.options.intercept_timeout)
            except ValueError as e:
                raise exceptions.OptionsError(
                    f"Invalid intercept_timeout specification: "
                    f"{ctx.options.intercept_timeout!r} ({e})"
                ) from e
            if timeout is not None and timeout <= 0:
                raise exceptions.OptionsError(
                    f"Invalid intercept_timeout specification: "
                    f"{ctx.options.intercept_timeout!r} (must be greater than zero)"
                )
            self.timeout = timeout
        if "intercept_timeout_action" in updated:
            action = ctx.options.intercept_timeout_action
            if action not in (
                flow.INTERCEPT_ACTION_FORWARD,
                flow.INTERCEPT_ACTION_KILL,
            ):
                raise exceptions.OptionsError(
                    f"Invalid intercept_timeout_action: {action!r}."
                )
            self.timeout_action = action

    def should_intercept(self, f: flow.Flow) -> bool:
        return bool(
            ctx.options.intercept_active
            and self.filt
            and self.filt(f)
            and not f.is_replay
        )

    def process_flow(self, f: flow.Flow) -> None:
        if self.should_intercept(f) and f.intercept():
            self._schedule_timeout(f)

    def _schedule_timeout(self, f: flow.Flow) -> None:
        # Capture the configuration in effect when interception starts. Later
        # option changes must not affect flows that are already waiting.
        delay = self.timeout
        if delay is None:
            return
        action = self.timeout_action
        if old := self._timers.pop(f.id, None):
            old.cancel()
        self._timers[f.id] = asyncio.get_running_loop().call_later(
            delay, self._on_timeout, f, action
        )

    def _on_timeout(self, f: flow.Flow, action: str) -> None:
        self._timers.pop(f.id, None)
        if not f.intercepted:
            # The flow was resumed or killed manually before the timeout fired.
            return
        if action == flow.INTERCEPT_ACTION_KILL:
            if not f.killable:
                # The underlying connection is already gone, leave the flow to
                # the existing connection teardown.
                return
            entry = f._resolve_interception(
                flow.INTERCEPT_ACTION_KILL, flow.INTERCEPT_DISPOSITION_TIMEOUT
            )
            f.kill()
            result = "killed"
        else:
            entry = f._resolve_interception(
                flow.INTERCEPT_ACTION_FORWARD, flow.INTERCEPT_DISPOSITION_TIMEOUT
            )
            f.resume()
            result = "forwarded"
        if entry is not None:
            logger.log(
                ALERT,
                f"Intercept timeout after {human.pretty_duration(entry['wait_seconds'])}: "
                f"flow {result}.",
            )
        ctx.master.addons.trigger(hooks.UpdateHook([f]))

    def done(self) -> None:
        # Pending timeouts simply disappear with the event loop, matching the
        # existing shutdown semantics for flows that are still intercepted.
        for handle in self._timers.values():
            handle.cancel()
        self._timers.clear()

    # Handlers

    def request(self, f):
        self.process_flow(f)

    def response(self, f):
        self.process_flow(f)

    def tcp_message(self, f):
        self.process_flow(f)

    def udp_message(self, f):
        self.process_flow(f)

    def dns_request(self, f):
        self.process_flow(f)

    def dns_response(self, f):
        self.process_flow(f)

    def websocket_message(self, f):
        self.process_flow(f)
