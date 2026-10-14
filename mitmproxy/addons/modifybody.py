import logging
import re
from collections.abc import Sequence

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy.addons import rewritetrace
from mitmproxy.addons.modifyheaders import ModifySpec
from mitmproxy.addons.modifyheaders import parse_modify_spec
from mitmproxy.log import ALERT

logger = logging.getLogger(__name__)


class ModifyBody:
    def __init__(self) -> None:
        self.replacements: list[ModifySpec] = []
        # verbatim rule texts, aligned by index with self.replacements
        self.raw_rules: list[str] = []

    def load(self, loader):
        loader.add_option(
            "modify_body",
            Sequence[str],
            [],
            """
            Replacement pattern of the form "[/flow-filter]/regex/[@]replacement", where
            the separator can be any character. The @ allows to provide a file path that
            is used to read the replacement string.
            """,
        )

    def configure(self, updated):
        if "modify_body" in updated:
            self.replacements = []
            self.raw_rules = []
            for option in ctx.options.modify_body:
                try:
                    spec = parse_modify_spec(option, True)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse modify_body option {option}: {e}"
                    ) from e

                self.replacements.append(spec)
                self.raw_rules.append(option)

        stream_and_modify_conflict = (
            ctx.options.modify_body
            and ctx.options.stream_large_bodies
            and ("modify_body" in updated or "stream_large_bodies" in updated)
        )
        if stream_and_modify_conflict:
            logger.log(
                ALERT,
                "Both modify_body and stream_large_bodies are active. "
                "Streamed bodies will not be modified.",
            )

    def request(self, flow):
        if flow.response or flow.error or not flow.live:
            return
        self.apply(flow, "request")

    def response(self, flow):
        if flow.error or not flow.live:
            return
        self.apply(flow, "response")

    def apply(self, flow, phase: str, trace: rewritetrace.Recorder | None = None):
        if trace is None:
            trace = rewritetrace.begin("modify_body", phase, flow, self.raw_rules)
        for i, spec in enumerate(self.replacements):
            if not spec.matches(flow):
                continue
            try:
                replacement = spec.read_replacement()
            except OSError as e:
                logging.warning(f"Could not read replacement file: {e}")
                if trace is not None:
                    trace.matched(i, error=e)
                continue
            message = flow.response if flow.response else flow.request
            before = message.content
            after = re.sub(
                spec.subject,
                lambda _: replacement,
                before,
                flags=re.DOTALL,
            )
            message.content = after
            if trace is not None:
                if after != before:
                    trace.hit(i, detail=f"{phase} body rewritten")
                else:
                    trace.matched(
                        i,
                        detail="flow filter matched, but the regex did not match the body",
                    )
        if trace is not None:
            trace.finish()
