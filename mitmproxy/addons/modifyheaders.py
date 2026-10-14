import logging
import re
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.addons import rewritetrace
from mitmproxy.http import Headers
from mitmproxy.utils import strutils
from mitmproxy.utils.spec import parse_spec


class ModifySpec(NamedTuple):
    matches: flowfilter.TFilter
    subject: bytes
    replacement_str: str

    def read_replacement(self) -> bytes:
        """
        Process the replacement str. This usually just involves converting it to bytes.
        However, if it starts with `@`, we interpret the rest as a file path to read from.

        Raises:
            - IOError if the file cannot be read.
        """
        if self.replacement_str.startswith("@"):
            return Path(self.replacement_str[1:]).expanduser().read_bytes()
        else:
            # We could cache this at some point, but unlikely to be a problem.
            return strutils.escaped_str_to_bytes(self.replacement_str)


def parse_modify_spec(option: str, subject_is_regex: bool) -> ModifySpec:
    flow_filter, subject_str, replacement = parse_spec(option)

    subject = strutils.escaped_str_to_bytes(subject_str)
    if subject_is_regex:
        try:
            re.compile(subject)
        except re.error as e:
            raise ValueError(f"Invalid regular expression {subject!r} ({e})")

    spec = ModifySpec(flow_filter, subject, replacement)

    try:
        spec.read_replacement()
    except OSError as e:
        raise ValueError(f"Invalid file path: {replacement[1:]} ({e})")

    return spec


class ModifyHeaders:
    def __init__(self) -> None:
        self.replacements: list[ModifySpec] = []
        # verbatim rule texts, aligned by index with self.replacements
        self.raw_rules: list[str] = []

    def load(self, loader):
        loader.add_option(
            "modify_headers",
            Sequence[str],
            [],
            """
            Header modify pattern of the form "[/flow-filter]/header-name/[@]header-value", where the
            separator can be any character. The @ allows to provide a file path that is used to read
            the header value string. An empty header-value removes existing header-name headers.
            """,
        )

    def configure(self, updated):
        if "modify_headers" in updated:
            self.replacements = []
            self.raw_rules = []
            for option in ctx.options.modify_headers:
                try:
                    spec = parse_modify_spec(option, False)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse modify_headers option {option}: {e}"
                    ) from e
                self.replacements.append(spec)
                self.raw_rules.append(option)

    def requestheaders(self, flow):
        if flow.response or flow.error or not flow.live:
            return
        self.apply(flow, flow.request.headers, "requestheaders")

    def responseheaders(self, flow):
        if flow.error or not flow.live:
            return
        self.apply(flow, flow.response.headers, "responseheaders")

    def apply(
        self,
        flow: http.HTTPFlow,
        hdrs: Headers,
        phase: str,
        trace: rewritetrace.Recorder | None = None,
    ) -> None:
        if trace is None:
            trace = rewritetrace.begin("modify_headers", phase, flow, self.raw_rules)

        # first check all the filters against the original, unmodified flow
        matches = [spec.matches(flow) for spec in self.replacements]

        # whether a matched header existed before the two-pass rewrite below,
        # only needed while tracing to tell removals apart from no-ops.
        present = (
            [
                matches[i] and self.replacements[i].subject in hdrs
                for i in range(len(matches))
            ]
            if trace is not None
            else []
        )

        # unset all specified headers
        for i, spec in enumerate(self.replacements):
            if matches[i]:
                hdrs.pop(spec.subject, None)

        # set all specified headers if the replacement string is not empty

        for i, spec in enumerate(self.replacements):
            if not matches[i]:
                continue
            try:
                replacement = spec.read_replacement()
            except OSError as e:
                logging.warning(f"Could not read replacement file: {e}")
                if trace is not None:
                    if present[i]:
                        trace.hit(
                            i,
                            detail=(
                                f"removed header {spec.subject!r}, "
                                "but the replacement file could not be read"
                            ),
                            error=e,
                        )
                    else:
                        trace.matched(i, error=e)
                continue
            if replacement:
                hdrs.add(spec.subject, replacement)
                if trace is not None:
                    trace.hit(i, detail=f"set header {spec.subject!r}")
            elif trace is not None:
                if present[i]:
                    trace.hit(i, detail=f"removed header {spec.subject!r}")
                else:
                    trace.matched(i, detail=f"header {spec.subject!r} was not present")

        if trace is not None:
            trace.finish()
