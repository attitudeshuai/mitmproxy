import re
from collections.abc import Sequence
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.addons import rewritetrace
from mitmproxy.utils.spec import parse_spec


class MapRemoteSpec(NamedTuple):
    matches: flowfilter.TFilter
    subject: str
    replacement: str


def parse_map_remote_spec(option: str) -> MapRemoteSpec:
    spec = MapRemoteSpec(*parse_spec(option))

    try:
        re.compile(spec.subject)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {spec.subject!r} ({e})")

    return spec


class MapRemote:
    def __init__(self) -> None:
        self.replacements: list[MapRemoteSpec] = []
        # verbatim rule texts, aligned by index with self.replacements
        self.raw_rules: list[str] = []

    def load(self, loader):
        loader.add_option(
            "map_remote",
            Sequence[str],
            [],
            """
            Map remote resources to another remote URL using a pattern of the form
            "[/flow-filter]/url-regex/replacement", where the separator can
            be any character.
            """,
        )

    def configure(self, updated):
        if "map_remote" in updated:
            self.replacements = []
            self.raw_rules = []
            for option in ctx.options.map_remote:
                try:
                    spec = parse_map_remote_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_remote option {option}: {e}"
                    ) from e

                self.replacements.append(spec)
                self.raw_rules.append(option)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.error or not flow.live:
            return
        trace = rewritetrace.begin("map_remote", "request", flow, self.raw_rules)
        self.apply(flow, trace)

    def apply(
        self, flow: http.HTTPFlow, trace: rewritetrace.Recorder | None = None
    ) -> None:
        for i, spec in enumerate(self.replacements):
            if not spec.matches(flow):
                if trace is not None:
                    trace.miss(i, "flow filter did not match")
                continue
            url = flow.request.pretty_url
            new_url = re.sub(spec.subject, spec.replacement, url)
            # this is a bit messy: setting .url also updates the host header,
            # so we really only do that if the replacement affected the URL.
            if url != new_url:
                flow.request.url = new_url  # type: ignore
                if trace is not None:
                    trace.hit(i, detail=f"URL mapped to {new_url}")
            elif trace is not None:
                trace.matched(
                    i,
                    detail="flow filter matched, but the regex did not change the URL",
                )
        if trace is not None:
            trace.finish()
