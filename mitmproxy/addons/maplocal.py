import logging
import mimetypes
import re
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from werkzeug.security import safe_join

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import version
from mitmproxy.addons import rewritetrace
from mitmproxy.utils.spec import parse_spec


class MapLocalSpec(NamedTuple):
    matches: flowfilter.TFilter
    regex: str
    local_path: Path


def parse_map_local_spec(option: str) -> MapLocalSpec:
    filter, regex, replacement = parse_spec(option)

    try:
        re.compile(regex)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {regex!r} ({e})")

    try:
        path = Path(replacement).expanduser().resolve(strict=True)
    except FileNotFoundError as e:
        raise ValueError(f"Invalid file path: {replacement} ({e})")

    return MapLocalSpec(filter, regex, path)


def _safe_path_join(root: Path, untrusted: str) -> Path:
    """Join a Path element with an untrusted str.

    This is a convenience wrapper around werkzeug's safe_join,
    raising a ValueError if the path is malformed."""
    untrusted_parts = Path(untrusted).parts
    joined = safe_join(root.as_posix(), *untrusted_parts)
    if joined is None:
        raise ValueError("Untrusted paths.")
    return Path(joined)


def file_candidates(url: str, spec: MapLocalSpec) -> list[Path]:
    """
    Get all potential file candidates given a URL and a mapping spec ordered by preference.
    This function already assumes that the spec regex matches the URL.
    """
    m = re.search(spec.regex, url)
    assert m
    if m.groups():
        suffix = m.group(1)
    else:
        suffix = re.split(spec.regex, url, maxsplit=1)[1]
        suffix = suffix.split("?")[0]  # remove query string
        suffix = suffix.strip("/")

    if suffix:
        decoded_suffix = urllib.parse.unquote(suffix)
        suffix_candidates = [decoded_suffix, f"{decoded_suffix}/index.html"]

        escaped_suffix = re.sub(r"[^0-9a-zA-Z\-_.=(),/]", "_", decoded_suffix)
        if decoded_suffix != escaped_suffix:
            suffix_candidates.extend([escaped_suffix, f"{escaped_suffix}/index.html"])
        try:
            return [_safe_path_join(spec.local_path, x) for x in suffix_candidates]
        except ValueError:
            return []
    else:
        return [spec.local_path / "index.html"]


class MapLocal:
    def __init__(self) -> None:
        self.replacements: list[MapLocalSpec] = []
        # verbatim rule texts, aligned by index with self.replacements
        self.raw_rules: list[str] = []

    def load(self, loader):
        loader.add_option(
            "map_local",
            Sequence[str],
            [],
            """
            Map remote resources to a local file using a pattern of the form
            "[/flow-filter]/url-regex/file-or-directory-path", where the
            separator can be any character.
            """,
        )

    def configure(self, updated):
        if "map_local" in updated:
            self.replacements = []
            self.raw_rules = []
            for option in ctx.options.map_local:
                try:
                    spec = parse_map_local_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_local option {option}: {e}"
                    ) from e

                self.replacements.append(spec)
                self.raw_rules.append(option)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.error or not flow.live:
            return
        trace = rewritetrace.begin("map_local", "request", flow, self.raw_rules)
        self.apply(flow, trace)

    def apply(
        self, flow: http.HTTPFlow, trace: rewritetrace.Recorder | None = None
    ) -> None:
        url = flow.request.pretty_url

        all_candidates: list[Path] = []
        for i, spec in enumerate(self.replacements):
            if not spec.matches(flow):
                if trace is not None:
                    trace.miss(i, "flow filter did not match")
                continue
            if not re.search(spec.regex, url):
                if trace is not None:
                    trace.miss(i, "flow filter matched, but the URL regex did not")
                continue

            if spec.local_path.is_file():
                candidates = [spec.local_path]
            else:
                candidates = file_candidates(url, spec)
            if trace is not None:
                trace.set_candidates(i, [str(c) for c in candidates])
            all_candidates.extend(candidates)

            local_file = None
            for candidate in candidates:
                if candidate.is_file():
                    local_file = candidate
                    break

            if local_file:
                headers = {"Server": version.MITMPROXY}
                mimetype = mimetypes.guess_type(str(local_file))[0]
                if mimetype:
                    headers["Content-Type"] = mimetype

                try:
                    contents = local_file.read_bytes()
                except OSError as e:
                    logging.warning(f"Could not read file: {e}")
                    if trace is not None:
                        trace.matched(i, error=e)
                    continue

                flow.response = http.Response.make(200, contents, headers)
                if trace is not None:
                    trace.hit(i, detail=f"served local file {local_file}")
                    trace.skip_remaining(
                        i, f"not evaluated: rule #{i} already produced a response"
                    )
                    trace.finish(
                        candidates=all_candidates,
                        selected=local_file,
                        note="response served from a local file",
                    )
                # only set flow.response once, for the first matching rule
                return
            if trace is not None:
                trace.matched(
                    i, detail="rule matched, but none of the candidate files exists"
                )

        note: str | None
        if all_candidates:
            flow.response = http.Response.make(404)
            note = "no candidate file existed, generated a 404 response"
            logging.info(
                f"None of the local file candidates exist: {', '.join(str(x) for x in all_candidates)}"
            )
        elif self.replacements:
            note = "empty hit: no rule matched"
        else:
            note = "empty hit: no rules configured"
        if trace is not None:
            trace.finish(candidates=all_candidates, note=note)
