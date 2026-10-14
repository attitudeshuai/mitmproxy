"""
Hit tracking and dry-run support for the rewrite addons
(``modify_headers``, ``modify_body``, ``map_local`` and ``map_remote``).

When the ``rewrite_trace`` option is enabled, every flow that passes through
one of the rewrite chains gets a structured hit record which is both attached
to ``flow.metadata["rewrite_trace"]`` (so that it shows up in the flow detail
view) and appended to a bounded, in-memory history that can be queried through
the ``rewrite.trace.*`` commands. Flows on which no rule fires are recorded
with an explicit empty-hit marker instead of being left without a record.

The ``rewrite.dry_run`` command runs the current rule set against a private
copy of a flow without mutating the original, without touching the history and
without any other side effects, and reports every rule decision and the final
effective rules.

Records are plain JSON-compatible data (dicts, lists and strings) so that they
survive flow copies and serialization unchanged. Every record stores the rule
index and the verbatim rule text at decision time, so editing the rule list
later only affects subsequent records and never rewrites history.
"""

import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http

ADDON_NAME = "rewritetrace"
METADATA_KEY = "rewrite_trace"

#: Rule matched and the flow was rewritten as a result.
HIT = "hit"
#: Rule matched, but the flow was not rewritten (no-op or a rewrite error).
MATCHED = "matched"
#: Rule did not match.
MISS = "miss"

_DEFAULT_SIZE = 1000


class Recorder:
    """
    Collects the per-rule decisions of a single run of one rewrite chain.

    Every rule starts out as :attr:`MISS`; the rewrite addons upgrade the
    decision while walking their rule list. ``finish`` produces the immutable
    record, attaches it to the flow metadata and (unless this is a dry run)
    hands it to the tracker for the global history.
    """

    def __init__(
        self,
        tracer: "RewriteTrace",
        chain: str,
        phase: str,
        flow: http.HTTPFlow,
        rules: list[str],
        dry_run: bool = False,
    ) -> None:
        self.tracer = tracer
        self.chain = chain
        self.phase = phase
        self.flow = flow
        self.dry_run = dry_run
        self.decisions: list[dict] = [
            {"index": i, "rule": rule, "result": MISS, "detail": None}
            for i, rule in enumerate(rules)
        ]
        self.effective: list[int] = []

    def hit(
        self,
        index: int,
        detail: str | None = None,
        error: Exception | str | None = None,
    ) -> None:
        """Record a rule that matched and rewrote the flow."""
        decision = self.decisions[index]
        decision["result"] = HIT
        if detail is not None:
            decision["detail"] = detail
        if error is not None:
            decision["error"] = str(error)
        if index not in self.effective:
            self.effective.append(index)

    def matched(
        self,
        index: int,
        detail: str | None = None,
        error: Exception | str | None = None,
    ) -> None:
        """Record a rule that matched but did not rewrite the flow."""
        decision = self.decisions[index]
        decision["result"] = MATCHED
        if detail is not None:
            decision["detail"] = detail
        if error is not None:
            decision["error"] = str(error)

    def miss(self, index: int, detail: str | None = None) -> None:
        """Record why an evaluated rule did not match."""
        if detail is not None:
            self.decisions[index]["detail"] = detail

    def set_candidates(self, index: int, candidates: list[str]) -> None:
        """Record the local file candidates of a map_local rule."""
        self.decisions[index]["candidates"] = list(candidates)

    def skip_remaining(self, index: int, reason: str) -> None:
        """
        Mark rules after *index* as not evaluated, e.g. because an earlier
        map_local rule already produced a response.
        """
        for decision in self.decisions[index + 1 :]:
            decision["detail"] = reason

    def finish(
        self,
        candidates: Sequence[str | Path] | None = None,
        selected: str | Path | None = None,
        note: str | None = None,
    ) -> dict:
        record = {
            "chain": self.chain,
            "phase": self.phase,
            "flow": self.flow.id,
            "timestamp": time.time(),
            "dry_run": self.dry_run,
            "rules": self.decisions,
            "effective": self.effective,
            "empty": not self.effective,
            "candidates": [str(c) for c in candidates]
            if candidates is not None
            else None,
            "selected": str(selected) if selected is not None else None,
            "note": note,
        }
        self.flow.metadata.setdefault(METADATA_KEY, []).append(record)
        if not self.dry_run:
            self.tracer.store(record)
        return record


def get_tracer() -> "RewriteTrace | None":
    return ctx.master.addons.get(ADDON_NAME)


def begin(
    chain: str,
    phase: str,
    flow: http.HTTPFlow,
    rules: list[str],
    dry_run: bool = False,
) -> Recorder | None:
    """
    Start recording one rewrite chain run. Returns ``None`` when tracking is
    switched off, leaving the rewrite addons on their original fast path.
    """
    tracer = get_tracer()
    if tracer is None:
        return None
    return tracer.begin(chain, phase, flow, rules, dry_run=dry_run)


_RESULT_LABELS = {
    HIT: "hit, rewritten",
    MATCHED: "matched, not rewritten",
    MISS: "miss",
}


def _format_decision(decision: dict) -> list[str]:
    lines = [
        f"  #{decision['index']}: {_RESULT_LABELS[decision['result']]}  {decision['rule']}"
    ]
    if decision.get("error"):
        lines.append(f"      error: {decision['error']}")
    if decision.get("detail"):
        lines.append(f"      {decision['detail']}")
    for candidate in decision.get("candidates") or []:
        lines.append(f"      candidate: {candidate}")
    return lines


def format_record(record: dict) -> list[str]:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record["timestamp"]))
    identifier = record.get("id")
    title = f"{record['chain']} @ {record['phase']}"
    if identifier is not None:
        title = f"#{identifier} {title}"
    if record.get("dry_run"):
        title += " (dry run)"
    lines = [f"{title}  flow {record['flow'][:8]}  {timestamp}"]
    for decision in record["rules"]:
        lines.extend(_format_decision(decision))
    if record["effective"]:
        lines.append(
            f"  effective rules: {', '.join('#' + str(i) for i in record['effective'])}"
        )
    else:
        lines.append("  effective rules: none (empty hit)")
    if record.get("selected"):
        lines.append(f"  selected file: {record['selected']}")
    if record.get("note"):
        lines.append(f"  note: {record['note']}")
    return lines


class RewriteTrace:
    def __init__(self) -> None:
        self.history: deque[dict] = deque(maxlen=_DEFAULT_SIZE)
        self._seq: int = 0

    def load(self, loader):
        loader.add_option(
            "rewrite_trace",
            bool,
            False,
            """
            Track rewrite rule hits. When enabled, every flow passing through the
            modify_headers, modify_body, map_local or map_remote chains
            carries a per-rule hit record in its flow metadata (visible in the
            flow detail view), and records are kept in an in-memory history that
            can be queried with rewrite.trace.history. When disabled, rewrite
            behavior and performance are unchanged.
            """,
        )
        loader.add_option(
            "rewrite_trace_size",
            int,
            _DEFAULT_SIZE,
            """
            Maximum number of rewrite hit records kept in memory. When the
            bound is exceeded, the oldest records are discarded.
            """,
        )

    def configure(self, updated):
        if "rewrite_trace_size" in updated:
            size = ctx.options.rewrite_trace_size
            if size < 0:
                raise exceptions.OptionsError(
                    "rewrite_trace_size must not be negative."
                )
            old = self.history
            self.history = deque(old, maxlen=size)

    @property
    def enabled(self) -> bool:
        return bool(ctx.options.rewrite_trace)

    def begin(
        self,
        chain: str,
        phase: str,
        flow: http.HTTPFlow,
        rules: list[str],
        dry_run: bool = False,
    ) -> Recorder | None:
        if not dry_run and not self.enabled:
            return None
        return Recorder(self, chain, phase, flow, rules, dry_run=dry_run)

    def store(self, record: dict) -> None:
        self._seq += 1
        record["id"] = self._seq
        self.history.append(record)

    @command.command("rewrite.trace.clear")
    def clear(self) -> None:
        """
        Clear the in-memory rewrite hit history.
        """
        self.history.clear()

    @command.command("rewrite.trace.history")
    def history_command(self, limit: int = 20) -> str:
        """
        Show up to the given number of most recent rewrite hit records.
        """
        if limit <= 0:
            raise exceptions.CommandError("limit must be a positive integer")
        records = list(self.history)[-limit:]
        if not records:
            return "No rewrite hit records."
        records.reverse()
        lines: list[str] = []
        for record in records:
            if lines:
                lines.append("")
            lines.extend(format_record(record))
        return "\n".join(lines)

    @command.command("rewrite.dry_run")
    def dry_run_command(self, f: flow.Flow) -> str:
        """
        Evaluate the current rewrite rules against a flow without rewriting it
        and report every rule decision plus the final effective rules.
        """
        if not isinstance(f, http.HTTPFlow):
            raise exceptions.CommandError("dry run requires an HTTP flow")
        return self.dry_run(f)

    def dry_run(self, original: http.HTTPFlow) -> str:
        addons = ctx.master.addons
        modify_headers = addons.get("modifyheaders")
        map_remote = addons.get("mapremote")
        map_local = addons.get("maplocal")
        modify_body = addons.get("modifybody")
        if not all((modify_headers, map_remote, map_local, modify_body)):
            raise exceptions.CommandError(
                "the rewrite addons are not loaded, cannot run a dry run"
            )

        trial = original.copy()
        # Start from a clean slate: the copy may carry real records from the
        # original flow, which must not show up in the dry-run report.
        trial.metadata.pop(METADATA_KEY, None)

        # Mirror the live event sequence for the request phase:
        # requestheaders (modify_headers) precedes the request hooks, which run
        # in addon order (map_remote, map_local, modify_body).
        modify_headers.apply(
            trial,
            trial.request.headers,
            "requestheaders",
            self.begin(
                "modify_headers",
                "requestheaders",
                trial,
                modify_headers.raw_rules,
                dry_run=True,
            ),
        )
        map_remote.apply(
            trial,
            self.begin(
                "map_remote", "request", trial, map_remote.raw_rules, dry_run=True
            ),
        )
        map_local.apply(
            trial,
            self.begin(
                "map_local", "request", trial, map_local.raw_rules, dry_run=True
            ),
        )
        # Same guard as ModifyBody.request: once a response exists, the body is
        # left untouched.
        if not trial.response:
            modify_body.apply(
                trial,
                "request",
                self.begin(
                    "modify_body", "request", trial, modify_body.raw_rules, dry_run=True
                ),
            )

        records = trial.metadata.get(METADATA_KEY, [])
        return self._format_dry_run_report(original, trial, records)

    def _format_dry_run_report(
        self, original: http.HTTPFlow, trial: http.HTTPFlow, records: list[dict]
    ) -> str:
        lines = [
            (
                f"Dry run for {original.request.method} {original.request.pretty_url} "
                "(nothing was changed)"
            )
        ]
        for record in records:
            lines.append("")
            lines.extend(format_record(record))

        lines.append("")
        lines.append("Final effective rules:")
        effective = [(record, i) for record in records for i in record["effective"]]
        if effective:
            for record, i in effective:
                rule = record["rules"][i]["rule"]
                lines.append(f"  {record['chain']} #{i}: {rule}")
        else:
            lines.append("  (none, empty hit)")

        lines.append("")
        lines.append("Outcome if applied:")
        changes = self._diff(original, trial)
        lines.extend(f"  {change}" for change in changes)

        return "\n".join(lines)

    @staticmethod
    def _diff(original: http.HTTPFlow, trial: http.HTTPFlow) -> list[str]:
        changes: list[str] = []
        if original.request.pretty_url != trial.request.pretty_url:
            changes.append(
                f"request URL: {original.request.pretty_url} -> {trial.request.pretty_url}"
            )
        before_headers = list(original.request.headers.items())
        after_headers = list(trial.request.headers.items())
        if before_headers != after_headers:
            changed = sorted(
                {k for k, _ in before_headers} ^ {k for k, _ in after_headers}
                | {k for k, v in before_headers if trial.request.headers.get(k) != v}
            )
            changes.append("request headers modified: " + ", ".join(changed))
        if original.request.content != trial.request.content:
            changes.append("request body modified")
        if trial.response:
            selected = None
            for record in reversed(trial.metadata.get(METADATA_KEY, [])):
                if record["chain"] == "map_local":
                    selected = record.get("selected")
                    break
            if selected:
                changes.append(
                    f"response served from local file: {selected} "
                    f"({trial.response.status_code})"
                )
            else:
                changes.append(
                    f"response generated ({trial.response.status_code}), "
                    "no local candidate existed"
                )
        if not changes:
            changes.append("no changes")
        return changes
