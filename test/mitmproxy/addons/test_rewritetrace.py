import pytest

from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy.addons import maplocal
from mitmproxy.addons import mapremote
from mitmproxy.addons import modifybody
from mitmproxy.addons import modifyheaders
from mitmproxy.addons import rewritetrace
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def records(flow):
    return flow.metadata[rewritetrace.METADATA_KEY]


@pytest.fixture
def chain():
    mh = modifyheaders.ModifyHeaders()
    mb = modifybody.ModifyBody()
    mr = mapremote.MapRemote()
    ml = maplocal.MapLocal()
    tracer = rewritetrace.RewriteTrace()
    with taddons.context(mh, mb, mr, ml, tracer) as tctx:
        yield tctx, tracer, mh, mb, mr, ml


class TestDisabled:
    def test_no_records_by_default(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(mr, map_remote=[":example.org:mitmproxy.org"])

        f = tflow.tflow()
        f.request.url = b"https://example.org/images/test.jpg"
        mr.request(f)

        assert rewritetrace.METADATA_KEY not in f.metadata
        assert len(tracer.history) == 0
        assert f.request.url == "https://mitmproxy.org/images/test.jpg"

    def test_addon_absent_keeps_addons_working(self):
        mr = mapremote.MapRemote()
        with taddons.context(mr) as tctx:
            tctx.configure(mr, map_remote=[":example.org:mitmproxy.org"])
            f = tflow.tflow()
            f.request.url = b"https://example.org/images/test.jpg"
            mr.request(f)
            assert f.request.url == "https://mitmproxy.org/images/test.jpg"


class TestMapRemote:
    def test_hit_miss_and_empty(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        rule = ":~d example.org:example.org/images:mitmproxy.org/img"
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_remote=[rule],
        )

        f = tflow.tflow()
        f.request.url = b"https://example.org/images/test.jpg"
        mr.request(f)

        record = records(f)[0]
        assert record["chain"] == "map_remote"
        assert record["phase"] == "request"
        assert record["flow"] == f.id
        assert record["effective"] == [0]
        assert record["empty"] is False
        decision = record["rules"][0]
        assert decision["index"] == 0
        assert decision["result"] == rewritetrace.HIT
        assert decision["rule"] == rule
        assert "mitmproxy.org/img/test.jpg" in decision["detail"]
        assert len(tracer.history) == 1

        # a flow on which no rule fires gets an explicit empty-hit record
        g = tflow.tflow()
        g.request.url = b"https://example.net/whatever"
        mr.request(g)
        empty = records(g)[0]
        assert empty["rules"][0]["result"] == rewritetrace.MISS
        assert empty["effective"] == []
        assert empty["empty"] is True

    def test_matched_but_not_rewritten(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer, rewrite_trace=True, map_remote=[":example.org:example.org"]
        )

        f = tflow.tflow()
        f.request.url = b"https://example.org/path"
        mr.request(f)

        decision = records(f)[0]["rules"][0]
        assert decision["result"] == rewritetrace.MATCHED
        assert records(f)[0]["empty"] is True
        assert f.request.url == "https://example.org/path"


class TestModifyBody:
    def test_hit_and_no_body_match(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer,
            rewrite_trace=True,
            modify_body=["/~q/foo/bar", "/~q/zzz/yyy"],
        )

        f = tflow.tflow()
        f.request.content = b"foo"
        mb.request(f)

        record = records(f)[0]
        assert record["rules"][0]["result"] == rewritetrace.HIT
        # the flow filter matched, but the regex did not touch the body
        assert record["rules"][1]["result"] == rewritetrace.MATCHED
        assert record["effective"] == [0]
        assert f.request.content == b"bar"

    def test_unreadable_replacement(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("replacement")
        tmpfile.write("bar")
        tctx.configure(
            tracer, rewrite_trace=True, modify_body=["/~q/foo/@" + str(tmpfile)]
        )
        tmpfile.remove()

        f = tflow.tflow()
        f.request.content = b"foo"
        mb.request(f)
        decision = records(f)[0]["rules"][0]
        assert decision["result"] == rewritetrace.MATCHED
        assert decision["error"]
        assert f.request.content == b"foo"


class TestModifyHeaders:
    @pytest.mark.parametrize(
        "present,value,expected",
        [
            (True, "two", rewritetrace.HIT),
            (False, "two", rewritetrace.HIT),
            (True, "", rewritetrace.HIT),
            (False, "", rewritetrace.MATCHED),
        ],
    )
    def test_decisions(self, chain, present, value, expected):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True, modify_headers=[f"/~q/one/{value}"])

        f = tflow.tflow()
        if present:
            f.request.headers["one"] = "xxx"
        mh.requestheaders(f)

        decision = records(f)[0]["rules"][0]
        assert decision["result"] == expected

    def test_unreadable_replacement_with_existing_header(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("replacement")
        tmpfile.write("two")
        tctx.configure(
            tracer,
            rewrite_trace=True,
            modify_headers=["/~q/one/@" + str(tmpfile)],
        )
        tmpfile.remove()

        f = tflow.tflow()
        f.request.headers["one"] = "xxx"
        mh.requestheaders(f)
        decision = records(f)[0]["rules"][0]
        # the header was popped before the read failed, so something changed
        assert decision["result"] == rewritetrace.HIT
        assert decision["error"]
        assert "one" not in f.request.headers

    def test_response_phase(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True, modify_headers=["/~s/one/two"])
        f = tflow.tflow(resp=True)
        f.response.headers["one"] = "xxx"
        mh.responseheaders(f)
        record = records(f)[0]
        assert record["phase"] == "responseheaders"
        assert record["rules"][0]["result"] == rewritetrace.HIT


class TestMapLocal:
    def test_candidates_and_selected(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("foo.jpg")
        tmpfile.write("foo")
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_local=["|//example.org/images|" + str(tmpdir)],
        )

        f = tflow.tflow()
        f.request.url = b"https://example.org/images/foo.jpg"
        ml.request(f)

        record = records(f)[0]
        assert record["rules"][0]["result"] == rewritetrace.HIT
        assert record["effective"] == [0]
        assert record["selected"] == str(tmpfile)
        candidates = record["rules"][0]["candidates"]
        assert str(tmpfile) in candidates
        assert f.response.content == b"foo"

    def test_missing_candidates_produce_404_and_empty_hit(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer, rewrite_trace=True, map_local=["|example.org/css|" + str(tmpdir)]
        )

        f = tflow.tflow()
        f.request.url = b"https://example.org/css/nonexistent"
        ml.request(f)

        record = records(f)[0]
        assert record["rules"][0]["result"] == rewritetrace.MATCHED
        assert record["empty"] is True
        assert record["selected"] is None
        assert record["candidates"]
        assert "404" in record["note"]
        assert f.response.status_code == 404

    def test_unreadable_file(self, chain, tmpdir, monkeypatch):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("foo.jpg")
        tmpfile.write("foo")
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_local=["|//example.org/images|" + str(tmpdir)],
        )
        tmpfile.remove()
        monkeypatch.setattr("pathlib.Path.is_file", lambda self: True)

        f = tflow.tflow()
        f.request.url = b"https://example.org/images/foo.jpg"
        ml.request(f)

        decision = records(f)[0]["rules"][0]
        assert decision["result"] == rewritetrace.MATCHED
        assert decision["error"]

    def test_first_serving_rule_stops_chain(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        first_dir = tmpdir.mkdir("a")
        first_dir.join("foo.jpg").write("first")
        second_dir = tmpdir.mkdir("b")
        second_dir.join("foo.jpg").write("second")
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_local=[
                "|//example.org/images|" + str(first_dir),
                "|//example.org|" + str(second_dir),
            ],
        )

        f = tflow.tflow()
        f.request.url = b"https://example.org/images/foo.jpg"
        ml.request(f)

        record = records(f)[0]
        assert record["effective"] == [0]
        assert record["selected"] == str(first_dir.join("foo.jpg"))
        assert record["rules"][1]["detail"].startswith("not evaluated")
        assert f.response.content == b"first"

    def test_no_rules_configured(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True)
        f = tflow.tflow()
        ml.request(f)
        record = records(f)[0]
        assert record["empty"] is True
        assert "no rules configured" in record["note"]


class TestHistory:
    def test_rule_text_is_frozen_and_indices_follow_new_rules(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer, rewrite_trace=True, map_remote=[":example.org/a:example.org/b"]
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/a"
        mr.request(f)
        old_rule = ":example.org/a:example.org/b"

        tctx.configure(tracer, map_remote=[":example.org/c:example.org/d"])
        g = tflow.tflow()
        g.request.url = b"https://example.org/c"
        mr.request(g)

        assert tracer.history[0]["rules"][0]["rule"] == old_rule
        assert tracer.history[1]["rules"][0]["rule"] == ":example.org/c:example.org/d"
        # history identity is per record, nothing is rewritten in place
        assert tracer.history[0]["id"] == 1
        assert tracer.history[1]["id"] == 2

    def test_capacity_discards_oldest(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True, rewrite_trace_size=2)
        for _ in range(3):
            f = tflow.tflow()
            mr.request(f)
        assert len(tracer.history) == 2
        assert [r["id"] for r in tracer.history] == [2, 3]

    def test_capacity_resize_keeps_newest(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True)
        for _ in range(3):
            f = tflow.tflow()
            mr.request(f)
        tctx.configure(tracer, rewrite_trace_size=2)
        assert [r["id"] for r in tracer.history] == [2, 3]

    def test_negative_capacity_rejected(self, chain):
        tctx, tracer, *_ = chain
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(tracer, rewrite_trace_size=-1)

    def test_history_command_and_clear(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        assert tracer.history_command() == "No rewrite hit records."

        tctx.configure(
            tracer, rewrite_trace=True, map_remote=[":example.org:mitmproxy.org"]
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/"
        mr.request(f)

        out = tctx.master.commands.call("rewrite.trace.history")
        assert "map_remote @ request" in out
        assert ":example.org:mitmproxy.org" in out
        assert "hit, rewritten" in out

        tctx.master.commands.call("rewrite.trace.clear")
        assert len(tracer.history) == 0

    def test_history_invalid_limit(self, chain):
        tctx, tracer, *_ = chain
        with pytest.raises(exceptions.CommandError):
            tracer.history_command(0)

    def test_history_formats_errors_and_separates_records(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("replacement")
        tmpfile.write("bar")
        tctx.configure(
            tracer, rewrite_trace=True, modify_body=["/~q/foo/@" + str(tmpfile)]
        )
        tmpfile.remove()
        for _ in range(2):
            f = tflow.tflow()
            f.request.content = b"foo"
            mb.request(f)

        out = tracer.history_command()
        assert "error:" in out
        # two records are separated by a blank line
        assert "\n\n" in out

    def test_dry_run_without_rewrite_addons(self):
        tracer = rewritetrace.RewriteTrace()
        with taddons.context(tracer):
            with pytest.raises(exceptions.CommandError, match="not loaded"):
                tracer.dry_run(tflow.tflow())


class TestDryRun:
    def test_dry_run_does_not_change_flow_or_history(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_remote=[":example.org/images:mitmproxy.org/img"],
            modify_body=["/~q/foo/bar"],
            modify_headers=["/~q/x-header/yes"],
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/images/a.jpg"
        f.request.content = b"foo"
        f.request.headers["x-header"] = "old"

        report = tctx.master.commands.call("rewrite.dry_run", f)

        # original flow is untouched
        assert f.request.url == "https://example.org/images/a.jpg"
        assert f.request.content == b"foo"
        assert f.request.headers["x-header"] == "old"
        assert f.response is None
        # dry runs are not recorded anywhere
        assert len(tracer.history) == 0
        assert rewritetrace.METADATA_KEY not in f.metadata

        # report content
        assert report.startswith("Dry run")
        assert "modify_headers @ requestheaders" in report
        assert "map_remote @ request" in report
        assert "map_local @ request" in report
        assert "modify_body @ request" in report
        assert "Final effective rules:" in report
        assert "map_remote #0" in report
        assert "modify_body #0" in report
        assert "Outcome if applied:" in report
        assert "mitmproxy.org/img/a.jpg" in report
        assert "request body modified" in report

    def test_dry_run_without_any_hit(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, rewrite_trace=True)
        f = tflow.tflow()
        report = tctx.master.commands.call("rewrite.dry_run", f)
        assert "(none, empty hit)" in report
        assert "no changes" in report

    def test_dry_run_map_local_reports_selected_file(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tmpfile = tmpdir.join("foo.jpg")
        tmpfile.write("foo")
        tctx.configure(
            tracer,
            rewrite_trace=True,
            map_local=["|//example.org/images|" + str(tmpdir)],
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/images/foo.jpg"
        report = tctx.master.commands.call("rewrite.dry_run", f)
        assert f.response is None
        assert "response served from local file" in report
        assert str(tmpfile) in report

    def test_dry_run_works_without_tracking_enabled(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(tracer, map_remote=[":example.org:mitmproxy.org"])
        f = tflow.tflow()
        f.request.url = b"https://example.org/x"
        report = tctx.master.commands.call("rewrite.dry_run", f)
        assert "hit, rewritten" in report
        assert len(tracer.history) == 0
        assert f.request.url == "https://example.org/x"

    def test_dry_run_map_local_reports_generated_404(self, chain, tmpdir):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer, rewrite_trace=True, map_local=["|example.org/css|" + str(tmpdir)]
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/css/nonexistent"
        report = tctx.master.commands.call("rewrite.dry_run", f)
        assert f.response is None
        assert "response generated (404)" in report

    def test_dry_run_requires_http_flow(self, chain):
        tctx, *_ = chain
        with pytest.raises(exceptions.CommandError, match="HTTP flow"):
            tctx.master.commands.call("rewrite.dry_run", tflow.ttcpflow())


class TestMetadata:
    def test_records_survive_flow_copy(self, chain):
        tctx, tracer, mh, mb, mr, ml = chain
        tctx.configure(
            tracer, rewrite_trace=True, map_remote=[":example.org:mitmproxy.org"]
        )
        f = tflow.tflow()
        f.request.url = b"https://example.org/x"
        mr.request(f)

        clone = f.copy()
        assert records(clone)[0]["rules"][0]["rule"] == ":example.org:mitmproxy.org"

        restored = http.HTTPFlow.from_state(f.get_state())
        assert restored.metadata[rewritetrace.METADATA_KEY][0]["chain"] == "map_remote"
