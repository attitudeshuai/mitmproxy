import asyncio

import pytest

from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy.addons import intercept
from mitmproxy.log import ALERT
from mitmproxy.test import taddons
from mitmproxy.test import tflow


async def test_simple():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        assert not r.filt
        tctx.configure(r, intercept="~q")
        assert r.filt
        assert tctx.options.intercept_active
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(r, intercept="~~")
        tctx.configure(r, intercept=None)
        assert not r.filt
        assert not tctx.options.intercept_active

        tctx.configure(r, intercept="~s")

        f = tflow.tflow(resp=True)
        await tctx.cycle(r, f)
        assert f.intercepted

        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert not f.intercepted

        f = tflow.tflow(resp=True)
        r.response(f)
        assert f.intercepted

        tctx.configure(r, intercept_active=False)
        f = tflow.tflow(resp=True)
        await tctx.cycle(r, f)
        assert not f.intercepted

        tctx.configure(r, intercept_active=True)
        f = tflow.tflow(resp=True)
        await tctx.cycle(r, f)
        assert f.intercepted


async def test_dns():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~s ~dns")

        f = tflow.tdnsflow(resp=True)
        await tctx.cycle(r, f)
        assert f.intercepted

        f = tflow.tdnsflow(resp=False)
        await tctx.cycle(r, f)
        assert not f.intercepted

        tctx.configure(r, intercept_active=False)
        f = tflow.tdnsflow(resp=True)
        await tctx.cycle(r, f)
        assert not f.intercepted


async def test_tcp():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~tcp")
        f = tflow.ttcpflow()
        await tctx.cycle(r, f)
        assert f.intercepted

        tctx.configure(r, intercept_active=False)
        f = tflow.ttcpflow()
        await tctx.cycle(r, f)
        assert not f.intercepted


async def test_udp():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~udp")
        f = tflow.tudpflow()
        await tctx.cycle(r, f)
        assert f.intercepted

        tctx.configure(r, intercept_active=False)
        f = tflow.tudpflow()
        await tctx.cycle(r, f)
        assert not f.intercepted


async def test_websocket_message():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept='~b "hello binary"')
        f = tflow.twebsocketflow()
        await tctx.cycle(r, f)
        assert f.intercepted

        tctx.configure(r, intercept_active=False)
        f = tflow.twebsocketflow()
        await tctx.cycle(r, f)
        assert not f.intercepted


def test_invalid_timeout_configuration():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        for invalid in ("0", "0s", "-1", "-5s", "nonsense", "10x"):
            with pytest.raises(exceptions.OptionsError):
                tctx.configure(r, intercept_timeout=invalid)
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(r, intercept_timeout_action="pause")
        # None and positive values are accepted.
        tctx.configure(r, intercept_timeout=None)
        tctx.configure(r, intercept_timeout="30s")
        tctx.configure(r, intercept_timeout="2m")
        tctx.configure(r, intercept_timeout="0.5s")
        assert r.timeout == 0.5
        assert r.timeout_action == flow.INTERCEPT_ACTION_FORWARD


async def test_no_timeout_means_no_timer():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q")
        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert f.intercepted
        assert r._timers == {}


async def test_timeout_forwards(caplog):
    caplog.set_level(ALERT, logger="mitmproxy.addons.intercept")
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q", intercept_timeout="0.05s")
        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert f.intercepted
        assert f.id in r._timers

        await asyncio.sleep(0.15)
        assert not f.intercepted
        history = f.metadata[flow.INTERCEPT_METADATA_KEY]
        assert history[-1]["action"] == flow.INTERCEPT_ACTION_FORWARD
        assert history[-1]["disposition"] == flow.INTERCEPT_DISPOSITION_TIMEOUT
        assert "[intercept timeout]" in f.comment
        assert r._timers == {}
        assert any(
            "Intercept timeout" in record.message and "forwarded" in record.message
            for record in caplog.records
        )


async def test_timeout_kills(caplog):
    caplog.set_level(ALERT, logger="mitmproxy.addons.intercept")
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(
            r,
            intercept="~q",
            intercept_timeout="0.05s",
            intercept_timeout_action="kill",
        )
        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert f.intercepted

        await asyncio.sleep(0.15)
        assert not f.intercepted
        assert not f.live
        assert f.error and f.error.msg == flow.Error.KILLED_MESSAGE
        history = f.metadata[flow.INTERCEPT_METADATA_KEY]
        assert history[-1]["action"] == flow.INTERCEPT_ACTION_KILL
        assert history[-1]["disposition"] == flow.INTERCEPT_DISPOSITION_TIMEOUT
        assert any(
            "Intercept timeout" in record.message and "killed" in record.message
            for record in caplog.records
        )


async def test_manual_resume_defuses_timeout():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q", intercept_timeout="0.05s")
        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert f.intercepted

        f.resume()
        # Wait past the scheduled timeout, it must not retroact on the flow.
        await asyncio.sleep(0.15)
        history = f.metadata[flow.INTERCEPT_METADATA_KEY]
        assert len(history) == 1
        assert history[-1]["disposition"] == flow.INTERCEPT_DISPOSITION_MANUAL
        assert f.comment == ""
        assert r._timers == {}


async def test_config_changes_only_affect_new_flows():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q", intercept_timeout="10h")
        old = tflow.tflow(resp=False)
        await tctx.cycle(r, old)
        assert old.intercepted

        tctx.configure(r, intercept_timeout="0.05s")
        new = tflow.tflow(resp=False)
        await tctx.cycle(r, new)
        assert new.intercepted

        await asyncio.sleep(0.15)
        # The new flow times out with the new configuration...
        assert not new.intercepted
        # ...while the previously intercepted flow keeps waiting.
        assert old.intercepted
        r.done()


async def test_replayed_flows_get_no_timer():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q", intercept_timeout="0.05s")
        f = tflow.tflow(resp=False)
        f.is_replay = "request"
        await tctx.cycle(r, f)
        assert not f.intercepted
        assert r._timers == {}


async def test_done_cancels_timers_without_resolving():
    r = intercept.Intercept()
    with taddons.context(r) as tctx:
        tctx.configure(r, intercept="~q", intercept_timeout="10h")
        f = tflow.tflow(resp=False)
        await tctx.cycle(r, f)
        assert f.intercepted
        handle = r._timers[f.id]
        r.done()
        assert handle.cancelled()
        assert r._timers == {}
        # Shutdown does not resolve waiting flows.
        assert f.intercepted
