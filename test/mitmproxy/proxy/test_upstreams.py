from __future__ import annotations

import itertools

import pytest

from mitmproxy.proxy import upstreams
from mitmproxy.proxy.upstreams import FailureKind
from mitmproxy.proxy.upstreams import UpstreamHealth
from mitmproxy.proxy.upstreams import UpstreamRegistry
from mitmproxy.proxy.upstreams import UpstreamSettings

P1 = ("http", ("p1", 8080))
P2 = ("http", ("p2", 8081))
P3 = ("https", ("p3", 8443))
SERVERS = [P1, P2, P3]


def registry(**kwargs) -> UpstreamRegistry:
    clock = itertools.count(1.0)
    return UpstreamRegistry(UpstreamSettings(**kwargs), clock=lambda: next(clock))


class TestUpstreamRegistry:
    def test_initial_state(self):
        reg = registry()
        assert reg.select(SERVERS) is P1
        assert reg.status(P1).state is UpstreamHealth.AVAILABLE
        assert reg.drain_events() == []

    def test_failures_degraded_then_unavailable(self):
        reg = registry(failure_threshold=3)
        reg.record(P1, False, error="boom", kind=FailureKind.CONNECT)
        assert reg.status(P1).state is UpstreamHealth.DEGRADED
        assert reg.status(P1).consecutive_failures == 1
        assert reg.status(P1).last_error == "boom"
        reg.record(P1, False, error="boom2")
        assert reg.status(P1).state is UpstreamHealth.DEGRADED
        reg.record(P1, False, error="boom3")
        assert reg.status(P1).state is UpstreamHealth.UNAVAILABLE
        assert reg.status(P1).consecutive_failures == 3
        assert reg.status(P1).total_failures == 3
        messages = [m for _, m in reg.drain_events()]
        assert any("degraded after 1 consecutive" in m for m in messages)
        assert any("unavailable after 3 consecutive" in m for m in messages)

    def test_threshold_one(self):
        reg = registry(failure_threshold=1)
        reg.record(P1, False, error="x")
        assert reg.status(P1).state is UpstreamHealth.UNAVAILABLE
        assert reg.select(SERVERS) is P2

    def test_success_resets(self):
        reg = registry(failure_threshold=2)
        reg.record(P1, False, error="x")
        assert reg.status(P1).state is UpstreamHealth.DEGRADED
        reg.record(P1, True)
        st = reg.status(P1)
        assert st.state is UpstreamHealth.AVAILABLE
        assert st.consecutive_failures == 0
        assert st.last_error is None
        assert st.last_success is not None
        # total failures are kept, consecutive failures reset.
        assert st.total_failures == 1

    def test_recovery_event(self):
        reg = registry(failure_threshold=1)
        reg.record(P1, False, error="x")
        reg.drain_events()
        reg.record(P1, True)
        messages = [m for _, m in reg.drain_events()]
        assert any("recovered" in m for m in messages)

    def test_sequential_failover_and_failback(self):
        reg = registry(failure_threshold=1)
        assert reg.select(SERVERS) is P1
        reg.record(P1, False, error="dead")
        # First connection after the failure still has P1 in its tried list,
        # so the retry moves to P2.
        assert reg.select(SERVERS, tried=[P1]) is P2
        assert reg.select(SERVERS) is P2
        messages = [m for _, m in reg.drain_events()]
        assert any("failover" in m and "p2" in m for m in messages)

        # P1 is probed successfully and traffic moves back automatically.
        reg.record(P1, True)
        reg.drain_events()
        assert reg.select(SERVERS) is P1
        messages = [m for _, m in reg.drain_events()]
        assert any(
            "now use http://p1:8080 instead of http://p2:8081" in m for m in messages
        )

    def test_sequential_prefers_degraded_primary(self):
        reg = registry(failure_threshold=3)
        reg.record(P1, False, error="flaky")
        assert reg.select(SERVERS) is P1
        assert reg.select(SERVERS, tried=[P1]) is P2

    def test_avoid_failures_prefers_healthy_backup(self):
        reg = registry(strategy="avoid-failures", failure_threshold=3)
        reg.record(P1, False, error="flaky")  # P1 degraded
        reg.drain_events()
        assert reg.select(SERVERS) is P2
        # When all are degraded, the one with fewer failures and then order wins.
        reg2 = registry(strategy="avoid-failures", failure_threshold=5)
        reg2.record(P1, False, error="x")
        reg2.record(P1, False, error="x")
        reg2.record(P2, False, error="x")
        reg2.record(P3, False, error="x")
        reg2.record(P3, False, error="x")
        reg2.drain_events()
        assert reg2.select(SERVERS) is P2

    def test_manual_sticky_until_active_fails(self):
        reg = registry(failure_threshold=1, recovery="manual")
        assert reg.select(SERVERS) is P1
        reg.record(P1, False, error="dead")
        reg.drain_events()
        assert reg.select(SERVERS) is P2
        # P1 recovers (probe), but manual mode sticks with P2.
        reg.record(P1, True)
        reg.drain_events()
        assert reg.select(SERVERS) is P2

        # Manual recover re-arms the primary.
        reg.recover(P1)
        reg.drain_events()
        assert reg.select(SERVERS) is P1

    def test_manual_recover_all(self):
        reg = registry(failure_threshold=1, recovery="manual")
        reg.record(P1, False, error="dead")
        reg.record(P2, False, error="dead")
        reg.record(P3, False, error="dead")
        assert reg.select(SERVERS, tried=[P1, P2, P3]) is None
        reg.drain_events()
        reg.recover()
        reg.drain_events()
        assert reg.status(P1).state is UpstreamHealth.AVAILABLE
        assert reg.status(P2).state is UpstreamHealth.AVAILABLE
        assert reg.select(SERVERS) is P1

    def test_all_unavailable_event_fires_once(self):
        reg = registry(failure_threshold=1)
        reg.record(P1, False, error="x")
        reg.record(P2, False, error="x")
        reg.record(P3, False, error="x")
        reg.drain_events()
        assert reg.select(SERVERS) is None
        assert reg.select(SERVERS) is None
        messages = [m for _, m in reg.drain_events()]
        assert (
            sum("All upstream proxy servers are unavailable" in m for m in messages)
            == 1
        )

    def test_exclude_tried_terminates(self):
        reg = registry(failure_threshold=3)
        reg.record(P1, False, error="x")
        reg.record(P2, False, error="x")
        assert reg.select(SERVERS, tried=[P1, P2]) is P3
        reg.record(P3, False, error="x")
        assert reg.select(SERVERS, tried=[P1, P2, P3]) is None

    def test_aggregate_error(self):
        reg = registry(failure_threshold=1)
        reg.record(P1, False, error="[Errno 61] Connection refused")
        reg.record(P2, False, error="[SSL: BAD ALERT]")
        reg.record(P3, False, error="x")
        err = reg.aggregate_error(SERVERS)
        assert "Could not establish the connection" in err
        assert "http://p1:8080: unavailable" in err
        assert "[Errno 61] Connection refused" in err
        assert "https://p3:8443: unavailable" in err

    def test_status_text(self):
        reg = registry(failure_threshold=2)
        reg.record(P1, False, error="oops")
        text = reg.format_status(SERVERS)
        assert "http://p1:8080: degraded" in text
        assert "http://p2:8081: available" in text
        assert "oops" in text

    def test_configure_prunes_unknown(self):
        reg = registry()
        reg.record(P1, False, error="x")
        reg.configure(UpstreamSettings(), [P2])
        assert P1 not in reg._statuses
        assert reg.select([P2]) is P2

    def test_late_record_for_removed_server_tolerated(self):
        reg = registry()
        reg.configure(UpstreamSettings(), [P1])
        # A late failure notification for a server no longer configured must not raise.
        reg.record(P2, False, error="late")
        assert reg.status(P2).state is UpstreamHealth.DEGRADED

    def test_unhealthy_and_empty_selection(self):
        reg = registry(failure_threshold=3)
        assert reg.select([]) is None
        reg.record(P1, False, error="x")
        reg.record(P2, False, error="x")
        reg.record(P2, False, error="x")
        reg.record(P2, False, error="x")
        unhealthy = reg.unhealthy()
        assert P1 in unhealthy and P2 in unhealthy
        assert P3 not in unhealthy

    def test_recover_unknown_spec_is_noop(self):
        reg = registry()
        # A server that has never been contacted needs no recovery and is skipped.
        reg.recover(P3)
        assert reg.drain_events() == []
        assert reg.status(P3).state is UpstreamHealth.AVAILABLE

    @pytest.mark.parametrize(
        "error,expected",
        [
            ("[Errno 61] Connection refused", FailureKind.CONNECT),
            ("[SSL: TLSV1_ALERT_HANDSHAKE_FAILURE] tlsv1 alert", FailureKind.TLS),
            (
                "Upstream proxy 127.0.0.1:8080 refused HTTP CONNECT request: 502 Bad Gateway",
                FailureKind.HANDSHAKE,
            ),
            ("Error connecting to 127.0.0.1:8080: malformed", FailureKind.HANDSHAKE),
            (None, FailureKind.CONNECT),
        ],
    )
    def test_classify_failure(self, error, expected):
        assert upstreams.classify_failure(error) is expected

    def test_active_flag(self):
        reg = registry()
        assert reg.is_active_for([P1]) is False
        assert reg.is_active_for([P1, P2]) is True
        reg.configure(UpstreamSettings(enabled=True), [P1])
        assert reg.is_active_for([P1]) is True
