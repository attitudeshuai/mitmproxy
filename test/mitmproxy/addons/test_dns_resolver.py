import asyncio
import socket
import sys
import typing

import pytest

import mitmproxy_rs
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy.addons import dns_resolver
from mitmproxy.addons import proxyserver
from mitmproxy.addons.dns_resolver import GetaddrinfoFallbackResolver
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils


async def test_ignores_reverse_mode():
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr, proxyserver.Proxyserver()):
        f = tflow.tdnsflow()
        f.client_conn.proxy_mode = ProxyMode.parse("dns")
        assert dr._should_resolve(f)

        f.client_conn.proxy_mode = ProxyMode.parse("wireguard")
        f.server_conn.address = ("10.0.0.53", 53)
        assert dr._should_resolve(f)

        f.client_conn.proxy_mode = ProxyMode.parse("reverse:dns://8.8.8.8")
        assert not dr._should_resolve(f)


def _err():
    raise RuntimeError("failed to get name servers")


async def test_name_servers(caplog, monkeypatch):
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        assert dr.name_servers() == mitmproxy_rs.dns.get_system_dns_servers()

        tctx.options.dns_name_servers = ["1.1.1.1"]
        assert dr.name_servers() == ["1.1.1.1"]

        monkeypatch.setattr(mitmproxy_rs.dns, "get_system_dns_servers", _err)
        tctx.options.dns_name_servers = []
        assert dr.name_servers() == []
        assert "Failed to get system dns servers" in caplog.text


async def lookup(name: str):
    match name:
        case "ipv4.example.com":
            return ["1.2.3.4"]
        case "ipv6.example.com":
            return ["::1"]
        case "no-a-records.example.com":
            raise socket.gaierror(socket.EAI_NODATA)
        case "no-network.example.com":
            raise socket.gaierror(socket.EAI_AGAIN)
        case _:
            raise socket.gaierror(socket.EAI_NONAME)


async def getaddrinfo(host: str, *_, **__):
    return [[None, None, None, None, [ip]] for ip in await lookup(host)]


Domain = typing.Literal[
    "nxdomain.example.com",
    "no-a-records.example.com",
    "no-network.example.com",
    "txt.example.com",
    "ipv4.example.com",
    "ipv6.example.com",
]
# We use literals here instead of bools because that makes the test easier to parse.
HostsFile = typing.Literal["hosts", "no-hosts"]
NameServers = typing.Literal["nameservers", "no-nameservers"]


@pytest.mark.parametrize("hosts_file", typing.get_args(HostsFile))
@pytest.mark.parametrize("name_servers", typing.get_args(NameServers))
@pytest.mark.parametrize("domain", typing.get_args(Domain))
async def test_lookup(
    domain: Domain, hosts_file: HostsFile, name_servers: NameServers, monkeypatch
):
    if name_servers == "nameservers":
        monkeypatch.setattr(
            mitmproxy_rs.dns, "get_system_dns_servers", lambda: ["8.8.8.8"]
        )
        monkeypatch.setattr(
            mitmproxy_rs.dns.DnsResolver, "lookup_ipv4", lambda _, name: lookup(name)
        )
        monkeypatch.setattr(
            mitmproxy_rs.dns.DnsResolver, "lookup_ipv6", lambda _, name: lookup(name)
        )
    else:
        monkeypatch.setattr(mitmproxy_rs.dns, "get_system_dns_servers", lambda: [])
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)

    dr = dns_resolver.DnsResolver()
    match domain:
        case "txt.example.com":
            typ = dns.types.TXT
        case "ipv6.example.com":
            typ = dns.types.AAAA
        case _:
            typ = dns.types.A

    with taddons.context(dr) as tctx:
        tctx.options.dns_use_hosts_file = hosts_file == "hosts"
        req = tutils.tdnsreq(
            questions=[
                dns.Question(domain, typ, dns.classes.IN),
            ]
        )
        flow = tflow.tdnsflow(req=req)
        await dr.dns_request(flow)

        match (domain, name_servers, hosts_file):
            case [_, "no-nameservers", "no-hosts"]:
                assert flow.error
            case ["nxdomain.example.com", _, _]:
                assert flow.response.response_code == dns.response_codes.NXDOMAIN
            case ["no-network.example.com", _, _]:
                assert flow.response.response_code == dns.response_codes.SERVFAIL
            case ["no-a-records.example.com", _, _]:
                if sys.platform == "win32":
                    # On Windows, EAI_NONAME and EAI_NODATA are the same constant (11001)...
                    assert flow.response.response_code == dns.response_codes.NXDOMAIN
                else:
                    assert flow.response.response_code == dns.response_codes.NOERROR
                assert not flow.response.answers
            case ["txt.example.com", "nameservers", _]:
                assert flow.server_conn.address == ("8.8.8.8", 53)
            case ["txt.example.com", "no-nameservers", _]:
                assert flow.error
            case ["ipv4.example.com", "nameservers", _]:
                assert flow.response.answers[0].data == b"\x01\x02\x03\x04"
            case ["ipv4.example.com", "no-nameservers", "hosts"]:
                assert flow.response.answers[0].data == b"\x01\x02\x03\x04"
            case ["ipv6.example.com", "nameservers", _]:
                assert (
                    flow.response.answers[0].data
                    == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                )
            case ["ipv6.example.com", "no-nameservers", "hosts"]:
                assert (
                    flow.response.answers[0].data
                    == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                )
            case other:
                typing.assert_never(other)


async def test_unspec_lookup(monkeypatch):
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
    assert await GetaddrinfoFallbackResolver().lookup_ip("ipv6.example.com") == ["::1"]


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.time = start

    def __call__(self) -> float:
        return self.time

    def advance(self, seconds: float) -> None:
        self.time += seconds


class FakeUpstream:
    """Deterministic stand-in for the hickory resolver."""

    def __init__(self):
        self.calls: list[str] = []
        self.broken: set[str] = set()

    async def __call__(self, name: str) -> list[str]:
        self.calls.append(name)
        if name in self.broken:
            raise socket.gaierror(socket.EAI_AGAIN)
        if name.endswith("nx.example"):
            raise socket.gaierror(socket.EAI_NONAME)
        if name.endswith("ipv6.example"):
            return ["::1"]
        return ["1.2.3.4"]


def _install_upstream(monkeypatch, upstream: FakeUpstream) -> None:
    async def lookup_ipv4(_resolver, name: str) -> list[str]:
        return await upstream(name)

    async def lookup_ipv6(_resolver, name: str) -> list[str]:
        return await upstream(name)

    monkeypatch.setattr(mitmproxy_rs.dns, "get_system_dns_servers", lambda: ["8.8.8.8"])
    monkeypatch.setattr(mitmproxy_rs.dns.DnsResolver, "lookup_ipv4", lookup_ipv4)
    monkeypatch.setattr(mitmproxy_rs.dns.DnsResolver, "lookup_ipv6", lookup_ipv6)


def _dns_flow(domain: str, typ: int = dns.types.A, id: int = 42):
    req = tutils.tdnsreq(
        id=id,
        questions=[dns.Question(domain, typ, dns.classes.IN)],
    )
    return tflow.tdnsflow(req=req)


def _cache_key(domain: str, typ: int = dns.types.A):
    return dns_resolver._CacheKey(domain.lower(), typ, dns.classes.IN)


async def test_cache_disabled_queries_upstream_every_time(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        assert not tctx.options.dns_cache
        f1 = _dns_flow("a.example", id=1)
        f2 = _dns_flow("a.example", id=2)
        await dr.dns_request(f1)
        await dr.dns_request(f2)
        assert len(upstream.calls) == 2
        assert f1.response.id == 1
        assert f2.response.id == 2
        assert f1.response.answers[0].ttl == dns.ResourceRecord.DEFAULT_TTL
        assert len(dr.cache) == 0


async def test_cache_hit_rewrites_remaining_ttl(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True

        f1 = _dns_flow("a.example", id=1)
        await dr.dns_request(f1)
        assert f1.response.answers[0].ttl == 60
        assert upstream.calls == ["a.example"]

        clock.advance(20)
        f2 = _dns_flow("a.example", id=2)
        await dr.dns_request(f2)
        assert f2.response.answers[0].ttl == 40
        assert upstream.calls == ["a.example"]
        assert f2.response.id == 2

        clock.advance(41)
        f3 = _dns_flow("a.example", id=3)
        await dr.dns_request(f3)
        assert f3.response.answers[0].ttl == 60
        assert upstream.calls == ["a.example", "a.example"]

        stats = dr.cache.stats
        assert (stats.hits, stats.misses, stats.stale, stats.negative) == (1, 2, 0, 0)


async def test_cache_key_includes_type_and_is_case_insensitive(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True

        await dr.dns_request(_dns_flow("a.example", dns.types.A))
        await dr.dns_request(_dns_flow("A.Example", dns.types.A))
        assert upstream.calls == ["a.example"]

        await dr.dns_request(_dns_flow("a.example", dns.types.AAAA))
        assert upstream.calls == ["a.example", "a.example"]
        assert len(dr.cache) == 2


async def test_ttl_bounds_clamp_cached_answers(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_ttl_max = 30

        f = _dns_flow("a.example")
        await dr.dns_request(f)
        assert f.response.answers[0].ttl == 30

    dr = dns_resolver.DnsResolver()
    dr.cache.clock = clock
    _install_upstream(monkeypatch, upstream)
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_ttl_min = 90

        await dr.dns_request(_dns_flow("a.example"))
        clock.advance(70)
        f = _dns_flow("a.example", id=3)
        await dr.dns_request(f)
        assert f.response.answers[0].ttl == 20
        assert len(upstream.calls) == 2


async def test_negative_cache_nxdomain_and_servfail(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_negative_ttl = 10

        f = _dns_flow("nx.example")
        await dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.NXDOMAIN
        await dr.dns_request(_dns_flow("nx.example", id=2))
        assert upstream.calls == ["nx.example"]
        assert dr.cache.stats.negative == 1

        clock.advance(10)
        await dr.dns_request(_dns_flow("nx.example", id=3))
        assert upstream.calls == ["nx.example", "nx.example"]

        upstream.broken.add("down.example")
        f = _dns_flow("down.example", id=4)
        await dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.SERVFAIL
        await dr.dns_request(_dns_flow("down.example", id=5))
        assert upstream.calls[-1] == "down.example"
        assert len(upstream.calls) == 3
        assert dr.cache.stats.negative == 2


async def test_errors_outside_negative_scope_are_not_cached(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()

    async def refused(_message):
        return _message.fail(dns.response_codes.REFUSED)

    monkeypatch.setattr(dr, "resolve", refused)
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        await dr.dns_request(_dns_flow("a.example"))
        await dr.dns_request(_dns_flow("a.example", id=2))
        assert len(dr.cache) == 0
        assert (dr.cache.stats.hits, dr.cache.stats.misses) == (0, 2)


async def test_stale_answer_served_on_upstream_failure(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_stale = True

        await dr.dns_request(_dns_flow("a.example"))
        assert len(upstream.calls) == 1

        clock.advance(61)
        upstream.broken.add("a.example")
        f = _dns_flow("a.example", id=2)
        await dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.NOERROR
        assert f.response.answers[0].ttl == 0
        assert f.metadata["dns_stale"] is True
        assert dr.cache.stats.stale == 1
        assert len(upstream.calls) == 2
        # The expired entry is retained and every query retries upstream.
        await dr.dns_request(_dns_flow("a.example", id=3))
        assert len(upstream.calls) == 3

        upstream.broken.remove("a.example")
        f = _dns_flow("a.example", id=4)
        await dr.dns_request(f)
        assert f.response.answers[0].ttl == 60
        assert "dns_stale" not in f.metadata


async def test_stale_disabled_returns_servfail_and_negatively_caches(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True

        await dr.dns_request(_dns_flow("a.example"))
        clock.advance(61)
        upstream.broken.add("a.example")

        f = _dns_flow("a.example", id=2)
        await dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.SERVFAIL
        assert "dns_stale" not in f.metadata
        assert dr.cache.stats.stale == 0

        await dr.dns_request(_dns_flow("a.example", id=3))
        assert len(upstream.calls) == 2
        assert dr.cache.stats.negative == 1


async def test_nxdomain_does_not_serve_stale(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    clock = FakeClock()
    dr.cache.clock = clock
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_stale = True

        await dr.dns_request(_dns_flow("nx.example"))
        clock.advance(61)
        f = _dns_flow("nx.example", id=2)
        await dr.dns_request(f)
        assert f.response.response_code == dns.response_codes.NXDOMAIN
        assert "dns_stale" not in f.metadata
        assert dr.cache.stats.stale == 0
        assert dr.cache.peek(_cache_key("nx.example")).negative


async def test_lru_eviction(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        tctx.options.dns_cache_size = 2

        for i, name in enumerate(["a.example", "b.example", "c.example"]):
            await dr.dns_request(_dns_flow(name, id=i + 1))
        assert len(dr.cache) == 2
        assert dr.cache.peek(_cache_key("a.example")) is None

        # b and c are still cached.
        await dr.dns_request(_dns_flow("b.example", id=10))
        await dr.dns_request(_dns_flow("c.example", id=11))
        assert upstream.calls == ["a.example", "b.example", "c.example"]

        # a has been evicted and is queried again.
        await dr.dns_request(_dns_flow("a.example", id=12))
        assert upstream.calls[-1] == "a.example"
        assert dr.cache.peek(_cache_key("b.example")) is None


async def test_config_validation():
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        for value in (0, -1):
            with pytest.raises(exceptions.OptionsError):
                tctx.options.dns_cache_size = value
        with pytest.raises(exceptions.OptionsError):
            tctx.options.dns_cache_ttl_min = 0
        with pytest.raises(exceptions.OptionsError):
            tctx.options.dns_cache_ttl_max = -1
        tctx.options.dns_cache_ttl_max = 60
        with pytest.raises(exceptions.OptionsError):
            tctx.options.dns_cache_ttl_min = 61
        with pytest.raises(exceptions.OptionsError):
            tctx.options.dns_cache_negative_ttl = 0
        # Valid changes are accepted.
        tctx.options.dns_cache_size = 10
        tctx.options.dns_cache_ttl_min = 30
        tctx.options.dns_cache_ttl_max = 300


async def test_configure_clears_cache(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        await dr.dns_request(_dns_flow("a.example"))
        assert len(dr.cache) == 1

        tctx.options.dns_cache_ttl_max = 120
        assert len(dr.cache) == 0

        await dr.dns_request(_dns_flow("a.example", id=2))
        assert len(dr.cache) == 1
        tctx.options.dns_name_servers = ["1.1.1.1"]
        assert len(dr.cache) == 0


async def test_concurrent_queries_share_upstream_lookup(monkeypatch):
    dr = dns_resolver.DnsResolver()
    entered = asyncio.Event()
    proceed = asyncio.Event()
    calls: list[str] = []

    async def lookup_ipv4(_resolver, name: str) -> list[str]:
        calls.append(name)
        entered.set()
        await proceed.wait()
        return ["1.2.3.4"]

    monkeypatch.setattr(mitmproxy_rs.dns, "get_system_dns_servers", lambda: ["8.8.8.8"])
    monkeypatch.setattr(mitmproxy_rs.dns.DnsResolver, "lookup_ipv4", lookup_ipv4)
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        f1 = _dns_flow("a.example", id=1)
        f2 = _dns_flow("a.example", id=2)
        task1 = asyncio.ensure_future(dr.dns_request(f1))
        await entered.wait()
        task2 = asyncio.ensure_future(dr.dns_request(f2))
        await asyncio.sleep(0)
        proceed.set()
        await asyncio.gather(task1, task2)

        assert calls == ["a.example"]
        assert f1.response.answers[0].data == f2.response.answers[0].data
        assert f1.response.id == 1
        assert f2.response.id == 2
        assert dr.cache.stats.misses == 2


async def test_cache_commands(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        await dr.dns_request(_dns_flow("a.example", dns.types.A))
        await dr.dns_request(_dns_flow("a.example", dns.types.A, id=2))
        await dr.dns_request(_dns_flow("a.example", dns.types.AAAA, id=3))

        report = dr.cache_stats()
        assert "enabled" in report
        assert "Hits: 1" in report
        assert "Misses: 2" in report

        assert dr.cache_clear("A.Example") == 2
        assert len(dr.cache) == 0
        assert dr.cache_clear("a.example") == 0


async def test_forwarded_queries_are_not_cached(monkeypatch):
    upstream = FakeUpstream()
    _install_upstream(monkeypatch, upstream)
    dr = dns_resolver.DnsResolver()
    with taddons.context(dr) as tctx:
        tctx.options.dns_cache = True
        f = _dns_flow("txt.example", dns.types.TXT)
        await dr.dns_request(f)
        assert f.server_conn.address == ("8.8.8.8", 53)
        assert not f.response
        assert len(dr.cache) == 0
