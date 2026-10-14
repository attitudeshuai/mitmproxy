from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import socket
import time
from collections import OrderedDict
from collections.abc import Callable
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from functools import cache
from typing import Protocol

import mitmproxy_rs
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy.flow import Error
from mitmproxy.proxy import mode_specs
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


class _LookupOutcome(Enum):
    """How a lookup that was not served from a fresh cache entry was answered."""

    fetched = "fetched"
    """The upstream resolver was queried and its (fresh) answer was cached."""

    failure = "failure"
    """The upstream resolver failed, no stale answer was available."""

    stale = "stale"
    """An expired cached answer was served because the upstream resolver failed."""


@dataclass(frozen=True)
class _FetchResult:
    outcome: _LookupOutcome
    response_code: int
    entry: _CacheEntry | None = None


@dataclass(frozen=True)
class _CacheKey:
    name: str
    type: int
    class_: int


@dataclass
class _CacheEntry:
    response_code: int
    answers: tuple[dns.ResourceRecord, ...]
    stored_at: float
    ttl: int
    negative: bool

    def is_expired(self, now: float) -> bool:
        return now - self.stored_at >= self.ttl

    def remaining_ttl(self, now: float) -> int:
        return max(0, int(self.ttl - (now - self.stored_at)))

    def to_message(
        self, message: dns.DNSMessage, now: float, *, stale: bool = False
    ) -> dns.DNSMessage:
        if self.negative:
            return message.fail(self.response_code)
        ttl = 0 if stale else self.remaining_ttl(now)
        return message.succeed(
            [dataclasses.replace(record, ttl=ttl) for record in self.answers]
        )


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale: int = 0
    negative: int = 0


class DnsCache:
    """
    Bounded LRU cache for synthesized DNS responses.

    Lookups do not change the recency order, callers must invoke `touch`
    explicitly when an entry is actually used.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._entries: OrderedDict[_CacheKey, _CacheEntry] = OrderedDict()
        self.clock = clock
        self.stats = CacheStats()

    def __len__(self) -> int:
        return len(self._entries)

    def peek(self, key: _CacheKey) -> _CacheEntry | None:
        return self._entries.get(key)

    def touch(self, key: _CacheKey) -> None:
        # The entry may already have been evicted while a lookup was in flight.
        if key in self._entries:
            self._entries.move_to_end(key)

    def put(self, key: _CacheKey, entry: _CacheEntry, *, capacity: int) -> None:
        self._entries[key] = entry
        self._entries.move_to_end(key)
        while len(self._entries) > capacity:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        self._entries.clear()

    def clear_domain(self, name: str) -> int:
        name = name.lower()
        keys = [key for key in self._entries if key.name == name]
        for key in keys:
            del self._entries[key]
        return len(keys)


class DnsResolver:
    def __init__(self) -> None:
        self.cache = DnsCache()
        self._inflight: dict[_CacheKey, asyncio.Task[_FetchResult]] = {}

    def load(self, loader):
        loader.add_option(
            "dns_use_hosts_file",
            bool,
            True,
            "Use the hosts file for DNS lookups in regular DNS mode/wireguard mode.",
        )

        loader.add_option(
            "dns_name_servers",
            Sequence[str],
            [],
            "Name servers to use for lookups in regular DNS mode/wireguard mode. Default: operating system's name servers",
        )

        loader.add_option(
            "dns_cache",
            bool,
            False,
            "Cache DNS responses in regular DNS mode/wireguard mode.",
        )
        loader.add_option(
            "dns_cache_size",
            int,
            256,
            "Maximum number of DNS responses kept in the cache. "
            "When the cache is full, the least recently used entries are evicted.",
        )
        loader.add_option(
            "dns_cache_ttl_min",
            int,
            1,
            "Lower bound in seconds for the TTL of cached DNS responses. "
            "Upstream TTLs shorter than this are raised to it.",
        )
        loader.add_option(
            "dns_cache_ttl_max",
            int,
            86400,
            "Upper bound in seconds for the TTL of cached DNS responses. "
            "Upstream TTLs longer than this are capped to it.",
        )
        loader.add_option(
            "dns_cache_negative_ttl",
            int,
            30,
            "TTL in seconds for negatively cached DNS failures "
            "(non-existent domain and server failure).",
        )
        loader.add_option(
            "dns_cache_stale",
            bool,
            False,
            "Serve stale cached responses with a TTL of zero "
            "when the upstream DNS resolver is unavailable.",
        )

    def configure(self, updated):
        if "dns_use_hosts_file" in updated or "dns_name_servers" in updated:
            self.resolver.cache_clear()
            self.name_servers.cache_clear()
            self.cache.clear()

        cache_options = {
            "dns_cache",
            "dns_cache_size",
            "dns_cache_ttl_min",
            "dns_cache_ttl_max",
            "dns_cache_negative_ttl",
            "dns_cache_stale",
        }
        if cache_options & updated:
            options = ctx.options
            if options.dns_cache_size <= 0:
                raise exceptions.OptionsError(
                    "dns_cache_size must be greater than zero."
                )
            if options.dns_cache_ttl_min <= 0 or options.dns_cache_ttl_max <= 0:
                raise exceptions.OptionsError(
                    "dns_cache_ttl_min and dns_cache_ttl_max must be greater than zero."
                )
            if options.dns_cache_ttl_min > options.dns_cache_ttl_max:
                raise exceptions.OptionsError(
                    "dns_cache_ttl_min must not be greater than dns_cache_ttl_max."
                )
            if options.dns_cache_negative_ttl <= 0:
                raise exceptions.OptionsError(
                    "dns_cache_negative_ttl must be greater than zero."
                )
            self.cache.clear()

    @cache
    def name_servers(self) -> list[str]:
        """
        Returns the operating system's name servers unless custom name servers are set.
        On error, an empty list is returned.
        """
        try:
            return (
                ctx.options.dns_name_servers
                or mitmproxy_rs.dns.get_system_dns_servers()
            )
        except RuntimeError as e:
            logger.warning(
                f"Failed to get system dns servers: {e}\n"
                f"The dns_name_servers option needs to be set manually."
            )
            return []

    @cache
    def resolver(self) -> Resolver:
        """
        Returns:
            The DNS resolver to use.
        Raises:
            MissingNameServers, if name servers are unknown and `dns_use_hosts_file` is disabled.
        """
        if ns := self.name_servers():
            # We always want to use our own resolver if name server info is available.
            return mitmproxy_rs.dns.DnsResolver(
                name_servers=ns,
                use_hosts_file=ctx.options.dns_use_hosts_file,
            )
        elif ctx.options.dns_use_hosts_file:
            # Fallback to getaddrinfo as hickory's resolver isn't as reliable
            # as we would like it to be (https://github.com/mitmproxy/mitmproxy/issues/7064).
            return GetaddrinfoFallbackResolver()
        else:
            raise MissingNameServers()

    async def dns_request(self, flow: dns.DNSFlow) -> None:
        if self._should_resolve(flow):
            all_ip_lookups = (
                flow.request.query
                and flow.request.op_code == dns.op_codes.QUERY
                and flow.request.question
                and flow.request.question.class_ == dns.classes.IN
                and flow.request.question.type in (dns.types.A, dns.types.AAAA)
            )
            if all_ip_lookups:
                try:
                    if ctx.options.dns_cache:
                        response, stale = await self._resolve_cached(flow.request)
                        if stale:
                            flow.metadata["dns_stale"] = True
                        flow.response = response
                    else:
                        flow.response = await self.resolve(flow.request)
                except MissingNameServers:
                    flow.error = Error("Cannot resolve, dns_name_servers unknown.")
            elif name_servers := self.name_servers():
                # For other records, the best we can do is to forward the query
                # to an upstream server.
                flow.server_conn.address = (name_servers[0], 53)
            else:
                flow.error = Error("Cannot resolve, dns_name_servers unknown.")

    @staticmethod
    def _should_resolve(flow: dns.DNSFlow) -> bool:
        return (
            (
                isinstance(flow.client_conn.proxy_mode, mode_specs.DnsMode)
                or (
                    isinstance(flow.client_conn.proxy_mode, mode_specs.WireGuardMode)
                    and flow.server_conn.address == ("10.0.0.53", 53)
                )
            )
            and flow.live
            and not flow.response
            and not flow.error
        )

    async def _resolve_cached(
        self, message: dns.DNSMessage
    ) -> tuple[dns.DNSMessage, bool]:
        """
        Resolve a query, serving from the cache when possible. Concurrent queries
        for the same name share a single upstream lookup.
        Returns the response together with a flag indicating a stale answer.
        """
        question = message.question
        assert question
        key = _CacheKey(question.name.lower(), question.type, question.class_)

        now = self.cache.clock()
        entry = self.cache.peek(key)
        if entry is not None and not entry.is_expired(now):
            self.cache.touch(key)
            if entry.negative:
                self.cache.stats.negative += 1
            else:
                self.cache.stats.hits += 1
            return entry.to_message(message, now), False

        task = self._inflight.get(key)
        if task is None:
            task = asyncio_utils.create_task(
                self._fetch_into_cache(key, message, entry),
                name="dns_resolve",
                keep_ref=True,
            )
            self._inflight[key] = task
            is_leader = True
        else:
            is_leader = False

        try:
            result = await task
        finally:
            # Remove the task synchronously after awaiting it: with eager task
            # factories a `done_callback` would be scheduled only later and a
            # completed task could then be mistaken for an in-flight lookup.
            if is_leader:
                self._inflight.pop(key, None)

        outcome = result.outcome
        now = self.cache.clock()
        if outcome == _LookupOutcome.stale and result.entry is not None:
            self.cache.touch(key)
            self.cache.stats.stale += 1
            return result.entry.to_message(message, now, stale=True), True

        self.cache.stats.misses += 1
        if outcome == _LookupOutcome.fetched:
            assert result.entry is not None
            return result.entry.to_message(message, now), False
        return message.fail(result.response_code), False

    async def _fetch_into_cache(
        self,
        key: _CacheKey,
        message: dns.DNSMessage,
        stale_entry: _CacheEntry | None,
    ) -> _FetchResult:
        try:
            response = await self.resolve(message)
        except MissingNameServers:
            raise

        response_code = response.response_code
        if response_code == dns.response_codes.NOERROR:
            ttl = min(
                (record.ttl for record in response.answers),
                default=dns.ResourceRecord.DEFAULT_TTL,
            )
            ttl = min(
                max(ttl, ctx.options.dns_cache_ttl_min),
                ctx.options.dns_cache_ttl_max,
            )
            entry = _CacheEntry(
                response_code=response_code,
                answers=tuple(
                    dataclasses.replace(record, ttl=ttl) for record in response.answers
                ),
                stored_at=self.cache.clock(),
                ttl=ttl,
                negative=False,
            )
            self.cache.put(key, entry, capacity=ctx.options.dns_cache_size)
            return _FetchResult(_LookupOutcome.fetched, response_code, entry)

        if response_code in (
            dns.response_codes.NXDOMAIN,
            dns.response_codes.SERVFAIL,
        ):
            if (
                response_code == dns.response_codes.SERVFAIL
                and stale_entry is not None
                and not stale_entry.negative
                and ctx.options.dns_cache_stale
            ):
                logger.warning(
                    f"Upstream DNS resolution for {key.name} failed, "
                    f"serving stale cached answer."
                )
                return _FetchResult(_LookupOutcome.stale, response_code, stale_entry)

            self.cache.put(
                key,
                _CacheEntry(
                    response_code=response_code,
                    answers=(),
                    stored_at=self.cache.clock(),
                    ttl=ctx.options.dns_cache_negative_ttl,
                    negative=True,
                ),
                capacity=ctx.options.dns_cache_size,
            )

        # Errors outside the negative-cache scope (NXDOMAIN, SERVFAIL) are not cached.
        return _FetchResult(_LookupOutcome.failure, response_code)

    async def resolve(
        self,
        message: dns.DNSMessage,
    ) -> dns.DNSMessage:
        q = message.question
        assert q
        try:
            if q.type == dns.types.A:
                ip_addrs = await self.resolver().lookup_ipv4(q.name)
            else:
                ip_addrs = await self.resolver().lookup_ipv6(q.name)
        except socket.gaierror as e:
            match e.args[0]:
                case socket.EAI_NONAME:
                    return message.fail(dns.response_codes.NXDOMAIN)
                case socket.EAI_NODATA:
                    ip_addrs = []
                case _:
                    return message.fail(dns.response_codes.SERVFAIL)

        return message.succeed(
            [
                dns.ResourceRecord(
                    name=q.name,
                    type=q.type,
                    class_=q.class_,
                    ttl=dns.ResourceRecord.DEFAULT_TTL,
                    data=ipaddress.ip_address(ip).packed,
                )
                for ip in ip_addrs
            ]
        )

    @command.command("dns.cache.stats")
    def cache_stats(self) -> str:
        """
        Show DNS response cache statistics.
        """
        stats = self.cache.stats
        return "\n".join(
            [
                f"DNS cache: {'enabled' if ctx.options.dns_cache else 'disabled'}",
                f"Entries: {len(self.cache)}/{ctx.options.dns_cache_size}",
                f"Hits: {stats.hits}",
                f"Misses: {stats.misses}",
                f"Stale answers: {stats.stale}",
                f"Negative answers: {stats.negative}",
            ]
        )

    @command.command("dns.cache.clear")
    def cache_clear(self, domain: str) -> int:
        """
        Remove all cached responses for the given domain. Returns the number of entries removed.
        """
        return self.cache.clear_domain(domain)


class Resolver(Protocol):
    async def lookup_ip(self, domain: str) -> list[str]:  # pragma: no cover
        ...

    async def lookup_ipv4(self, domain: str) -> list[str]:  # pragma: no cover
        ...

    async def lookup_ipv6(self, domain: str) -> list[str]:  # pragma: no cover
        ...


class GetaddrinfoFallbackResolver(Resolver):
    async def lookup_ip(self, domain: str) -> list[str]:
        return await self._lookup(domain, socket.AF_UNSPEC)

    async def lookup_ipv4(self, domain: str) -> list[str]:
        return await self._lookup(domain, socket.AF_INET)

    async def lookup_ipv6(self, domain: str) -> list[str]:
        return await self._lookup(domain, socket.AF_INET6)

    async def _lookup(self, domain: str, family: socket.AddressFamily) -> list[str]:
        addrinfos = await asyncio.get_running_loop().getaddrinfo(
            host=domain,
            port=None,
            family=family,
            type=socket.SOCK_STREAM,
        )
        return [addrinfo[4][0] for addrinfo in addrinfos]


class MissingNameServers(RuntimeError):
    pass
