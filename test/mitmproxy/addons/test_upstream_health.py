from __future__ import annotations

import asyncio

import pytest

from .test_clientplayback import tcp_server
from mitmproxy import exceptions
from mitmproxy.addons.next_layer import NextLayer
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.addons.upstream_health import UpstreamHealth
from mitmproxy.net.free_port import get_free_port
from mitmproxy.proxy import upstreams
from mitmproxy.test import taddons


def test_invalid_options():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        with pytest.raises(exceptions.OptionsError, match="upstream_probe_interval"):
            tctx.configure(uh, upstream_probe_interval=0)
        with pytest.raises(exceptions.OptionsError, match="upstream_probe_interval"):
            tctx.configure(uh, upstream_probe_interval=-2)
        with pytest.raises(exceptions.OptionsError, match="upstream_probe_interval"):
            tctx.configure(uh, upstream_probe_interval=float("nan"))
        with pytest.raises(
            exceptions.OptionsError, match="upstream_failover_threshold"
        ):
            tctx.configure(uh, upstream_failover_threshold=0)
        # Wrong types are rejected by the options framework itself.
        with pytest.raises((exceptions.OptionsError, TypeError)):
            tctx.configure(uh, upstream_failover_threshold="abc")
        with pytest.raises((exceptions.OptionsError, TypeError)):
            tctx.configure(uh, upstream_probe_interval="soon")


def test_configure_ignores_unknown_and_dedupes_modes():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        # Invalid mode specs are skipped (proxyserver reports the error), and
        # the same server declared in multiple modes is only listed once.
        tctx.configure(
            uh,
            mode=[
                "upstream:http://primary:8080",
                "upstream:http://primary:8080",
                "this-is-not-a-mode",
            ],
        )
        assert uh._configured_servers() == [("http", ("primary", 8080))]


def test_configure_without_relevant_options_is_noop():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        # Must not raise despite no upstream-related option being updated.
        tctx.configure(uh, http2=False)


def test_status_and_recover_commands():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        assert "No upstream proxy servers configured." in uh.status()
        tctx.configure(
            uh,
            mode=["upstream:http://primary:8080,http://backup:8081"],
            upstream_failover_threshold=1,
        )
        assert "http://primary:8080: available" in uh.status()
        assert "http://backup:8081: available" in uh.status()

        with pytest.raises(exceptions.CommandError, match="not a configured"):
            uh.recover("http://unknown:1234")
        with pytest.raises(exceptions.CommandError):
            uh.recover("not a spec")

        uh.registry.record(("http", ("primary", 8080)), False, error="dead")
        uh.registry.drain_events()
        assert "http://primary:8080: unavailable" in uh.status()
        uh.recover("http://primary:8080")
        assert "http://primary:8080: available" in uh.status()

        uh.registry.record(("http", ("backup", 8081)), False, error="dead")
        uh.registry.drain_events()
        uh.recover()
        assert "http://backup:8081: available" in uh.status()


def test_configure_prunes_removed_servers():
    uh = UpstreamHealth()
    p1 = ("http", ("primary", 8080))
    p2 = ("http", ("backup", 8081))
    with taddons.context(uh) as tctx:
        tctx.configure(
            uh,
            mode=["upstream:http://primary:8080,http://backup:8081"],
            upstream_failover_threshold=1,
        )
        uh.registry.record(p1, False, error="x")
        uh.registry.record(p2, False, error="x")
        uh.registry.drain_events()
        assert p1 in uh.registry._statuses
        tctx.configure(uh, mode=["upstream:http://backup:8081"])
        assert p1 not in uh.registry._statuses
        assert p2 in uh.registry._statuses


async def test_probe_recovers_and_detects_failures():
    async def probe_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Health probes only establish a TCP connection and close again.
        data = await reader.read(1024)
        if data:
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        writer.close()

    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        async with tcp_server(probe_server) as backup_addr:
            dead_port = get_free_port()
            tctx.configure(
                uh,
                mode=[
                    f"upstream:http://127.0.0.1:{dead_port},"
                    f"http://{backup_addr[0]}:{backup_addr[1]}"
                ],
                upstream_failover_threshold=1,
            )
            live = ("http", (backup_addr[0], backup_addr[1]))
            dead = ("http", ("127.0.0.1", dead_port))

            uh.registry.record(live, False, error="earlier failure")
            uh.registry.drain_events()
            uh.registry.record(dead, False, error="earlier failure")
            uh.registry.drain_events()
            assert (
                uh.registry.status(live).state is upstreams.UpstreamHealth.UNAVAILABLE
            )
            assert (
                uh.registry.status(dead).state is upstreams.UpstreamHealth.UNAVAILABLE
            )

            await uh.probe_once()

            assert uh.registry.status(live).state is upstreams.UpstreamHealth.AVAILABLE
            # The dead port stays unavailable and its failure is classified as connect error.
            assert (
                uh.registry.status(dead).state is upstreams.UpstreamHealth.UNAVAILABLE
            )
            assert (
                uh.registry.status(dead).last_error_kind
                is upstreams.FailureKind.CONNECT
            )


async def test_probe_loop_lifecycle():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        tctx.configure(uh, upstream_probe_interval=60)
        assert uh._probe_task is None
        # done() before running is a no-op.
        uh.done()
        uh.running()
        first_task = uh._probe_task
        assert first_task is not None and not first_task.done()
        # Reconfiguring while running restarts the loop with the new interval.
        tctx.configure(uh, upstream_probe_interval=30)
        assert uh._probe_task is not first_task
        uh.done()
        assert uh._probe_task is None
        await asyncio.sleep(0)
        assert first_task.done()


async def test_probe_loop_runs_probes():
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        tctx.configure(uh, upstream_probe_interval=0.01)
        uh.running()
        await asyncio.sleep(0.1)
        uh.done()
        # The loop has called probe_once repeatedly without error (no unhealthy servers).
        assert uh._probe_task is None


async def tls_probe_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Complete the TLS handshake, nothing else is needed for probing.
    writer.close()


def _self_signed_cert(tmp_path) -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "cert.pem"
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(path)


async def test_probe_https(tmp_path):
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(_self_signed_cert(tmp_path))
    uh = UpstreamHealth()
    with taddons.context(uh) as tctx:
        server = await asyncio.start_server(tls_probe_server, "127.0.0.1", 0, ssl=ctx)
        async with server:
            tls_addr = server.sockets[0].getsockname()
            dead_port = get_free_port()
            tctx.configure(
                uh,
                mode=[
                    f"upstream:https://127.0.0.1:{dead_port},"
                    f"https://{tls_addr[0]}:{tls_addr[1]}"
                ],
                upstream_failover_threshold=1,
            )
            live = ("https", (tls_addr[0], tls_addr[1]))
            dead = ("https", ("127.0.0.1", dead_port))
            uh.registry.record(live, False, error="earlier")
            uh.registry.record(dead, False, error="earlier")
            uh.registry.drain_events()

            await uh.probe_once()

            assert uh.registry.status(live).state is upstreams.UpstreamHealth.AVAILABLE
            # The dead HTTPS port fails at the TCP level, not with a TLS error.
            assert (
                uh.registry.status(dead).state is upstreams.UpstreamHealth.UNAVAILABLE
            )
            assert (
                uh.registry.status(dead).last_error_kind
                is upstreams.FailureKind.CONNECT
            )


async def test_end_to_end_failover(caplog_async):
    caplog_async.set_level("WARNING")

    async def backup_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    ps = Proxyserver()
    uh = UpstreamHealth()
    nl = NextLayer()
    with taddons.context(ps, uh, nl) as tctx:
        async with tcp_server(backup_handler) as backup_addr:
            dead_port = get_free_port()
            tctx.configure(
                ps,
                listen_host="127.0.0.1",
                listen_port=0,
                mode=[
                    f"upstream:http://127.0.0.1:{dead_port},"
                    f"http://{backup_addr[0]}:{backup_addr[1]}"
                ],
                upstream_failover_threshold=1,
            )
            assert await ps.setup_servers()
            ps.running()

            proxy_addr = ps.listen_addrs()[0]
            reader, writer = await asyncio.open_connection(*proxy_addr)
            writer.write(
                b"GET http://example.com/hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            response = await reader.readuntil(b"\r\n\r\n")
            assert b"204 No Content" in response

            await caplog_async.await_log("failover")

            primary = ("http", ("127.0.0.1", dead_port))
            backup = ("http", backup_addr)
            assert (
                uh.registry.status(primary).state
                is upstreams.UpstreamHealth.UNAVAILABLE
            )
            assert (
                uh.registry.status(backup).state is upstreams.UpstreamHealth.AVAILABLE
            )
            assert uh.registry.status(primary).last_error is not None
            assert "unavailable" in uh.status()

            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            tctx.configure(ps, server=False)
            if ps.servers.is_updating:
                async with ps.servers._lock:
                    pass
