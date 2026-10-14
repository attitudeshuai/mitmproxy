from typing import TYPE_CHECKING

from mitmproxy import connection
from mitmproxy.options import Options

if TYPE_CHECKING:
    from mitmproxy.proxy.layer import Layer
    from mitmproxy.proxy.upstreams import UpstreamRegistry


class Context:
    """
    The context object provided to each protocol layer in the proxy core.
    """

    client: connection.Client
    """The client connection."""
    server: connection.Server
    """
    The server connection.

    For practical reasons this attribute is always set, even if there is not server connection yet.
    In this case the server address is `None`.
    """
    options: Options
    """
    Provides access to options for proxy layers. Not intended for use by addons, use `mitmproxy.ctx.options` instead.
    """
    layers: list["Layer"]
    """
    The protocol layer stack.
    """

    upstreams: "UpstreamRegistry | None"
    """
    Shared registry of upstream proxy server health, if the upstream health
    addon is loaded. `None` means that upstream proxy mode behaves as before
    without any health-based selection or failover.
    """

    def __init__(
        self,
        client: connection.Client,
        options: Options,
        upstreams: "UpstreamRegistry | None" = None,
    ) -> None:
        self.client = client
        self.options = options
        self.upstreams = upstreams
        self.server = connection.Server(
            address=None, transport_protocol=client.transport_protocol
        )
        self.layers = []

    def fork(self) -> "Context":
        ret = Context(self.client, self.options, self.upstreams)
        ret.server = self.server
        ret.layers = self.layers.copy()
        return ret

    def __repr__(self):
        return (
            f"Context(\n"
            f"  {self.client!r},\n"
            f"  {self.server!r},\n"
            f"  layers=[{self.layers!r}]\n"
            f")"
        )
