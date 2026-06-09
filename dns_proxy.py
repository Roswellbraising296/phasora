"""
Phasora - DNS Proxy
Forwards DNS queries through SOCKS5 — prevents DNS leaks

Author : Rushqp
Project: Phasora — github or local
"""

import asyncio
import logging
import struct
import argparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PHASORA-DNS] %(message)s")
log = logging.getLogger("dns_proxy")

DEFAULT_DNS      = "1.1.1.1"   # DNS server on the server side (goes through tunnel)
DEFAULT_DNS_PORT = 53
TIMEOUT          = 5


async def socks5_connect(
    socks_host: str, socks_port: int,
    dst_host: str, dst_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection through SOCKS5"""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port),
        timeout=TIMEOUT,
    )

    # SOCKS5 greeting: no auth
    writer.write(b'\x05\x01\x00')
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[1] != 0x00:
        writer.close()
        raise ConnectionError("SOCKS5 auth failed")

    # CONNECT request
    host_bytes = dst_host.encode()
    writer.write(
        b'\x05\x01\x00\x03'
        + bytes([len(host_bytes)])
        + host_bytes
        + struct.pack(">H", dst_port)
    )
    await writer.drain()

    resp = await reader.readexactly(4)
    if resp[1] != 0x00:
        writer.close()
        raise ConnectionError(f"SOCKS5 CONNECT rejected: {resp[1]}")

    # skip remaining address bytes
    atyp = resp[3]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)

    return reader, writer


async def resolve_via_tunnel(
    query: bytes,
    socks_host: str, socks_port: int,
    dns_host: str,  dns_port: int,
) -> bytes | None:
    """Send a DNS query through SOCKS5 to the DNS server (DNS over TCP)"""
    try:
        reader, writer = await asyncio.wait_for(
            socks5_connect(socks_host, socks_port, dns_host, dns_port),
            timeout=TIMEOUT,
        )
        try:
            # DNS over TCP: 2-byte length prefix
            writer.write(struct.pack(">H", len(query)) + query)
            await writer.drain()

            resp_len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=TIMEOUT)
            resp_len       = struct.unpack(">H", resp_len_bytes)[0]
            response       = await asyncio.wait_for(reader.readexactly(resp_len), timeout=TIMEOUT)
            return response
        finally:
            writer.close()
    except Exception as e:
        log.warning(f"DNS tunnel error: {e}")
        return None


class DNSProxyProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        socks_host: str, socks_port: int,
        dns_host: str,   dns_port: int,
        loop: asyncio.AbstractEventLoop,
    ):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.dns_host   = dns_host
        self.dns_port   = dns_port
        self.loop       = loop
        self.transport  = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, query: bytes, addr: tuple):
        try:
            response = await resolve_via_tunnel(
                query,
                self.socks_host, self.socks_port,
                self.dns_host,   self.dns_port,
            )
            if response and self.transport:
                self.transport.sendto(response, addr)
            else:
                log.warning(f"No DNS response for query from {addr}")
        except Exception as e:
            log.error(f"DNS handle error: {e}")

    def error_received(self, exc):
        log.error(f"DNS socket error: {exc}")

    def connection_lost(self, exc):
        pass


async def run_dns_proxy(
    listen_host: str, listen_port: int,
    socks_host: str,  socks_port: int,
    dns_host: str,    dns_port: int,
):
    loop = asyncio.get_running_loop()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSProxyProtocol(socks_host, socks_port, dns_host, dns_port, loop),
        local_addr=(listen_host, listen_port),
    )

    log.info(
        f"DNS proxy on {listen_host}:{listen_port} "
        f"→ {socks_host}:{socks_port} "
        f"→ {dns_host}:{dns_port}"
    )

    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phasora DNS Proxy")
    parser.add_argument("--listen",   default="127.0.0.1", help="Listen address")
    parser.add_argument("--port",     type=int, default=5353, help="UDP listen port")
    parser.add_argument("--socks",    default="127.0.0.1:1080", help="SOCKS5 host:port")
    parser.add_argument("--dns",      default=DEFAULT_DNS, help="Upstream DNS server (server side)")
    parser.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)
    args = parser.parse_args()

    socks_parts = args.socks.rsplit(":", 1)
    socks_host  = socks_parts[0]
    socks_port  = int(socks_parts[1]) if len(socks_parts) > 1 else 1080

    asyncio.run(run_dns_proxy(
        args.listen, args.port,
        socks_host,  socks_port,
        args.dns,    args.dns_port,
    ))
