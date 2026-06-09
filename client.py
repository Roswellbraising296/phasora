"""
Phasora - Client v6
SOCKS5 proxy mode + Full VPN mode (Windows/wintun)

Changes v6:
  - ECDH key exchange در handshake برای PFS
  - NonceCounter برای جلوگیری از nonce reuse
  - Token در handshake ارسال میشه
  - exponential backoff بهتر

Author : Rushqp
Project: Phasora — github or local
"""

import asyncio
import json
import logging
import struct
import uuid
import sys
import os
import subprocess
import ctypes

from crypto import (
    derive_key, derive_auth_key,
    make_handshake_token,
    ECDHSession, NonceCounter,
    encrypt, decrypt,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PHASORA-CLIENT] %(message)s")
log = logging.getLogger("client")

HEADER_SIZE         = 4
MAX_PKT             = 256 * 1024
LOCAL_PORT          = 1080
DNS_PROXY_PORT      = 5353
KEEPALIVE_INTERVAL  = 30
MAX_RECONNECT_DELAY = 30


async def read_msg(reader: asyncio.StreamReader):
    try:
        header = await reader.readexactly(HEADER_SIZE)
        length = struct.unpack(">I", header)[0]
        if length > MAX_PKT:
            return None
        return await reader.readexactly(length)
    except (asyncio.IncompleteReadError, ConnectionResetError,
            asyncio.CancelledError, OSError):
        return None


async def send_msg(writer: asyncio.StreamWriter, data: bytes):
    try:
        writer.write(struct.pack(">I", len(data)) + data)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


class MultiplexTunnel:
    def __init__(self, key: bytes, relay_reader, relay_writer,
                 nonce_counter: NonceCounter):
        self.key           = key
        self.relay_reader  = relay_reader
        self.relay_writer  = relay_writer
        self.relay_lock    = asyncio.Lock()
        self.nonce_counter = nonce_counter
        self.connections: dict = {}
        self.alive         = True
        self._last_pong    = asyncio.get_event_loop().time()

    async def send_packet(self, conn_id: str, ptype: int, data: bytes = b""):
        payload   = conn_id.encode() + bytes([ptype]) + data
        encrypted = encrypt(self.key, payload, self.nonce_counter)
        async with self.relay_lock:
            await send_msg(self.relay_writer, encrypted)

    async def _send_ping(self):
        async with self.relay_lock:
            try:
                self.relay_writer.write(struct.pack(">I", 4) + b"PING")
                await self.relay_writer.drain()
            except Exception:
                self.alive = False

    async def keepalive_loop(self):
        while self.alive:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if not self.alive:
                break
            await self._send_ping()
            if asyncio.get_event_loop().time() - self._last_pong > 90:
                log.warning("Keepalive timeout — relay not responding")
                self.alive = False
                break

    async def reader_loop(self):
        while self.alive:
            raw = await read_msg(self.relay_reader)
            if raw is None:
                log.info("Relay disconnected")
                self.alive = False
                for q in self.connections.values():
                    await q.put(None)
                break

            if raw == b"PING":
                async with self.relay_lock:
                    try:
                        self.relay_writer.write(struct.pack(">I", 4) + b"PONG")
                        await self.relay_writer.drain()
                    except Exception:
                        self.alive = False
                continue
            if raw == b"PONG":
                self._last_pong = asyncio.get_event_loop().time()
                continue

            try:
                decrypted = decrypt(self.key, raw)
                conn_id = decrypted[:36].decode()
                ptype   = decrypted[36]
                data    = decrypted[37:]
                if conn_id in self.connections:
                    await self.connections[conn_id].put((ptype, data))
            except Exception as e:
                log.warning(f"Decrypt error: {e}")

    async def open_connection(self, conn_id: str, host: str, port: int):
        q = asyncio.Queue()
        self.connections[conn_id] = q
        payload = json.dumps({"host": host, "port": port}).encode()
        await self.send_packet(conn_id, 1, payload)
        return q

    async def close_connection(self, conn_id: str):
        try:
            await self.send_packet(conn_id, 2)
        except Exception:
            pass
        self.connections.pop(conn_id, None)

    async def send_data(self, conn_id: str, data: bytes):
        await self.send_packet(conn_id, 0, data)


_current_tunnel: MultiplexTunnel | None = None


async def handle_local_connection(local_reader, local_writer):
    if _current_tunnel is None or not _current_tunnel.alive:
        local_writer.close()
        return

    tunnel  = _current_tunnel
    peer    = local_writer.get_extra_info("peername")
    conn_id = str(uuid.uuid4())

    try:
        # SOCKS5 handshake
        data = await asyncio.wait_for(local_reader.read(256), timeout=10)
        if not data or data[0] != 0x05:
            return
        local_writer.write(b'\x05\x00')
        await local_writer.drain()

        data = await asyncio.wait_for(local_reader.read(256), timeout=10)
        if len(data) < 7 or data[1] != 0x01:
            return

        atyp = data[3]
        if atyp == 0x01:
            host = ".".join(str(b) for b in data[4:8])
            port = struct.unpack(">H", data[8:10])[0]
        elif atyp == 0x03:
            dlen = data[4]
            host = data[5:5 + dlen].decode()
            port = struct.unpack(">H", data[5 + dlen:7 + dlen])[0]
        else:
            local_writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        log.info(f"[{conn_id[:8]}] {peer} → {host}:{port}")

        queue = await tunnel.open_connection(conn_id, host, port)
        resp  = await asyncio.wait_for(queue.get(), timeout=10)
        if resp is None or resp[0] == 2:
            local_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await local_writer.drain()
            return

        local_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await local_writer.drain()

        async def local_to_tunnel():
            while True:
                chunk = await local_reader.read(32768)
                if not chunk:
                    break
                await tunnel.send_data(conn_id, chunk)

        async def tunnel_to_local():
            while True:
                item = await queue.get()
                if item is None or item[0] == 2:
                    break
                _, d = item
                if d:
                    local_writer.write(d)
                    await local_writer.drain()

        await asyncio.gather(local_to_tunnel(), tunnel_to_local(),
                             return_exceptions=True)

    except asyncio.TimeoutError:
        log.warning(f"[{conn_id[:8]}] timeout")
    except Exception as e:
        log.error(f"[{conn_id[:8]}] {e}")
    finally:
        await tunnel.close_connection(conn_id)
        try:
            local_writer.close()
        except Exception:
            pass


# ── VPN mode (Windows only) ───────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def find_tool(name: str) -> str | None:
    base = os.path.dirname(os.path.abspath(__file__))
    for candidate in [
        os.path.join(base, name),
        os.path.join(base, "tools", name),
        name,
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


class WinVPN:
    TUN_IP   = "10.0.0.1"
    TUN_MASK = "255.255.255.0"
    TUN_GW   = "10.0.0.2"
    TUN_NAME = "Phasora"
    METRIC   = "5"

    def __init__(self, relay_host: str):
        self.relay_host            = relay_host
        self._tun2socks_proc       = None
        self._original_dns: list   = []
        self._original_gw: str     = ""
        self._adapter_name: str    = ""

    def _run(self, cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _get_default_gw(self) -> str:
        r = self._run(["powershell", "-NoProfile", "-Command",
                       "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                       "Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                      check=False)
        return r.stdout.strip()

    def _get_dns(self, iface: str) -> list:
        r = self._run(["powershell", "-NoProfile", "-Command",
                       f"(Get-DnsClientServerAddress -InterfaceAlias '{iface}' "
                       f"-AddressFamily IPv4).ServerAddresses -join ','"],
                      check=False)
        out = r.stdout.strip()
        return [x for x in out.split(",") if x] if out else []

    def _get_main_iface(self) -> str:
        r = self._run(["powershell", "-NoProfile", "-Command",
                       "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                       "Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"],
                      check=False)
        return r.stdout.strip()

    def start(self):
        if not is_admin():
            raise PermissionError("VPN mode requires Administrator privileges")

        tun2socks = find_tool("tun2socks.exe")
        if not tun2socks:
            raise FileNotFoundError(
                "tun2socks.exe not found.\n"
                "Download: https://github.com/xjasonlyu/tun2socks/releases\n"
                "Place next to client.py or inside tools/"
            )

        log.info("Starting VPN mode...")
        self._original_gw  = self._get_default_gw()
        main_iface         = self._get_main_iface()
        self._original_dns = self._get_dns(main_iface)

        cmd = [tun2socks,
               "-device",   f"tun://{self.TUN_NAME}",
               "-proxy",    f"socks5://127.0.0.1:{LOCAL_PORT}",
               "-loglevel", "info"]
        self._tun2socks_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

        import time
        for _ in range(20):
            time.sleep(0.5)
            r = self._run(["powershell", "-NoProfile", "-Command",
                           f"Get-NetAdapter -Name '{self.TUN_NAME}' "
                           f"-ErrorAction SilentlyContinue"], check=False)
            if self.TUN_NAME in r.stdout:
                break
        else:
            raise RuntimeError(f"Adapter '{self.TUN_NAME}' did not come up")

        self._adapter_name = self.TUN_NAME
        self._run(["netsh", "interface", "ip", "set", "address",
                   f"name={self._adapter_name}", "static",
                   self.TUN_IP, self.TUN_MASK, self.TUN_GW])

        if self._original_gw:
            self._run(["route", "add", self.relay_host,
                       "mask", "255.255.255.255",
                       self._original_gw, "metric", "1"], check=False)

        self._run(["route", "delete", "0.0.0.0", "mask", "0.0.0.0"], check=False)
        self._run(["route", "add",    "0.0.0.0", "mask", "0.0.0.0",
                   self.TUN_GW, "metric", self.METRIC])

        self._run(["powershell", "-NoProfile", "-Command",
                   f"Set-DnsClientServerAddress -InterfaceAlias '{main_iface}' "
                   f"-ServerAddresses ('127.0.0.1')"])

        log.info("VPN mode active")

    def stop(self):
        log.info("Stopping VPN mode...")
        self._run(["route", "delete", "0.0.0.0", "mask", "0.0.0.0"], check=False)
        if self._original_gw:
            self._run(["route", "add", "0.0.0.0", "mask", "0.0.0.0",
                       self._original_gw, "metric", "10"], check=False)
        self._run(["route", "delete", self.relay_host], check=False)

        main_iface = self._get_main_iface()
        if self._original_dns:
            dns_str = "','".join(self._original_dns)
            self._run(["powershell", "-NoProfile", "-Command",
                       f"Set-DnsClientServerAddress -InterfaceAlias '{main_iface}' "
                       f"-ServerAddresses ('{dns_str}')"], check=False)
        else:
            self._run(["powershell", "-NoProfile", "-Command",
                       f"Set-DnsClientServerAddress -InterfaceAlias '{main_iface}' "
                       f"-ResetServerAddresses"], check=False)

        if self._tun2socks_proc:
            try:
                self._tun2socks_proc.terminate()
                self._tun2socks_proc.wait(timeout=5)
            except Exception:
                self._tun2socks_proc.kill()
            self._tun2socks_proc = None

        log.info("VPN mode stopped — routing restored")


# ── relay connection ──────────────────────────────────────────────────────────

async def connect_to_relay(relay_host, relay_port, code, static_key, auth_key):
    global _current_tunnel
    reader, writer = await asyncio.open_connection(relay_host, relay_port)

    # ── ECDH key exchange ──────────────────────────────────────────────────────
    ecdh  = ECDHSession()
    token = make_handshake_token(auth_key, "client", code)

    await send_msg(writer, json.dumps({
        "role":     "client",
        "code":     code.upper(),
        "token":    token,
        "ecdh_pub": ecdh.public_bytes.hex(),
    }).encode())

    resp = await read_msg(reader)
    if not resp:
        raise ConnectionError("No response from relay")
    status = json.loads(resp)
    log.info(f"Relay: {status}")

    if status.get("status") == "error":
        raise ConnectionError(f"Relay rejected: {status.get('msg')}")

    if status.get("status") == "waiting":
        log.info("Waiting for server...")
        resp = await read_msg(reader)
        if not resp:
            raise ConnectionError("Relay disconnected while waiting")
        status = json.loads(resp)

    if status.get("status") != "connected":
        raise ConnectionError(f"Unexpected status: {status}")

    # ── Session key ────────────────────────────────────────────────────────────
    server_pub_hex = status.get("peer_ecdh_pub", "")
    if server_pub_hex:
        try:
            server_pub  = bytes.fromhex(server_pub_hex)
            session_key = ecdh.derive_session_key(server_pub)
            log.info("PFS active — using ephemeral session key")
        except Exception as e:
            log.warning(f"ECDH failed ({e}) — falling back to static key")
            session_key = static_key
    else:
        session_key = static_key
        log.warning("No ECDH from server — PFS disabled for this session")

    nonce_ctr = NonceCounter()
    log.info("Connected to server — tunnel ready")
    tunnel = MultiplexTunnel(session_key, reader, writer, nonce_ctr)
    _current_tunnel = tunnel
    asyncio.create_task(tunnel.reader_loop())
    asyncio.create_task(tunnel.keepalive_loop())
    return tunnel, writer


async def run_client(relay_host: str, relay_port: int, code: str,
                     passphrase: str, vpn_mode: bool = False):
    global _current_tunnel
    static_key = derive_key(passphrase)
    auth_key   = derive_auth_key(passphrase)
    log.info(f"Keys ready | code: {code} | mode: {'VPN' if vpn_mode else 'SOCKS5'}")

    win_vpn         = None
    reconnect_delay = 3

    local_server = await asyncio.start_server(
        handle_local_connection, "127.0.0.1", LOCAL_PORT
    )
    log.info(f"SOCKS5 proxy listening on 127.0.0.1:{LOCAL_PORT}")

    async with local_server:
        asyncio.create_task(local_server.serve_forever())

        if vpn_mode:
            dns_script = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "dns_proxy.py"
            )
            if os.path.isfile(dns_script):
                await asyncio.create_subprocess_exec(
                    sys.executable, dns_script,
                    "--socks", f"127.0.0.1:{LOCAL_PORT}",
                    "--port",  str(DNS_PROXY_PORT),
                )
                log.info(f"DNS proxy on 127.0.0.1:{DNS_PROXY_PORT}")

        while True:
            writer = None
            try:
                tunnel, writer = await connect_to_relay(
                    relay_host, relay_port, code, static_key, auth_key
                )
                reconnect_delay = 3

                if vpn_mode and win_vpn is None:
                    win_vpn = WinVPN(relay_host)
                    try:
                        win_vpn.start()
                    except Exception as e:
                        log.error(f"VPN setup error: {e}")
                        win_vpn = None

                while tunnel.alive:
                    await asyncio.sleep(0.5)

            except Exception as e:
                log.error(f"Error: {e}")
                _current_tunnel = None
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass

            log.info(f"Reconnecting in {reconnect_delay}s...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, MAX_RECONNECT_DELAY)


def main():
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Phasora Client v6")
    parser.add_argument("--relay", default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=7070)
    parser.add_argument("--code",  required=True)
    parser.add_argument("--key",   required=True)
    parser.add_argument("--vpn",   action="store_true")
    args = parser.parse_args()

    if args.vpn and sys.platform != "win32":
        print("VPN mode is only supported on Windows")
        sys.exit(1)

    if args.vpn and not is_admin():
        log.info("Requesting Administrator privileges...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

    loop = asyncio.new_event_loop()

    def _cleanup(s, f):
        log.info("Shutting down...")
        loop.stop()

    signal.signal(signal.SIGINT,  _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        loop.run_until_complete(
            run_client(args.relay, args.port, args.code, args.key, args.vpn)
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
