"""
Phasora - Relay v6
Dual-protocol relay: Phasora + VLESS/xray bridge

Changes v6:
  - Token verification فعال شد (قبلاً فقط parse میشد)
  - Rate limiting برای جلوگیری از DoS و brute-force
  - ECDH public key exchange در handshake
  - X25519 session key برای PFS
  - connection_made time tracking برای abuse detection

Author : Rushqp
Project: Phasora — github or local
"""

import asyncio
import json
import logging
import struct
import time
from collections import defaultdict
from typing import Dict, Optional

from crypto import (
    derive_auth_key, verify_handshake_token,
    ECDHSession, NonceCounter, encrypt, decrypt,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PHASORA-RELAY] %(message)s")
log = logging.getLogger("relay")

# ── config ────────────────────────────────────────────────────────────────────
PT_HOST   = "0.0.0.0"
PT_PORT   = 7070
SOX_HOST  = "127.0.0.1"
SOX_PORT  = 1081

MAX_PKT            = 256 * 1024
HEADER_SIZE        = 4
SESSION_TTL        = 300
KEEPALIVE_INTERVAL = 30
KEEPALIVE_TIMEOUT  = 90
MAX_SESSIONS       = 64

# Rate limiting — جلوگیری از DoS/brute-force
RATE_LIMIT_WINDOW  = 60    # seconds
RATE_LIMIT_MAX     = 10    # حداکثر connection در هر پنجره از یه IP
_rate_tracker: Dict[str, list] = defaultdict(list)  # ip -> [timestamps]

sessions: Dict[str, dict] = {}
sessions_lock = asyncio.Lock()

XRAY_SESSION_CODE = "XRAY"

# passphrase اینجا set میشه — از argparse میاد
_AUTH_KEY: bytes | None = None


# ── Rate Limiting ─────────────────────────────────────────────────────────────

def _check_rate_limit(ip: str) -> bool:
    """
    True = مجاز به اتصال
    False = بلاک (بیش از حد مجاز)
    """
    now = time.time()
    timestamps = _rate_tracker[ip]
    # پاک کردن timestamp های قدیمی
    _rate_tracker[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_tracker[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_tracker[ip].append(now)
    return True


# ── shared helpers ────────────────────────────────────────────────────────────

async def read_msg(reader: asyncio.StreamReader) -> Optional[bytes]:
    try:
        header = await asyncio.wait_for(
            reader.readexactly(HEADER_SIZE), timeout=KEEPALIVE_TIMEOUT
        )
        length = struct.unpack(">I", header)[0]
        if length > MAX_PKT:
            log.warning(f"Oversized packet dropped: {length} bytes")
            return None
        return await asyncio.wait_for(
            reader.readexactly(length), timeout=KEEPALIVE_TIMEOUT
        )
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            ConnectionResetError, OSError):
        return None


async def send_msg(writer: asyncio.StreamWriter, data: bytes) -> bool:
    try:
        writer.write(struct.pack(">I", len(data)) + data)
        await asyncio.wait_for(writer.drain(), timeout=10)
        return True
    except Exception:
        return False


async def pipe(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    label: str,
    stop: asyncio.Event,
):
    """Forward raw bytes from src to dst (no framing)."""
    try:
        while not stop.is_set():
            chunk = await asyncio.wait_for(src.read(32768), timeout=KEEPALIVE_TIMEOUT)
            if not chunk:
                break
            dst.write(chunk)
            await asyncio.wait_for(dst.drain(), timeout=10)
    except Exception:
        pass
    finally:
        log.info(f"{label}: pipe closed")
        stop.set()


async def relay_loop(
    src_reader: asyncio.StreamReader,
    dst_writer: asyncio.StreamWriter,
    label: str,
    stop: asyncio.Event,
):
    """Phasora framed relay — PING/PONG passthrough."""
    while not stop.is_set():
        data = await read_msg(src_reader)
        if data is None:
            log.info(f"{label}: disconnected")
            stop.set()
            break
        if data == b"PING":
            # PING رو مستقیم به طرف مقابل forward میکنیم
            if not await send_msg(dst_writer, b"PING"):
                stop.set()
            continue
        if not await send_msg(dst_writer, data):
            log.info(f"{label}: send failed")
            stop.set()
            break


async def keepalive_loop(
    writer: asyncio.StreamWriter,
    stop: asyncio.Event,
    label: str,
):
    while not stop.is_set():
        await asyncio.sleep(KEEPALIVE_INTERVAL)
        if stop.is_set():
            break
        if not await send_msg(writer, b"PING"):
            log.info(f"{label}: keepalive failed")
            stop.set()


# ── session pool ───────────────────────────────────────────────────────────────

async def _get_or_create_session(code: str) -> dict:
    now = time.time()
    expired = [k for k, v in sessions.items() if now - v["created"] > SESSION_TTL]
    for k in expired:
        sessions.pop(k, None)
        log.info(f"Session expired: code={k}")
    if code not in sessions:
        sessions[code] = {
            "server": None, "server_reader": None,
            "client": None, "client_reader": None,
            "created": now,
        }
    return sessions[code]


# ── Phasora protocol handler (port 7070) ──────────────────────────────────────

async def handle_pt_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    peer    = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "unknown"
    my_code = None
    my_role = None
    log.info(f"[PT] New connection: {peer}")

    # ── Rate limiting ──────────────────────────────────────────────────────────
    if not _check_rate_limit(peer_ip):
        log.warning(f"[PT] {peer_ip}: rate limit exceeded — dropping")
        await send_msg(writer, b'{"status":"error","msg":"rate limited"}')
        writer.close()
        return

    try:
        raw = await asyncio.wait_for(read_msg(reader), timeout=30)
        if not raw:
            return

        # ── Handshake parse ────────────────────────────────────────────────────
        try:
            hs   = json.loads(raw.decode())
            role = hs["role"]
            code = hs["code"].strip().upper()
            token = hs.get("token", "")
            assert role in ("server", "client")
            assert 4 <= len(code) <= 32
        except Exception:
            log.warning(f"[PT] {peer}: invalid handshake structure")
            await send_msg(writer, b'{"status":"error","msg":"invalid handshake"}')
            return

        # ── Token verification ─────────────────────────────────────────────────
        # این بخش قبلاً وجود نداشت — هر کسی با code درست میتونست وصل بشه
        if _AUTH_KEY is not None:
            if not token:
                log.warning(f"[PT] {peer}: missing token")
                await send_msg(writer, b'{"status":"error","msg":"auth required"}')
                return
            if not verify_handshake_token(_AUTH_KEY, role, code, token):
                log.warning(f"[PT] {peer}: invalid token — possible brute-force from {peer_ip}")
                await send_msg(writer, b'{"status":"error","msg":"auth failed"}')
                return
            log.info(f"[PT] {peer}: token verified OK")

        # ── ECDH key exchange ──────────────────────────────────────────────────
        # public key طرف مقابل رو دریافت میکنیم
        peer_pub_hex = hs.get("ecdh_pub", "")
        if peer_pub_hex:
            try:
                peer_pub_bytes = bytes.fromhex(peer_pub_hex)
                assert len(peer_pub_bytes) == 32
            except Exception:
                log.warning(f"[PT] {peer}: invalid ECDH public key")
                await send_msg(writer, b'{"status":"error","msg":"invalid ecdh key"}')
                return
        else:
            peer_pub_bytes = None

        my_code = code
        my_role = role

        async with sessions_lock:
            if len(sessions) >= MAX_SESSIONS:
                await send_msg(writer, b'{"status":"error","msg":"server full"}')
                return
            session = await _get_or_create_session(code)
            if session[role] is not None:
                await send_msg(writer, b'{"status":"error","msg":"role already connected"}')
                return
            session[role] = writer
            session[f"{role}_reader"] = reader
            # public key رو برای بعد نگه میداریم
            if peer_pub_bytes:
                session[f"{role}_ecdh_pub"] = peer_pub_bytes

        # relay ecdh pub خودش رو نداره — فقط forward میکنه
        # session key بین server و client negotiate میشه
        await send_msg(writer, json.dumps({"status": "waiting", "role": role}).encode())
        log.info(f"[PT] code={code} | {role} connected — waiting for peer")

        other_role = "client" if role == "server" else "server"
        deadline   = time.time() + SESSION_TTL

        while True:
            if time.time() > deadline:
                log.info(f"[PT] code={code}: timeout waiting for {other_role}")
                return
            async with sessions_lock:
                other_writer = session.get(other_role)
                other_reader = session.get(f"{other_role}_reader")
            if other_writer is not None:
                break
            await asyncio.sleep(0.3)

        if role == "server":
            log.info(f"[PT] code={code}: both sides connected — starting relay")
            await send_msg(writer,       json.dumps({"status": "connected"}).encode())
            await send_msg(other_writer, json.dumps({"status": "connected"}).encode())

            stop = asyncio.Event()
            await asyncio.gather(
                relay_loop(reader,       other_writer, f"[{code[:6]}] srv→cli", stop),
                relay_loop(other_reader, writer,       f"[{code[:6]}] cli→srv", stop),
                keepalive_loop(writer,       stop, f"[{code[:6]}] ka-srv"),
                keepalive_loop(other_writer, stop, f"[{code[:6]}] ka-cli"),
                return_exceptions=True,
            )
            log.info(f"[PT] code={code}: relay ended")
        else:
            while True:
                async with sessions_lock:
                    if session.get("server") is None:
                        break
                await asyncio.sleep(1)

    except asyncio.TimeoutError:
        log.warning(f"[PT] {peer}: handshake timeout")
    except Exception as e:
        log.error(f"[PT] {peer}: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass
        if my_code and my_role:
            async with sessions_lock:
                s = sessions.get(my_code)
                if s:
                    if s.get(my_role) is writer:
                        s[my_role] = None
                        s[f"{my_role}_reader"] = None
                    if s["server"] is None and s["client"] is None:
                        sessions.pop(my_code, None)
                        log.info(f"[PT] code={my_code}: session cleaned up")


# ── SOCKS5 bridge handler (port 1081) ─────────────────────────────────────────

async def _socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> "tuple[str, int] | None":
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=10)
        if not data or data[0] != 0x05:
            return None
        writer.write(b'\x05\x00')
        await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=10)
        if len(data) < 7 or data[1] != 0x01:
            return None

        atyp = data[3]
        if atyp == 0x01:
            host = ".".join(str(b) for b in data[4:8])
            port = struct.unpack(">H", data[8:10])[0]
        elif atyp == 0x03:
            dlen = data[4]
            host = data[5:5 + dlen].decode()
            port = struct.unpack(">H", data[5 + dlen:7 + dlen])[0]
        elif atyp == 0x04:
            import socket
            host = socket.inet_ntop(socket.AF_INET6, data[4:20])
            port = struct.unpack(">H", data[20:22])[0]
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return None

        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()
        return host, port
    except Exception as e:
        log.warning(f"[SOX] SOCKS5 handshake error: {e}")
        return None


async def handle_socks_bridge(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    peer = writer.get_extra_info("peername")
    log.info(f"[SOX] xray connection: {peer}")

    result = await _socks5_handshake(reader, writer)
    if result is None:
        writer.close()
        return

    dst_host, dst_port = result
    log.info(f"[SOX] → {dst_host}:{dst_port}")

    deadline = time.time() + SESSION_TTL
    while True:
        if time.time() > deadline:
            log.warning(f"[SOX] No server connected for code={XRAY_SESSION_CODE}")
            writer.close()
            return
        async with sessions_lock:
            session = sessions.get(XRAY_SESSION_CODE)
            if session and session.get("server") is not None:
                break
        await asyncio.sleep(0.5)

    import uuid
    sub_code = f"XR_{uuid.uuid4().hex[:8].upper()}"

    async with sessions_lock:
        sessions[sub_code] = {
            "server": None, "server_reader": None,
            "client": writer, "client_reader": reader,
            "created": time.time(),
            "_xray": True,
        }

    try:
        srv_reader, srv_conn = await asyncio.open_connection("127.0.0.1", PT_PORT)
    except Exception as e:
        log.error(f"[SOX] Cannot connect to PT port: {e}")
        writer.close()
        return

    hs = json.dumps({"role": "client", "code": sub_code}).encode()
    srv_conn.write(struct.pack(">I", len(hs)) + hs)
    await srv_conn.drain()

    try:
        _r = await asyncio.wait_for(srv_conn.readexactly(4), timeout=10)
        _l = struct.unpack(">I", _r)[0]
        _m = await asyncio.wait_for(srv_conn.readexactly(_l), timeout=10)
        log.info(f"[SOX] Internal PT handshake: {_m.decode()}")
    except Exception as e:
        log.warning(f"[SOX] Internal handshake failed: {e}")
        writer.close()
        srv_conn.close()
        return

    stop = asyncio.Event()
    await asyncio.gather(
        pipe(reader,     srv_conn, f"[{sub_code}] iphone→pt", stop),
        pipe(srv_reader, writer,   f"[{sub_code}] pt→iphone", stop),
        return_exceptions=True,
    )

    try:
        writer.close()
    except Exception:
        pass
    try:
        srv_conn.close()
    except Exception:
        pass
    async with sessions_lock:
        sessions.pop(sub_code, None)
    log.info(f"[SOX] {sub_code}: connection closed")


# ── entry point ───────────────────────────────────────────────────────────────

async def main():
    global _AUTH_KEY, PT_PORT, SOX_PORT

    import argparse
    parser = argparse.ArgumentParser(description="Phasora Relay v6")
    parser.add_argument("--pt-port",   type=int, default=PT_PORT)
    parser.add_argument("--sox-port",  type=int, default=SOX_PORT)
    parser.add_argument("--xray-code", default=XRAY_SESSION_CODE)
    parser.add_argument("--key",       default="",
                        help="Passphrase — اگر داده بشه token تأیید میشه")
    args = parser.parse_args()

    PT_PORT  = args.pt_port
    SOX_PORT = args.sox_port

    if args.key:
        from crypto import derive_auth_key
        _AUTH_KEY = derive_auth_key(args.key)
        log.info("Auth mode: token verification ENABLED")
    else:
        log.warning("Auth mode: DISABLED — توصیه میشه --key بدی")

    pt_server  = await asyncio.start_server(handle_pt_connection, PT_HOST,  args.pt_port)
    sox_server = await asyncio.start_server(handle_socks_bridge,  SOX_HOST, args.sox_port)

    log.info(f"Phasora Relay v6 started")
    log.info(f"  [PT]  {PT_HOST}:{args.pt_port}  — Phasora clients")
    log.info(f"  [SOX] {SOX_HOST}:{args.sox_port} — xray-core SOCKS5 bridge")
    log.info(f"  xray session code: {args.xray_code}")
    log.info(f"  Rate limit: {RATE_LIMIT_MAX} conn/{RATE_LIMIT_WINDOW}s per IP")
    log.info(f"  Keepalive {KEEPALIVE_INTERVAL}s | timeout {KEEPALIVE_TIMEOUT}s")

    async with pt_server, sox_server:
        await asyncio.gather(
            pt_server.serve_forever(),
            sox_server.serve_forever(),
        )


if __name__ == "__main__":
    asyncio.run(main())
