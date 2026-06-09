"""
Phasora - Server v4
Runs behind a firewall — connects outbound to the relay

Changes v4:
  - ECDH key exchange در handshake برای PFS
  - NonceCounter برای جلوگیری از nonce reuse
  - Token verification پاس میشه (از crypto)
  - بهبود reconnect با exponential backoff

Author : Rushqp
Project: Phasora — github or local
"""

import asyncio
import json
import logging
import struct
from crypto import (
    derive_key, derive_auth_key,
    make_handshake_token,
    ECDHSession, NonceCounter,
    encrypt, decrypt,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PHASORA-SERVER] %(message)s")
log = logging.getLogger("server")

HEADER_SIZE       = 4
MAX_PKT           = 256 * 1024
MAX_RECONNECT_DELAY = 60  # seconds


async def read_msg(reader):
    try:
        header = await reader.readexactly(HEADER_SIZE)
        length = struct.unpack(">I", header)[0]
        if length > MAX_PKT:
            return None
        return await reader.readexactly(length)
    except (asyncio.IncompleteReadError, ConnectionResetError,
            asyncio.CancelledError, OSError):
        return None


async def send_msg(writer, data: bytes):
    try:
        writer.write(struct.pack(">I", len(data)) + data)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


class ConnectionManager:
    def __init__(self, key: bytes, relay_writer, nonce_counter: NonceCounter):
        self.key           = key
        self.relay_writer  = relay_writer
        self.relay_lock    = asyncio.Lock()
        self.connections: dict = {}
        self.nonce_counter = nonce_counter

    async def send_packet(self, conn_id: str, ptype: int, data: bytes = b""):
        payload   = conn_id.encode() + bytes([ptype]) + data
        encrypted = encrypt(self.key, payload, self.nonce_counter)
        async with self.relay_lock:
            await send_msg(self.relay_writer, encrypted)

    async def handle_new_connection(self, conn_id: str, host: str, port: int):
        log.info(f"[{conn_id[:8]}] → {host}:{port}")
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            self.connections[conn_id] = (r, w)
            await self.send_packet(conn_id, 1)  # connected
            asyncio.create_task(self.target_to_client(conn_id, r))
        except Exception as e:
            log.warning(f"[{conn_id[:8]}] connect failed: {e}")
            await self.send_packet(conn_id, 2)  # error

    async def target_to_client(self, conn_id: str, reader):
        try:
            while True:
                chunk = await reader.read(32768)
                if not chunk:
                    break
                await self.send_packet(conn_id, 0, chunk)
        except Exception:
            pass
        finally:
            await self.send_packet(conn_id, 2)
            self.connections.pop(conn_id, None)
            log.info(f"[{conn_id[:8]}] closed")

    async def handle_data(self, conn_id: str, data: bytes):
        if conn_id not in self.connections:
            return
        _, w = self.connections[conn_id]
        try:
            w.write(data)
            await w.drain()
        except Exception:
            self.connections.pop(conn_id, None)

    async def close_connection(self, conn_id: str):
        if conn_id in self.connections:
            _, w = self.connections.pop(conn_id)
            try:
                w.close()
            except Exception:
                pass


async def run_server(relay_host: str, relay_port: int, code: str, passphrase: str):
    static_key = derive_key(passphrase)
    auth_key   = derive_auth_key(passphrase)
    log.info(f"Keys ready | code: {code}")

    reconnect_delay = 5

    while True:
        writer = None
        try:
            log.info(f"Connecting to relay: {relay_host}:{relay_port}")
            reader, writer = await asyncio.open_connection(relay_host, relay_port)

            # ── ECDH key exchange ──────────────────────────────────────────────
            # یه ephemeral key pair میسازیم
            ecdh = ECDHSession()
            token = make_handshake_token(auth_key, "server", code)

            await send_msg(writer, json.dumps({
                "role":     "server",
                "code":     code.upper(),
                "token":    token,
                "ecdh_pub": ecdh.public_bytes.hex(),   # 32 bytes hex
            }).encode())

            resp = await read_msg(reader)
            if not resp:
                raise ConnectionError("No response from relay")
            status = json.loads(resp)
            log.info(f"Relay: {status}")

            if status.get("status") == "error":
                log.error(f"Relay rejected: {status.get('msg')}")
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, MAX_RECONNECT_DELAY)
                continue

            if status.get("status") == "waiting":
                log.info("Waiting for client...")
                resp = await read_msg(reader)
                if not resp:
                    raise ConnectionError("Relay disconnected while waiting")
                status = json.loads(resp)

            if status.get("status") != "connected":
                raise ConnectionError(f"Unexpected status: {status}")

            # ── Session key ────────────────────────────────────────────────────
            # اگر client ecdh pub فرستاد، session key رو derive میکنیم
            # وگرنه از static key استفاده میکنیم (backward compat)
            client_pub_hex = status.get("peer_ecdh_pub", "")
            if client_pub_hex:
                try:
                    client_pub = bytes.fromhex(client_pub_hex)
                    session_key = ecdh.derive_session_key(client_pub)
                    log.info("PFS active — using ephemeral session key")
                except Exception as e:
                    log.warning(f"ECDH failed ({e}) — falling back to static key")
                    session_key = static_key
            else:
                session_key = static_key
                log.warning("No ECDH from client — PFS disabled for this session")

            nonce_ctr = NonceCounter()
            reconnect_delay = 5  # reset after successful connect

            log.info("Client connected — ready")
            mgr = ConnectionManager(session_key, writer, nonce_ctr)

            while True:
                raw = await read_msg(reader)
                if raw is None:
                    log.info("Relay disconnected")
                    break

                if raw == b"PING":
                    await send_msg(writer, b"PONG")
                    continue
                if raw == b"PONG":
                    continue

                try:
                    decrypted = decrypt(session_key, raw)
                    conn_id = decrypted[:36].decode()
                    ptype   = decrypted[36]
                    data    = decrypted[37:]
                except Exception as e:
                    log.warning(f"Decrypt error: {e}")
                    continue

                if ptype == 1:
                    req = json.loads(data)
                    asyncio.create_task(
                        mgr.handle_new_connection(conn_id, req["host"], req["port"])
                    )
                elif ptype == 0:
                    await mgr.handle_data(conn_id, data)
                elif ptype == 2:
                    await mgr.close_connection(conn_id)

        except Exception as e:
            log.error(f"Error: {e}")
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass

        log.info(f"Reconnecting in {reconnect_delay}s...")
        await asyncio.sleep(reconnect_delay)
        reconnect_delay = min(reconnect_delay * 2, MAX_RECONNECT_DELAY)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Phasora Server v4")
    parser.add_argument("--relay", default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=7070)
    parser.add_argument("--code",  required=True)
    parser.add_argument("--key",   required=True)
    args = parser.parse_args()
    asyncio.run(run_server(args.relay, args.port, args.code, args.key))
