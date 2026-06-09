"""
Phasora - Relay Setup
Run once on the relay machine to install and configure everything

Author : Rushqp
Project: Phasora — github or local
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import uuid
import zipfile
from pathlib import Path

BASE = Path(__file__).parent
CONFIG_FILE  = BASE / "phasora.json"
XRAY_CONFIG  = BASE / "xray_config.json"
XRAY_BIN     = BASE / "xray"
LOGS_DIR     = BASE / "logs"

# ── helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str):
    print(f"\n\033[96m{'─'*60}\n  {msg}\n{'─'*60}\033[0m")

def ok(msg: str):
    print(f"  \033[92m✓\033[0m  {msg}")

def warn(msg: str):
    print(f"  \033[93m⚠\033[0m  {msg}")

def err(msg: str):
    print(f"  \033[91m✗\033[0m  {msg}")

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {prompt}{suffix}: ").strip()
    return val if val else default

def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)

# ── steps ─────────────────────────────────────────────────────────────────────

def step_deps():
    banner("Step 1 — Python dependencies")
    pkgs = ["cryptography"]
    for pkg in pkgs:
        r = run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=False)
        if r.returncode == 0:
            ok(f"{pkg} installed")
        else:
            warn(f"{pkg} may already be installed or failed — continuing")


def _xray_asset() -> tuple[str, str]:
    """Return (download_url, filename) for the current OS/arch."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if "aarch64" in machine or "arm64" in machine:
            arch = "arm64-v8a"
        elif "arm" in machine:
            arch = "arm32-v7a"
        else:
            arch = "64"
        filename = f"Xray-linux-{arch}.zip"
    elif system == "darwin":
        arch = "arm64-v8a" if "arm" in machine else "64"
        filename = f"Xray-macos-{arch}.zip"
    elif system == "windows":
        filename = "Xray-windows-64.zip"
    else:
        raise OSError(f"Unsupported OS: {system}")

    base_url = "https://github.com/XTLS/Xray-core/releases/latest/download"
    return f"{base_url}/{filename}", filename


def step_xray():
    banner("Step 2 — xray-core binary")

    xray_bin = XRAY_BIN if platform.system() != "Windows" else BASE / "xray.exe"
    if xray_bin.exists():
        ok(f"xray already present: {xray_bin}")
        return

    try:
        url, filename = _xray_asset()
        zip_path = BASE / filename
        print(f"  Downloading {url} ...")
        urllib.request.urlretrieve(url, zip_path)
        ok(f"Downloaded {filename}")

        with zipfile.ZipFile(zip_path, "r") as z:
            names = z.namelist()
            xray_name = next(
                (n for n in names if n.startswith("xray") and "." not in n.split("/")[-1]),
                None
            ) or next((n for n in names if "xray" in n), None)
            if not xray_name:
                raise FileNotFoundError("xray binary not found in zip")
            z.extract(xray_name, BASE)
            extracted = BASE / xray_name
            extracted.rename(xray_bin)

        zip_path.unlink(missing_ok=True)

        if platform.system() != "Windows":
            xray_bin.chmod(0o755)

        ok(f"xray installed: {xray_bin}")
    except Exception as e:
        err(f"Could not download xray: {e}")
        print("  Download manually from: https://github.com/XTLS/Xray-core/releases")
        print(f"  Extract to: {BASE}")


def step_config(relay_host: str, vless_port: int, vless_uuid: str, sox_port: int):
    banner("Step 3 — xray_config.json")

    LOGS_DIR.mkdir(exist_ok=True)

    cfg = {
        "log": {
            "loglevel": "warning",
            "access": str(LOGS_DIR / "xray_access.log"),
            "error":  str(LOGS_DIR / "xray_error.log"),
        },
        "inbounds": [
            {
                "tag": "vless-in",
                "port": vless_port,
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": vless_uuid,
                            "flow": ""
                        }
                    ],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": "/phantom"},
                },
            }
        ],
        "outbounds": [
            {
                "tag": "socks-out",
                "protocol": "socks",
                "settings": {
                    "servers": [{"address": "127.0.0.1", "port": sox_port}]
                },
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["vless-in"],
                    "outboundTag": "socks-out",
                }
            ]
        },
    }

    XRAY_CONFIG.write_text(json.dumps(cfg, indent=2))
    ok(f"xray_config.json written")


def step_vless_info(relay_host: str, vless_port: int, vless_uuid: str):
    banner("Step 4 — VLESS connection info (V2Box / Streisand / Shadowrocket)")

    from urllib.parse import quote
    params = f"type=ws&path=%2Fphantom&security=none&host={quote(relay_host)}"
    vless_link = f"vless://{vless_uuid}@{relay_host}:{vless_port}?{params}#Phasora"

    print(f"\n  VLESS link — works with V2Box, Streisand, Shadowrocket:\n")
    print(f"  \033[93m{vless_link}\033[0m\n")

    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(border=1)
        qr.add_data(vless_link)
        qr.make(fit=True)
        print("  Scan with your app:\n")
        qr.print_ascii(invert=True)
    except ImportError:
        print("  (Install qrcode for QR: pip install qrcode)")

    info = {
        "relay_host": relay_host,
        "vless_port": vless_port,
        "vless_uuid": vless_uuid,
        "vless_link": vless_link,
        "path":       "/phantom",
        "network":    "ws",
        "security":   "none",
        "apps": ["V2Box (free)", "Streisand (free)", "Shadowrocket (paid)"],
        "steps": [
            "Open V2Box or Streisand",
            "Tap + then Import from clipboard/URL",
            "Paste the vless:// link above",
            "Tap Save then Connect",
        ],
    }
    info_file = BASE / "iphone_connection.json"
    info_file.write_text(json.dumps(info, indent=2))
    ok(f"Connection info saved: {info_file}")


def step_phasora_config(relay_host: str, pt_port: int,
                               code: str, passphrase: str,
                               vless_port: int, sox_port: int):
    banner("Step 5 — phasora.json")

    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass

    cfg.update({
        "relay_host":     relay_host,
        "relay_port":     pt_port,
        "code":           code,
        "key":            passphrase,
        "vless_port":     vless_port,
        "sox_bridge_port": sox_port,
        "dns_server":     cfg.get("dns_server", "1.1.1.1"),
        "socks_port":     cfg.get("socks_port", 1080),
        "dns_proxy_port": cfg.get("dns_proxy_port", 5353),
    })
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    ok(f"phasora.json updated")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n\033[96m\033[1m")
    print("  ╔══════════════════════════════════════╗")
    print("  ║   Phasora — Relay Setup        ║")
    print("  ╚══════════════════════════════════════╝")
    print("\033[0m")
    print("  This script runs once to set up everything on the relay machine.\n")

    # load existing config defaults
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass

    relay_host = ask("Public IP or domain of this relay machine",
                     cfg.get("relay_host", ""))
    pt_port    = int(ask("Phasora port", str(cfg.get("relay_port", 7070))))
    vless_port = int(ask("VLESS port (for iPhone)",
                         str(cfg.get("vless_port", 8443))))
    sox_port   = int(ask("SOCKS5 bridge port (relay ↔ xray internal)",
                         str(cfg.get("sox_bridge_port", 1081))))
    code       = ask("Session code (same on server.py)", cfg.get("code", "MYCODE"))
    passphrase = ask("Passphrase (same on server.py)", cfg.get("key", ""))

    # generate or reuse UUID
    existing_uuid = cfg.get("vless_uuid") or str(uuid.uuid4())
    vless_uuid    = ask("VMess UUID (Enter to keep/generate)", existing_uuid)

    cfg["vless_uuid"] = vless_uuid
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

    step_deps()
    step_xray()
    step_config(relay_host, vless_port, vless_uuid, sox_port)
    step_vless_info(relay_host, vless_port, vless_uuid)
    step_phasora_config(relay_host, pt_port, code, passphrase, vless_port, sox_port)

    banner("All done!")
    print("  Start everything with:\n")
    print("    \033[92mpython menu.py\033[0m\n")
    print("  Or manually:\n")
    print(f"    python relay.py --pt-port {pt_port} --sox-port {sox_port}")
    print(f"    ./xray run -c xray_config.json")
    print(f"    python server.py --relay 127.0.0.1 --port {pt_port} --code {code} --key <passphrase>")
    print()


if __name__ == "__main__":
    main()
