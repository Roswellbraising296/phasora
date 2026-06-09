"""
Phasora - Menu v2
Interactive launcher — manages all components including xray-core

Author : Rushqp
Project: Phasora — github or local
"""

import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

WIN    = platform.system() == "Windows"
BASE   = Path(__file__).parent
CONFIG = BASE / "phasora.json"
PYTHON = sys.executable
XRAY   = BASE / ("xray.exe" if WIN else "xray")

if WIN:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )

C = {
    "cyan":   "\033[96m", "green":  "\033[92m",
    "yellow": "\033[93m", "red":    "\033[91m",
    "gray":   "\033[90m", "white":  "\033[97m",
    "bold":   "\033[1m",  "reset":  "\033[0m",
}

def c(color, text):
    return f"{C.get(color,'')}{text}{C['reset']}"

def clear():
    os.system("cls" if WIN else "clear")

# ── config ────────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    try:
        return json.loads(CONFIG.read_text("utf-8")) if CONFIG.exists() else {}
    except Exception:
        return {}

def save_cfg(cfg: dict):
    CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")

# ── process manager ───────────────────────────────────────────────────────────

_procs: dict[str, subprocess.Popen] = {}

def alive(name: str) -> bool:
    p = _procs.get(name)
    return p is not None and p.poll() is None

def dot(name: str) -> str:
    return c("green", "●") if alive(name) else c("gray", "○")

def kill(name: str):
    p = _procs.pop(name, None)
    if not p or p.poll() is not None:
        return
    try:
        p.send_signal(signal.CTRL_BREAK_EVENT) if WIN else p.terminate()
        p.wait(timeout=5)
    except Exception:
        p.kill()

def spawn(name: str, cmd: list[str]) -> subprocess.Popen:
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if WIN else 0,
    )
    _procs[name] = p
    _logs[name]  = LiveLog(p)
    return p

# ── live log ──────────────────────────────────────────────────────────────────

class LiveLog:
    def __init__(self, proc, max_lines=300):
        self.lines: list[str] = []
        self._t = threading.Thread(
            target=self._read, args=(proc,), daemon=True
        )
        self._t.start()

    def _read(self, proc):
        if proc.stdout:
            for line in proc.stdout:
                self.lines.append(line.rstrip())
                if len(self.lines) > 300:
                    self.lines.pop(0)

    def tail(self, n=20):
        return self.lines[-n:]

_logs: dict[str, LiveLog] = {}

# ── launchers ─────────────────────────────────────────────────────────────────

def start_relay(cfg: dict):
    if alive("relay"):
        return print(c("yellow", "  Relay is already running."))
    s = BASE / "relay.py"
    if not s.exists():
        return print(c("red", "  relay.py not found."))
    pt  = cfg.get("relay_port",     7070)
    sox = cfg.get("sox_bridge_port", 1081)
    p = spawn("relay", [PYTHON, str(s),
                        "--pt-port",  str(pt),
                        "--sox-port", str(sox)])
    print(c("green", f"  Relay started (PID {p.pid})  PT:{pt}  SOX:{sox}"))


def start_xray(cfg: dict):
    if alive("xray"):
        return print(c("yellow", "  xray is already running."))
    if not XRAY.exists():
        return print(c("red",
            f"  xray binary not found at {XRAY}\n"
            "  Run: python setup_relay.py"))
    xcfg = BASE / "xray_config.json"
    if not xcfg.exists():
        return print(c("red",
            "  xray_config.json not found.\n"
            "  Run: python setup_relay.py"))
    p = spawn("xray", [str(XRAY), "run", "-c", str(xcfg)])
    port = cfg.get("vless_port", 8443)
    print(c("green", f"  xray started (PID {p.pid})  VLESS port:{port}"))


def start_server(cfg: dict):
    if alive("server"):
        return print(c("yellow", "  Server is already running."))
    s = BASE / "server.py"
    if not s.exists():
        return print(c("red", "  server.py not found."))
    relay = cfg.get("relay_host", "")
    port  = cfg.get("relay_port", 7070)
    code  = cfg.get("code", "")
    key   = cfg.get("key", "")
    if not all([relay, code, key]):
        return print(c("red", "  Configure relay host, code and key first (s)."))
    p = spawn("server", [PYTHON, str(s),
                         "--relay", relay, "--port", str(port),
                         "--code", code, "--key", key])
    print(c("green", f"  Server started (PID {p.pid})"))


def start_client(cfg: dict, vpn: bool = False):
    key_name = "client_vpn" if vpn else "client"
    label    = "VPN" if vpn else "SOCKS5"
    if alive(key_name):
        return print(c("yellow", f"  Client ({label}) is already running."))
    s = BASE / "client.py"
    if not s.exists():
        return print(c("red", "  client.py not found."))
    relay = cfg.get("relay_host", "")
    port  = cfg.get("relay_port", 7070)
    code  = cfg.get("code", "")
    key   = cfg.get("key", "")
    if not all([relay, code, key]):
        return print(c("red", "  Configure relay host, code and key first (s)."))
    if vpn and not WIN:
        return print(c("red", "  VPN mode is Windows only."))
    cmd = [PYTHON, str(s),
           "--relay", relay, "--port", str(port),
           "--code", code, "--key", key]
    if vpn:
        cmd.append("--vpn")
    p = spawn(key_name, cmd)
    print(c("green", f"  Client ({label}) started (PID {p.pid})"))


def start_dns(cfg: dict):
    if alive("dns"):
        return print(c("yellow", "  DNS proxy is already running."))
    s = BASE / "dns_proxy.py"
    if not s.exists():
        return print(c("red", "  dns_proxy.py not found."))
    sp = cfg.get("socks_port", 1080)
    dp = cfg.get("dns_proxy_port", 5353)
    ds = cfg.get("dns_server", "1.1.1.1")
    p = spawn("dns", [PYTHON, str(s),
                      "--socks", f"127.0.0.1:{sp}",
                      "--port", str(dp),
                      "--dns", ds])
    print(c("green", f"  DNS proxy started (PID {p.pid})"))


def stop_all():
    for name in list(_procs.keys()):
        kill(name)
    print(c("green", "  All services stopped."))

# ── quick restart (the key feature) ──────────────────────────────────────────

def quick_restart(cfg: dict):
    """Stop everything and restart relay + xray + server in order."""
    print(c("yellow", "\n  Restarting all relay-side services...\n"))
    for name in ["relay", "xray", "server"]:
        kill(name)
        time.sleep(0.5)

    start_relay(cfg);  time.sleep(1.5)
    start_xray(cfg);   time.sleep(1.5)
    start_server(cfg); time.sleep(0.5)
    print(c("green", "\n  All relay services restarted."))

# ── UI helpers ────────────────────────────────────────────────────────────────

def header():
    print(c("cyan", c("bold", """
  ██████╗  ██╗  ██╗ █████╗  ███████╗ ██████╗  ██████╗   █████╗
  ██╔══██╗ ██║  ██║██╔══██╗ ██╔════╝██╔═══██╗ ██╔══██╗ ██╔══██╗
  ██████╔╝ ███████║███████║ ███████╗ ██║   ██║ ██████╔╝ ███████║
  ██╔═══╝  ██╔══██║██╔══██║ ╚════██║ ██║   ██║ ██╔══██╗ ██╔══██║
  ██║      ██║  ██║██║  ██║ ███████║ ╚██████╔╝ ██║  ██║ ██║  ██║
  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝""")))
    print(c("gray", "  ────────────────── Phasora v1  |  by Rushqp ──────────────────\n"))


def status_bar(cfg: dict):
    relay = cfg.get("relay_host") or c("yellow","not set")
    pt    = cfg.get("relay_port", 7070)
    sox   = cfg.get("sox_bridge_port", 1081)
    vless = cfg.get("vless_port", 8443)
    code  = cfg.get("code") or c("yellow","not set")
    key_s = "********" if cfg.get("key") else c("yellow","not set")

    print(f"  {c('gray','Host')} {relay}   "
          f"{c('gray','PT')} :{pt}   "
          f"{c('gray','VLESS')} :{vless}   "
          f"{c('gray','SOX')} :{sox}")
    print(f"  {c('gray','Code')} {code}   {c('gray','Key')} {key_s}\n")

    rows = [
        ("relay",      "Relay          (PT + SOCKS5 bridge)"),
        ("xray",       "xray-core      (VLESS → SOCKS5)"),
        ("server",     "Tunnel Server  (behind firewall)"),
        ("client",     "Client         (SOCKS5 proxy)"),
        ("client_vpn", "Client         (Full VPN)"),
        ("dns",        "DNS Proxy"),
    ]
    for name, label in rows:
        pid = f" pid={_procs[name].pid}" if alive(name) else ""
        print(f"  {dot(name)}  {label}{c('gray', pid)}")
    print()


def menu():
    sections = [
        ("─── Relay machine ─────────────────────", [
            ("1", "Start Relay"),
            ("2", "Start xray-core  (VLESS for iPhone)"),
            ("3", "Start Server     (behind firewall)"),
            ("r", "Quick restart    (relay + xray + server)"),
        ]),
        ("─── Client machine ────────────────────", [
            ("4", "Start Client     (SOCKS5 proxy)"),
            ("5", "Start Client     (Full VPN — Admin)"),
            ("6", "Start DNS Proxy"),
        ]),
        ("─── Manage ────────────────────────────", [
            ("7", "Stop a service"),
            ("8", "Stop all"),
            ("9", "View live logs"),
        ]),
        ("─── Setup / Info ───────────────────────", [
            ("s", "Connection settings"),
            ("i", "Show iPhone connection info"),
            ("t", "Test connection  (IP check via SOCKS5)"),
            ("u", "Run setup wizard (first time / re-setup)"),
            ("q", "Quit"),
        ]),
    ]
    for title, items in sections:
        print(c("gray", f"  {title}"))
        for k, label in items:
            print(f"    {c('cyan', f'[{k}]')}  {label}")
        print()


def stop_one_menu():
    names = {"1":"relay","2":"xray","3":"server",
             "4":"client","5":"client_vpn","6":"dns"}
    clear(); header()
    print(c("bold", "  ─── Stop a Service ───\n"))
    for k, n in names.items():
        print(f"    {c('cyan',f'[{k}]')} {dot(n)}  {n}")
    print()
    ch = input("  Choice: ").strip()
    if ch in names:
        kill(names[ch])
        print(c("green", f"  {names[ch]} stopped."))
    else:
        print(c("yellow", "  Invalid choice."))
    time.sleep(1)


def log_view():
    names = {"1":"relay","2":"xray","3":"server",
             "4":"client","5":"client_vpn","6":"dns"}
    clear(); header()
    print(c("bold", "  ─── Live Logs ───\n"))
    for k, n in names.items():
        print(f"    {c('cyan',f'[{k}]')} {dot(n)}  {n}")
    print()
    ch = input("  Choice (Enter to go back): ").strip()
    name = names.get(ch)
    if not name:
        return
    lv = _logs.get(name)
    if not lv:
        print(c("yellow","  No logs (service not started)."))
        input("\n  Press Enter...")
        return
    print(c("gray", f"\n  [{name}] — Ctrl+C to exit\n  {'─'*52}"))
    shown = 0
    try:
        for line in lv.tail(20):
            print(f"  {c('gray',line)}")
            shown += 1
        while True:
            new = lv.tail(300)
            for line in new[shown:]:
                print(f"  {line}")
            shown = len(new)
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass


def show_iphone_info():
    info_file = BASE / "iphone_connection.json"
    if not info_file.exists():
        print(c("yellow",
            "\n  iphone_connection.json not found.\n"
            "  Run the setup wizard first: press [u]"))
        return
    info = json.loads(info_file.read_text())
    print(c("bold", "\n  ─── iPhone / Shadowrocket connection ───\n"))
    print(f"  Host  : {info.get('relay_host')}")
    print(f"  Port  : {info.get('vless_port')}")
    print(f"  UUID  : {info.get('vless_uuid','(see xray_config.json)')}")
    print(f"  Net   : WebSocket  path=/phantom  TLS=off")
    print()
    link = info.get("vless_link","")
    if link:
        print(f"  VLESS link:\n  {c('yellow', link)}\n")
    print("  Steps:")
    for i, step in enumerate(info.get("shadowrocket_steps",[]), 1):
        print(f"    {i}. {step}")
    print()


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{c('gray',default)}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v if v else default


def settings_menu(cfg: dict) -> dict:
    clear(); header()
    print(c("bold","  ─── Connection Settings ───\n"))
    cfg["relay_host"]      = ask("Relay public host/IP", cfg.get("relay_host",""))
    cfg["relay_port"]      = int(ask("Phasora port",   str(cfg.get("relay_port",7070))))
    cfg["sox_bridge_port"] = int(ask("SOCKS5 bridge port",   str(cfg.get("sox_bridge_port",1081))))
    cfg["vless_port"]      = int(ask("VLESS port (iPhone)",  str(cfg.get("vless_port",8443))))
    cfg["code"]            = ask("Session code",             cfg.get("code",""))
    cfg["key"]             = ask("Passphrase",               cfg.get("key",""))
    cfg["dns_server"]      = ask("Upstream DNS server",      cfg.get("dns_server","1.1.1.1"))
    cfg["socks_port"]      = int(ask("Local SOCKS5 port",    str(cfg.get("socks_port",1080))))
    cfg["dns_proxy_port"]  = int(ask("Local DNS proxy port", str(cfg.get("dns_proxy_port",5353))))
    save_cfg(cfg)
    print(c("green","\n  Settings saved."))
    time.sleep(1)
    return cfg


def test_conn(cfg: dict):
    sp = cfg.get("socks_port",1080)
    print(c("gray",f"\n  Testing via SOCKS5 127.0.0.1:{sp} ...\n"))
    for url, label in [
        ("https://api.ipify.org",               "Public IP"),
        ("https://cloudflare.com/cdn-cgi/trace","Cloudflare trace"),
    ]:
        cmd = ["curl","-s","--max-time","8",
               "--socks5-hostname",f"127.0.0.1:{sp}", url]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                print(c("green",f"  {label}:"))
                print(c("white",f"    {r.stdout.strip()[:200]}"))
            else:
                print(c("red",f"  {label}: failed (exit {r.returncode})"))
        except FileNotFoundError:
            print(c("yellow","  curl not found."))
            break
        except subprocess.TimeoutExpired:
            print(c("red",f"  {label}: timeout"))
        print()

# ── main loop ─────────────────────────────────────────────────────────────────

def main():
    cfg = load_cfg()

    if not cfg.get("relay_host"):
        clear(); header()
        print(c("yellow","  First run — please configure settings.\n"))
        cfg = settings_menu(cfg)

    while True:
        # detect crashes
        for name in list(_procs.keys()):
            if _procs[name].poll() is not None:
                print(c("yellow", f"  ⚠  {name} crashed — press [r] to restart"))
                _procs.pop(name)

        clear(); header()
        status_bar(cfg)
        menu()

        try:
            ch = input(c("cyan","  Choice › ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            stop_all(); break

        if   ch == "1": start_relay(cfg);          input(c("gray","  Enter..."))
        elif ch == "2": start_xray(cfg);            input(c("gray","  Enter..."))
        elif ch == "3": start_server(cfg);          input(c("gray","  Enter..."))
        elif ch == "r": quick_restart(cfg);         input(c("gray","  Enter..."))
        elif ch == "4": start_client(cfg, False);   input(c("gray","  Enter..."))
        elif ch == "5": start_client(cfg, True);    input(c("gray","  Enter..."))
        elif ch == "6": start_dns(cfg);             input(c("gray","  Enter..."))
        elif ch == "7": stop_one_menu()
        elif ch == "8": stop_all()
        elif ch == "9": log_view()
        elif ch == "s": cfg = settings_menu(cfg)
        elif ch == "i": show_iphone_info();         input(c("gray","\n  Enter..."))
        elif ch == "t": test_conn(cfg);             input(c("gray","  Enter..."))
        elif ch == "u":
            subprocess.run([PYTHON, str(BASE/"setup_relay.py")])
            cfg = load_cfg()
            input(c("gray","  Enter..."))
        elif ch == "q":
            stop_all()
            print(c("cyan","\n  Goodbye!\n"))
            break
        else:
            print(c("yellow","  Invalid choice."))
            time.sleep(0.4)

if __name__ == "__main__":
    main()
