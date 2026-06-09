"""
Phasora - Client Menu
منوی تعاملی برای ماشین کلاینت

شامل:
  - client.py  (SOCKS5 proxy یا VPN کامل)
  - dns_proxy.py (جلوگیری از DNS leak)
  - تست اتصال

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

# ── config ─────────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    try:
        return json.loads(CONFIG.read_text("utf-8")) if CONFIG.exists() else {}
    except Exception:
        return {}

def save_cfg(cfg: dict):
    CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")

# ── process manager ────────────────────────────────────────────────────────────

_procs: dict = {}
_logs:  dict = {}

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

def spawn(name: str, cmd: list) -> subprocess.Popen:
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if WIN else 0,
    )
    _procs[name] = p
    _logs[name]  = LiveLog(p)
    return p

# ── live log ───────────────────────────────────────────────────────────────────

class LiveLog:
    def __init__(self, proc):
        self.lines: list = []
        self._t = threading.Thread(target=self._read, args=(proc,), daemon=True)
        self._t.start()

    def _read(self, proc):
        if proc.stdout:
            for line in proc.stdout:
                self.lines.append(line.rstrip())
                if len(self.lines) > 300:
                    self.lines.pop(0)

    def tail(self, n=20):
        return self.lines[-n:]

# ── launchers ──────────────────────────────────────────────────────────────────

def start_client(cfg: dict, vpn: bool = False):
    key_name = "client_vpn" if vpn else "client"
    label    = "VPN" if vpn else "SOCKS5"

    if alive(key_name):
        return print(c("yellow", f"  Client ({label}) در حال اجراست."))

    s = BASE / "client.py"
    if not s.exists():
        return print(c("red", "  client.py پیدا نشد."))

    relay = cfg.get("relay_host", "")
    port  = cfg.get("relay_port", 7070)
    code  = cfg.get("code", "")
    key   = cfg.get("key", "")

    if not all([relay, code, key]):
        return print(c("red", "  ابتدا تنظیمات رو کامل کن (s)."))

    if vpn and not WIN:
        return print(c("red", "  VPN mode فقط روی ویندوز کار میکنه."))

    cmd = [PYTHON, str(s),
           "--relay", relay,
           "--port",  str(port),
           "--code",  code,
           "--key",   key]
    if vpn:
        cmd.append("--vpn")

    p = spawn(key_name, cmd)
    socks_port = cfg.get("socks_port", 1080)
    print(c("green",
        f"  Client ({label}) started  PID={p.pid}\n"
        f"  {'SOCKS5 proxy: 127.0.0.1:' + str(socks_port) if not vpn else 'VPN فعال — کل ترافیک از tunnel'}"))


def start_dns(cfg: dict):
    if alive("dns"):
        return print(c("yellow", "  DNS proxy در حال اجراست."))

    s = BASE / "dns_proxy.py"
    if not s.exists():
        return print(c("red", "  dns_proxy.py پیدا نشد."))

    sp = cfg.get("socks_port", 1080)
    dp = cfg.get("dns_proxy_port", 5353)
    ds = cfg.get("dns_server", "1.1.1.1")

    p = spawn("dns", [PYTHON, str(s),
                      "--socks", f"127.0.0.1:{sp}",
                      "--port",  str(dp),
                      "--dns",   ds])
    print(c("green",
        f"  DNS proxy started  PID={p.pid}\n"
        f"  UDP 127.0.0.1:{dp}  →  tunnel  →  {ds}"))


def stop_all():
    for name in list(_procs.keys()):
        kill(name)
    print(c("green", "  همه سرویس‌ها متوقف شدند."))


def quick_restart(cfg: dict):
    print(c("yellow", "\n  Restart...\n"))
    for name in ["client", "client_vpn", "dns"]:
        kill(name)
        time.sleep(0.4)
    start_client(cfg, vpn=False)
    time.sleep(1)
    start_dns(cfg)
    print(c("green", "\n  سرویس‌ها restart شدند."))

# ── UI ─────────────────────────────────────────────────────────────────────────

def header():
    print(c("cyan", c("bold", """
  ██████╗  ██╗  ██╗ █████╗  ███████╗ ██████╗  ██████╗   █████╗
  ██╔══██╗ ██║  ██║██╔══██╗ ██╔════╝██╔═══██╗ ██╔══██╗ ██╔══██╗
  ██████╔╝ ███████║███████║ ███████╗ ██║   ██║ ██████╔╝ ███████║
  ██╔═══╝  ██╔══██║██╔══██║ ╚════██║ ██║   ██║ ██╔══██╗ ██╔══██║
  ██║      ██║  ██║██║  ██║ ███████║ ╚██████╔╝ ██║  ██║ ██║  ██║
  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝""")))
    print(c("gray", "  ──────────────────── Client Menu ────────────────────────────\n"))


def status_bar(cfg: dict):
    relay     = cfg.get("relay_host") or c("yellow", "not set")
    pt        = cfg.get("relay_port", 7070)
    code      = cfg.get("code")       or c("yellow", "not set")
    key_s     = "********" if cfg.get("key") else c("yellow", "not set")
    socks_p   = cfg.get("socks_port", 1080)
    dns_p     = cfg.get("dns_proxy_port", 5353)

    print(f"  {c('gray','Relay')} {relay}:{pt}   "
          f"{c('gray','Code')} {code}   "
          f"{c('gray','Key')} {key_s}")
    print(f"  {c('gray','SOCKS5')} 127.0.0.1:{socks_p}   "
          f"{c('gray','DNS')} 127.0.0.1:{dns_p}\n")

    rows = [
        ("client",     "Client     (SOCKS5 proxy)"),
        ("client_vpn", "Client     (Full VPN — Windows)"),
        ("dns",        "DNS Proxy  (anti DNS leak)"),
    ]
    for name, label in rows:
        pid = f"  pid={_procs[name].pid}" if alive(name) else ""
        print(f"  {dot(name)}  {label}{c('gray', pid)}")
    print()


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{c('gray', default)}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v if v else default


def settings_menu(cfg: dict) -> dict:
    clear(); header()
    print(c("bold", "  ─── تنظیمات اتصال ───\n"))
    cfg["relay_host"]     = ask("آدرس relay (IP یا دامنه)", cfg.get("relay_host", ""))
    cfg["relay_port"]     = int(ask("پورت Phasora",          str(cfg.get("relay_port", 7070))))
    cfg["code"]           = ask("Session code",               cfg.get("code", ""))
    cfg["key"]            = ask("Passphrase",                 cfg.get("key", ""))
    cfg["socks_port"]     = int(ask("پورت SOCKS5 لوکال",     str(cfg.get("socks_port", 1080))))
    cfg["dns_proxy_port"] = int(ask("پورت DNS proxy لوکال",  str(cfg.get("dns_proxy_port", 5353))))
    cfg["dns_server"]     = ask("DNS server (سمت سرور)",     cfg.get("dns_server", "1.1.1.1"))
    save_cfg(cfg)
    print(c("green", "\n  تنظیمات ذخیره شد."))
    time.sleep(1)
    return cfg


def test_conn(cfg: dict):
    sp = cfg.get("socks_port", 1080)
    print(c("gray", f"\n  تست اتصال از طریق SOCKS5 127.0.0.1:{sp} ...\n"))
    for url, label in [
        ("https://api.ipify.org",                "IP عمومی"),
        ("https://cloudflare.com/cdn-cgi/trace", "Cloudflare trace"),
    ]:
        cmd = ["curl", "-s", "--max-time", "8",
               "--socks5-hostname", f"127.0.0.1:{sp}", url]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                print(c("green", f"  {label}:"))
                print(c("white", f"    {r.stdout.strip()[:200]}"))
            else:
                print(c("red", f"  {label}: ناموفق (exit {r.returncode})"))
        except FileNotFoundError:
            print(c("yellow", "  curl نصب نیست."))
            break
        except subprocess.TimeoutExpired:
            print(c("red", f"  {label}: timeout"))
        print()


def log_view():
    names = {"1": "client", "2": "client_vpn", "3": "dns"}
    clear(); header()
    print(c("bold", "  ─── Live Logs ───\n"))
    for k, n in names.items():
        print(f"    {c('cyan', f'[{k}]')} {dot(n)}  {n}")
    print()
    ch = input("  انتخاب (Enter برای برگشت): ").strip()
    name = names.get(ch)
    if not name:
        return
    lv = _logs.get(name)
    if not lv:
        print(c("yellow", "  سرویس شروع نشده."))
        input("\n  Enter...")
        return
    print(c("gray", f"\n  [{name}] — Ctrl+C برای برگشت\n  {'─'*52}"))
    shown = 0
    try:
        for line in lv.tail(20):
            print(f"  {c('gray', line)}")
            shown += 1
        while True:
            new = lv.tail(300)
            for line in new[shown:]:
                print(f"  {line}")
            shown = len(new)
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass


def menu_items():
    sections = [
        ("─── اتصال ──────────────────────────────", [
            ("1", "Start Client     (SOCKS5 proxy)"),
            ("2", "Start Client     (Full VPN — Admin/Windows)"),
            ("3", "Start DNS Proxy  (anti DNS leak)"),
            ("r", "Restart همه سرویس‌ها"),
        ]),
        ("─── مدیریت ─────────────────────────────", [
            ("4", "Stop Client"),
            ("5", "Stop DNS Proxy"),
            ("6", "Stop همه"),
        ]),
        ("─── ابزار ──────────────────────────────", [
            ("l", "Live logs"),
            ("t", "تست اتصال  (IP check)"),
            ("s", "تنظیمات"),
            ("q", "خروج"),
        ]),
    ]
    for title, items in sections:
        print(c("gray", f"  {title}"))
        for k, label in items:
            print(f"    {c('cyan', f'[{k}]')}  {label}")
        print()

# ── main loop ──────────────────────────────────────────────────────────────────

def main():
    cfg = load_cfg()

    if not cfg.get("relay_host"):
        clear(); header()
        print(c("yellow", "  اول باید تنظیمات رو وارد کنی.\n"))
        cfg = settings_menu(cfg)

    while True:
        # crash detection
        for name in list(_procs.keys()):
            if _procs[name].poll() is not None:
                print(c("yellow", f"  ⚠  {name} کرش کرد — [r] برای restart"))
                _procs.pop(name)

        clear(); header()
        status_bar(cfg)
        menu_items()

        try:
            ch = input(c("cyan", "  انتخاب › ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            stop_all(); break

        if   ch == "1": start_client(cfg, vpn=False); input(c("gray", "  Enter..."))
        elif ch == "2": start_client(cfg, vpn=True);  input(c("gray", "  Enter..."))
        elif ch == "3": start_dns(cfg);                input(c("gray", "  Enter..."))
        elif ch == "r": quick_restart(cfg);            input(c("gray", "  Enter..."))
        elif ch == "4":
            kill("client"); kill("client_vpn")
            print(c("green", "  Client متوقف شد."))
            input(c("gray", "  Enter..."))
        elif ch == "5":
            kill("dns")
            print(c("green", "  DNS proxy متوقف شد."))
            input(c("gray", "  Enter..."))
        elif ch == "6":
            stop_all()
            input(c("gray", "  Enter..."))
        elif ch == "l": log_view()
        elif ch == "t": test_conn(cfg); input(c("gray", "  Enter..."))
        elif ch == "s": cfg = settings_menu(cfg)
        elif ch == "q":
            stop_all()
            print(c("cyan", "\n  خداحافظ!\n"))
            break
        else:
            print(c("yellow", "  انتخاب نامعتبر."))
            time.sleep(0.4)

if __name__ == "__main__":
    main()
