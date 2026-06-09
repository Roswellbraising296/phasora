"""
Phasora - Server Menu
منوی تعاملی برای ماشین پشت فایروال

فقط شامل:
  - server.py (tunnel به relay)

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

# ── launcher ───────────────────────────────────────────────────────────────────

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
        return print(c("red", "  ابتدا تنظیمات رو کامل کن (s)."))
    p = spawn("server", [PYTHON, str(s),
                         "--relay", relay,
                         "--port",  str(port),
                         "--code",  code,
                         "--key",   key])
    print(c("green", f"  Server started  PID={p.pid}  →  {relay}:{port}"))

def stop_all():
    for name in list(_procs.keys()):
        kill(name)
    print(c("green", "  همه سرویس‌ها متوقف شدند."))

# ── UI ─────────────────────────────────────────────────────────────────────────

def header():
    print(c("cyan", c("bold", """
  ██████╗  ██╗  ██╗ █████╗  ███████╗ ██████╗  ██████╗   █████╗
  ██╔══██╗ ██║  ██║██╔══██╗ ██╔════╝██╔═══██╗ ██╔══██╗ ██╔══██╗
  ██████╔╝ ███████║███████║ ███████╗ ██║   ██║ ██████╔╝ ███████║
  ██╔═══╝  ██╔══██║██╔══██║ ╚════██║ ██║   ██║ ██╔══██╗ ██╔══██║
  ██║      ██║  ██║██║  ██║ ███████║ ╚██████╔╝ ██║  ██║ ██║  ██║
  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝""")))
    print(c("gray", "  ─────────────── Server Menu  |  Behind Firewall ───────────────\n"))

def status_bar(cfg: dict):
    relay = cfg.get("relay_host") or c("yellow", "not set")
    pt    = cfg.get("relay_port", 7070)
    code  = cfg.get("code")       or c("yellow", "not set")
    key_s = "********" if cfg.get("key") else c("yellow", "not set")

    print(f"  {c('gray','Relay')} {relay}:{pt}   "
          f"{c('gray','Code')} {code}   "
          f"{c('gray','Key')} {key_s}\n")

    print(f"  {dot('server')}  Server  (tunnel → relay)")
    print()

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{c('gray', default)}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v if v else default

def settings_menu(cfg: dict) -> dict:
    clear(); header()
    print(c("bold", "  ─── تنظیمات اتصال ───\n"))
    cfg["relay_host"] = ask("آدرس relay (IP یا دامنه)", cfg.get("relay_host", ""))
    cfg["relay_port"] = int(ask("پورت Phasora", str(cfg.get("relay_port", 7070))))
    cfg["code"]       = ask("Session code", cfg.get("code", ""))
    cfg["key"]        = ask("Passphrase", cfg.get("key", ""))
    save_cfg(cfg)
    print(c("green", "\n  تنظیمات ذخیره شد."))
    time.sleep(1)
    return cfg

def log_view():
    clear(); header()
    print(c("bold", "  ─── Live Logs — Server ───\n"))
    lv = _logs.get("server")
    if not lv:
        print(c("yellow", "  سرویس هنوز شروع نشده."))
        input("\n  Enter...")
        return
    print(c("gray", "  Ctrl+C برای برگشت\n  " + "─" * 52))
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
        ("─── سرویس ─────────────────────────────", [
            ("1", "Start Server     (اتصال به relay)"),
            ("2", "Stop Server"),
            ("r", "Restart Server"),
        ]),
        ("─── مدیریت ─────────────────────────────", [
            ("l", "Live logs"),
            ("s", "تنظیمات اتصال"),
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

        if ch == "1":
            start_server(cfg)
            input(c("gray", "  Enter..."))
        elif ch == "2":
            kill("server")
            print(c("green", "  Server متوقف شد."))
            input(c("gray", "  Enter..."))
        elif ch == "r":
            kill("server")
            time.sleep(0.8)
            start_server(cfg)
            input(c("gray", "  Enter..."))
        elif ch == "l":
            log_view()
        elif ch == "s":
            cfg = settings_menu(cfg)
        elif ch == "q":
            stop_all()
            print(c("cyan", "\n  خداحافظ!\n"))
            break
        else:
            print(c("yellow", "  انتخاب نامعتبر."))
            time.sleep(0.4)

if __name__ == "__main__":
    main()
