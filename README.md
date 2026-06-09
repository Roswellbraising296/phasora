<div align="center">

```
██████╗  ██╗  ██╗ █████╗  ███████╗ ██████╗  ██████╗   █████╗
██╔══██╗ ██║  ██║██╔══██╗ ██╔════╝██╔═══██╗ ██╔══██╗ ██╔══██╗
██████╔╝ ███████║███████║ ███████╗ ██║   ██║ ██████╔╝ ███████║
██╔═══╝  ██╔══██║██╔══██║ ╚════██║ ██║   ██║ ██╔══██╗ ██╔══██║
██║      ██║  ██║██║  ██║ ███████║ ╚██████╔╝ ██║  ██║ ██║  ██║
╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Phasora** — Encrypted tunnel through any firewall · SOCKS5 + iPhone VLESS

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20%2B%20X25519-purple?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)]()

[🇬🇧 English](#english) · [🇮🇷 فارسی](#فارسی)

</div>

---

<a name="english"></a>

## What is Phasora?

Phasora is a self-hosted encrypted tunnel that lets a machine **behind a firewall** expose a SOCKS5 proxy to the outside — no inbound ports, no port forwarding needed. A VPS in the middle acts as the relay. iPhones connect via VLESS/WebSocket through xray-core.

```
[Server — behind firewall] ──outbound──► [Relay VPS] ◄──── [Client / Laptop]
                                              │
                                       [iPhone via VLESS]
```

---

## Security

| Layer | Detail |
|-------|--------|
| **AES-256-GCM** | Authenticated encryption on all tunnel traffic |
| **X25519 ECDH** | Perfect Forward Secrecy — new ephemeral key every session |
| **HKDF-SHA256** | Session key derived from ECDH shared secret |
| **PBKDF2-SHA256** | 600,000 iterations — brute-force resistant |
| **HMAC-SHA256 token** | Handshake auth with ±1 minute time window |
| **Monotonic nonce** | Prevents nonce reuse in AES-GCM |
| **Packet padding** | Random padding mitigates traffic fingerprinting |
| **Rate limiting** | Max 10 connections / IP / 60 seconds |

---

## File Structure

```
phasora/
├── crypto.py           ← Crypto core (shared by all components)
├── relay.py            ← Relay server — runs on VPS
├── server.py           ← Runs behind firewall, connects outbound
├── client.py           ← SOCKS5 proxy + full VPN mode (Windows)
├── dns_proxy.py        ← DNS-over-SOCKS5, prevents DNS leaks
├── setup_relay.py      ← One-time setup wizard (run first)
├── xray_config.json    ← xray-core config for iPhone VLESS
├── menu.py             ← Full launcher (relay machine)
├── menu_server.py      ← Launcher (firewall machine)
└── menu_client.py      ← Launcher (client machine)
```

---

## Quick Start

### 1 — Install dependency

```bash
pip install cryptography
```

### 2 — Setup relay (run once on your VPS)

```bash
python setup_relay.py
```

Downloads xray-core, generates config, prints your iPhone VLESS link.

### 3 — Start relay services

```bash
python menu.py
# press [r] — quick restart: relay + xray + server
```

### 4 — Start on firewall machine

```bash
python menu_server.py
# press [1]
```

### 5 — Connect from client

```bash
python menu_client.py
# press [1] for SOCKS5   or   [2] for full VPN (Windows Admin)
```

Set your browser/system proxy to `127.0.0.1:1080`.

### iPhone

Scan the QR code printed by `setup_relay.py` in **V2Box** or **Streisand** (free apps on App Store).

---

## Configuration — phasora.json

| Key | Default | Description |
|-----|---------|-------------|
| `relay_host` | — | Public IP or domain of your VPS |
| `relay_port` | 7070 | Phasora protocol port |
| `sox_bridge_port` | 1081 | Internal xray → relay bridge |
| `vless_port` | 8443 | VLESS port for iPhone |
| `code` | — | Session code (shared secret) |
| `key` | — | Passphrase for AES key derivation |
| `socks_port` | 1080 | Local SOCKS5 port (client side) |
| `dns_proxy_port` | 5353 | Local DNS proxy port |
| `dns_server` | 1.1.1.1 | Upstream DNS (resolved via tunnel) |

> ⚠️ **`phasora.json` is in `.gitignore` — it contains your passphrase and IP, never commit it.**

---

## VPN Mode (Windows only)

Routes **all** traffic through the tunnel using tun2socks:

1. Download `tun2socks.exe` → [github.com/xjasonlyu/tun2socks/releases](https://github.com/xjasonlyu/tun2socks/releases)
2. Place it next to `client.py`
3. Run `menu_client.py` as **Administrator** → press `[2]`

---

## Requirements

- Python 3.11+
- `pip install cryptography`
- A VPS with a public IP (relay)
- For iPhone: V2Box or Streisand (free, App Store)
- For full VPN on Windows: tun2socks.exe + Admin rights

---

## Author

**Rushqp** — built for personal use, shared for anyone who needs it.

---
---

<a name="فارسی"></a>

## فازورا چیه؟

فازورا یه تانل رمزنگاری‌شده self-hosted هست که به یه کامپیوتر **پشت فایروال** اجازه می‌ده پروکسی SOCKS5 بده — بدون port forwarding و بدون پورت inbound باز. یه VPS وسط کار relay رو انجام می‌ده. آیفون هم از طریق VLESS/WebSocket با xray-core وصل می‌شه.

```
[سرور — پشت فایروال] ──outbound──► [Relay VPS] ◄──── [کلاینت / لپ‌تاپ]
                                          │
                                   [آیفون با VLESS]
```

---

## امنیت

| لایه | جزئیات |
|------|--------|
| **AES-256-GCM** | رمزنگاری احراز هویت‌دار روی کل ترافیک |
| **X25519 ECDH** | Perfect Forward Secrecy — هر session یه کلید جدید |
| **HKDF-SHA256** | session key از ECDH derive میشه |
| **PBKDF2-SHA256** | 600,000 iteration — brute-force مقاوم |
| **توکن HMAC-SHA256** | احراز هویت handshake با پنجره ±1 دقیقه |
| **Nonce یکنوا** | جلوگیری از nonce reuse در AES-GCM |
| **Padding تصادفی** | مقابله با traffic fingerprinting |
| **Rate limiting** | ۱۰ اتصال / IP / ۶۰ ثانیه |

---

## ساختار فایل‌ها

```
phasora/
├── crypto.py           ← هسته رمزنگاری (مشترک بین همه)
├── relay.py            ← سرور relay — روی VPS اجرا میشه
├── server.py           ← پشت فایروال، outbound به relay وصل میشه
├── client.py           ← SOCKS5 proxy + VPN کامل (ویندوز)
├── dns_proxy.py        ← DNS-over-SOCKS5 برای جلوگیری از DNS leak
├── setup_relay.py      ← ویزارد راه‌اندازی (اول اجرا کن)
├── xray_config.json    ← تنظیمات xray-core برای آیفون
├── menu.py             ← لانچر کامل (ماشین relay)
├── menu_server.py      ← لانچر ماشین پشت فایروال
└── menu_client.py      ← لانچر ماشین کلاینت
```

---

## شروع سریع

### ۱ — نصب وابستگی

```bash
pip install cryptography
```

### ۲ — راه‌اندازی relay (یه‌بار روی VPS)

```bash
python setup_relay.py
```

xray-core رو دانلود می‌کنه، config می‌سازه، لینک VLESS آیفون رو چاپ می‌کنه.

### ۳ — شروع سرویس‌های relay

```bash
python menu.py
# دکمه [r] — restart سریع: relay + xray + server
```

### ۴ — اجرا روی ماشین پشت فایروال

```bash
python menu_server.py
# دکمه [1]
```

### ۵ — اتصال از کلاینت

```bash
python menu_client.py
# [1] برای SOCKS5   یا   [2] برای VPN کامل (ویندوز Admin)
```

پروکسی مرورگر یا سیستم رو روی `127.0.0.1:1080` بذار.

### آیفون

QR code چاپ‌شده توسط `setup_relay.py` رو در **V2Box** یا **Streisand** (رایگان در App Store) اسکن کن.

---

## پیکربندی — phasora.json

| کلید | پیش‌فرض | توضیح |
|------|---------|-------|
| `relay_host` | — | IP یا دامنه عمومی VPS |
| `relay_port` | 7070 | پورت پروتکل Phasora |
| `sox_bridge_port` | 1081 | پل داخلی xray → relay |
| `vless_port` | 8443 | پورت VLESS برای آیفون |
| `code` | — | کد session (shared secret) |
| `key` | — | passphrase برای derive کلید AES |
| `socks_port` | 1080 | پورت SOCKS5 لوکال (کلاینت) |
| `dns_proxy_port` | 5353 | پورت DNS proxy لوکال |
| `dns_server` | 1.1.1.1 | DNS upstream (از طریق تانل) |

> ⚠️ **فایل `phasora.json` داخل `.gitignore` هست — حاوی passphrase و IP توئه، هرگز upload نکن.**

---

## VPN کامل (فقط ویندوز)

همه ترافیک رو از طریق تانل route می‌کنه با tun2socks:

1. `tun2socks.exe` رو از [github.com/xjasonlyu/tun2socks/releases](https://github.com/xjasonlyu/tun2socks/releases) دانلود کن
2. کنار `client.py` بذارش
3. `menu_client.py` رو به عنوان **Administrator** باز کن ← دکمه `[2]`

---

## پیش‌نیازها

- Python 3.11+
- `pip install cryptography`
- یه VPS با IP عمومی (relay)
- برای آیفون: V2Box یا Streisand (رایگان، App Store)
- برای VPN کامل ویندوز: tun2socks.exe + دسترسی Admin

---

## نویسنده

**Rushqp** — برای استفاده شخصی ساخته شده، برای هر کسی که نیاز داشته باشه.
