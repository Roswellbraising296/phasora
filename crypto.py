"""
Phasora - Crypto v4
AES-256-GCM + PBKDF2 key derivation + X25519 ECDH Perfect Forward Secrecy

Changes v4:
  - X25519 ECDH برای Perfect Forward Secrecy — هر session کلید جدید
  - HKDF برای key derivation بعد از ECDH
  - Monotonic nonce counter برای جلوگیری از nonce reuse
  - PBKDF2 iterations از 260k به 600k
  - Packet padding تصادفی برای مقابله با traffic fingerprinting

Author : Rushqp
Project: Phasora — github or local
"""

import os
import hashlib
import hmac
import time
import struct
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ── constants ─────────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 600_000          # بالاتر از قبل — brute-force سخت‌تر
SALT = b"Phasora_v1_salt_2025"       # fixed salt برای key derivation اولیه

PAD_BLOCK   = 64    # bytes — تراز پایه
PAD_MAX_ADD = 128   # bytes — حداکثر padding اضافه تصادفی


# ── PBKDF2 key derivation ─────────────────────────────────────────────────────

def derive_key(passphrase: str) -> bytes:
    """PBKDF2-SHA256 — returns 32-byte static key"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode(),
        SALT,
        PBKDF2_ITERATIONS,
        dklen=32
    )


def derive_auth_key(passphrase: str) -> bytes:
    """Separate key برای HMAC handshake"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode(),
        SALT + b"_auth",
        PBKDF2_ITERATIONS,
        dklen=32
    )


# ── HMAC handshake token ──────────────────────────────────────────────────────

def make_handshake_token(auth_key: bytes, role: str, code: str) -> str:
    """HMAC-SHA256 روی role+code+timestamp"""
    ts = int(time.time()) // 60
    msg = f"{role}:{code.upper()}:{ts}".encode()
    return hmac.new(auth_key, msg, hashlib.sha256).hexdigest()


def verify_handshake_token(auth_key: bytes, role: str, code: str, token: str) -> bool:
    """تأیید token — پنجره +-1 دقیقه"""
    ts = int(time.time()) // 60
    for delta in (0, -1, 1):
        msg = f"{role}:{code.upper()}:{ts + delta}".encode()
        expected = hmac.new(auth_key, msg, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, token):
            return True
    return False


# ── X25519 ECDH Perfect Forward Secrecy ──────────────────────────────────────

class ECDHSession:
    """
    X25519 Ephemeral ECDH — هر session یه کلید جدید

    مراحل:
      1. هر طرف یه private key موقت میسازه
      2. public keyها رد و بدل میشن (32 bytes هر کدوم)
      3. shared secret محاسبه میشه
      4. از HKDF یه session key 32 بایتی میشه

    نتیجه: حتی اگر passphrase لو بره، traffic قدیمی decrypt نمیشه (PFS)
    """

    def __init__(self):
        self._private = X25519PrivateKey.generate()
        self.public_bytes = self._private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )  # 32 bytes — برای ارسال به طرف مقابل

    def derive_session_key(
        self,
        peer_public_bytes: bytes,
        context: bytes = b"Phasora_session_v4",
    ) -> bytes:
        """
        shared secret رو از کلید عمومی طرف مقابل محاسبه میکنه
        و با HKDF یه کلید 32 بایتی میسازه
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared   = self._private.exchange(peer_pub)

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context,
        ).derive(shared)


# ── Nonce Counter — جلوگیری از nonce reuse ───────────────────────────────────

class NonceCounter:
    """
    Monotonic counter برای AES-GCM nonce
    هرگز دو بار یه nonce استفاده نمیشه

    ساختار nonce (12 bytes):
      [4 bytes: random session id] + [8 bytes: counter big-endian]
    """

    def __init__(self):
        self._session_id = os.urandom(4)
        self._counter    = 0
        self._lock       = threading.Lock()

    def next(self) -> bytes:
        with self._lock:
            if self._counter >= (1 << 64) - 1:
                raise OverflowError("Nonce counter exhausted — reconnect required")
            nonce = self._session_id + struct.pack(">Q", self._counter)
            self._counter += 1
            return nonce  # 12 bytes


# ── Packet Padding ────────────────────────────────────────────────────────────

def pad(data: bytes) -> bytes:
    """
    Padding تصادفی اضافه میکنه تا traffic fingerprinting سخت‌تر بشه
    فرمت: [2 bytes: طول padding] + [data] + [padding bytes تصادفی]
    """
    pad_len = (PAD_BLOCK - (len(data) % PAD_BLOCK)) % PAD_BLOCK
    pad_len += os.urandom(1)[0] % PAD_MAX_ADD
    return struct.pack(">H", pad_len) + data + os.urandom(pad_len)


def unpad(data: bytes) -> bytes:
    """Padding رو حذف میکنه"""
    if len(data) < 2:
        raise ValueError("Padded data too short")
    pad_len = struct.unpack(">H", data[:2])[0]
    end = len(data) - pad_len
    if end < 2:
        raise ValueError("Invalid padding length")
    return data[2:end]


# ── AES-256-GCM encrypt/decrypt ───────────────────────────────────────────────

def encrypt(key: bytes, plaintext: bytes, nonce_counter: "NonceCounter | None" = None) -> bytes:
    """
    AES-256-GCM با padding
    output: nonce(12) + ciphertext+tag

    اگر nonce_counter داده بشه از counter monotonic استفاده میشه
    وگرنه random nonce (برای backward compatibility)
    """
    padded = pad(plaintext)
    nonce  = nonce_counter.next() if nonce_counter else os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, padded, None)


def decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt + unpad"""
    if len(data) < 12:
        raise ValueError("Ciphertext too short")
    decrypted = AESGCM(key).decrypt(data[:12], data[12:], None)
    return unpad(decrypted)
