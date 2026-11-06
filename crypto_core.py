"""Kriptografi inti.

* Super Enkripsi teks : Layer 1 Vigenère (A-Z mod 26) + Layer 2 AES-256-GCM.
* Derivasi kunci      : PBKDF2-HMAC-SHA256.
* Enkripsi kolom DB   : AES-256-GCM dengan AAD = nama kolom (context binding).
"""
import base64
import binascii
import hashlib
import os
import string
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config


class CryptoError(Exception):
    """Kesalahan kriptografi yang aman ditampilkan ke pengguna."""


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error) as exc:
        raise CryptoError("Format Base64 tidak valid.") from exc


def derive_key(secret, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256 -> kunci AES 256-bit."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, dklen=32)


# ---------------------------------------------------------------------------
# Layer 1: Vigenère Cipher (alfabet A-Z, mod 26)
# Huruf besar/kecil dipertahankan; karakter non-huruf tidak diubah dan tidak
# menggeser indeks kunci.
# ---------------------------------------------------------------------------
def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    shifts = [ord(c.upper()) - 65 for c in key if c in string.ascii_letters]
    if not shifts:
        raise CryptoError("Kunci Vigenère harus berisi minimal satu huruf A-Z.")
    out, j = [], 0
    for ch in text:
        if ch in string.ascii_uppercase:
            base = 65
        elif ch in string.ascii_lowercase:
            base = 97
        else:
            out.append(ch)
            continue
        shift = shifts[j % len(shifts)]
        j += 1
        if decrypt:
            shift = -shift
        out.append(chr((ord(ch) - base + shift) % 26 + base))
    return "".join(out)


# ---------------------------------------------------------------------------
# Super Enkripsi: Vigenère -> AES-256-GCM
# Token: "SEV1." + base64url( iterations(4) | salt(16) | nonce(12) | ciphertext+tag )
# AAD  : "SEV1" + iterations(4)  -> header ikut diautentikasi.
# ---------------------------------------------------------------------------
SUPER_PREFIX = "SEV1"
_ITER_MIN, _ITER_MAX = 1_000, 5_000_000


def super_encrypt(plaintext: str, vigenere_key: str, passphrase: str) -> dict:
    if not plaintext:
        raise CryptoError("Teks tidak boleh kosong.")
    if len(passphrase) < 8:
        raise CryptoError("Passphrase AES minimal 8 karakter.")
    layer1 = vigenere(plaintext, vigenere_key)
    iterations = config.TEXT_KDF_ITERATIONS
    salt, nonce = os.urandom(16), os.urandom(12)
    iter_bytes = struct.pack(">I", iterations)
    key = derive_key(passphrase, salt, iterations)
    ct = AESGCM(key).encrypt(nonce, layer1.encode("utf-8"), SUPER_PREFIX.encode() + iter_bytes)
    token = f"{SUPER_PREFIX}." + b64e(iter_bytes + salt + nonce + ct)
    return {"layer1": layer1, "ciphertext": token}


def super_decrypt(token: str, vigenere_key: str, passphrase: str) -> dict:
    prefix, _, body = token.strip().partition(".")
    if prefix != SUPER_PREFIX or not body:
        raise CryptoError("Format ciphertext tidak dikenali (harus diawali 'SEV1.').")
    blob = b64d(body)
    if len(blob) < 4 + 16 + 12 + 16:
        raise CryptoError("Ciphertext terlalu pendek atau rusak.")
    iter_bytes, salt, nonce, ct = blob[:4], blob[4:20], blob[20:32], blob[32:]
    iterations = struct.unpack(">I", iter_bytes)[0]
    if not _ITER_MIN <= iterations <= _ITER_MAX:
        raise CryptoError("Parameter KDF pada ciphertext tidak valid.")
    key = derive_key(passphrase, salt, iterations)
    try:
        layer1 = AESGCM(key).decrypt(nonce, ct, SUPER_PREFIX.encode() + iter_bytes).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise CryptoError("Dekripsi gagal: passphrase salah atau data telah diubah.") from exc
    return {"layer1": layer1, "plaintext": vigenere(layer1, vigenere_key, decrypt=True)}


# ---------------------------------------------------------------------------
# Enkripsi kolom database (AES-256-GCM)
# Format: "v1:" + base64url(nonce(12) | ciphertext+tag); AAD = "tabel.kolom".
# ---------------------------------------------------------------------------
_FIELD_PREFIX = "v1:"


class FieldCipher:
    def __init__(self, master_key: bytes):
        self._aes = AESGCM(master_key)

    def encrypt(self, value: str, context: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, value.encode("utf-8"), context.encode("utf-8"))
        return _FIELD_PREFIX + b64e(nonce + ct)

    def decrypt(self, token: str, context: str) -> str:
        if not token.startswith(_FIELD_PREFIX):
            raise CryptoError("Format kolom terenkripsi tidak dikenali.")
        raw = b64d(token[len(_FIELD_PREFIX):])
        if len(raw) < 12 + 16:
            raise CryptoError("Data kolom rusak.")
        try:
            return self._aes.decrypt(raw[:12], raw[12:], context.encode("utf-8")).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise CryptoError("Kolom tidak dapat didekripsi (kunci salah / data diubah).") from exc


_field_cipher = FieldCipher(config.MASTER_KEY)


def encrypt_field(value: str, context: str) -> str:
    return _field_cipher.encrypt(value, context)


def decrypt_field(token: str, context: str) -> str:
    return _field_cipher.decrypt(token, context)
