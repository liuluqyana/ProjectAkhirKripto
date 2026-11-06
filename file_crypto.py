"""Enkripsi file biner naskah soal (PDF/DOCX) - format berversi 'KGP2'.

Tata letak berkas .kgp:

    offset  ukuran  isi
    0       4       magic  b"KGP2"
    4       1       versi format (1)
    5       4       jumlah iterasi PBKDF2 (uint32 big-endian)
    9       16      salt acak
    25      12      nonce ChaCha20-Poly1305
    37      ...     ciphertext + Poly1305 tag (16 byte)

Plaintext terenkripsi: uint16 panjang nama | nama berkas UTF-8 | isi berkas.
Seluruh header (37 byte) menjadi AAD sehingga tidak dapat diubah tanpa
membuat dekripsi gagal. Kunci ChaCha20-256 diturunkan dari token/passphrase
memakai PBKDF2-HMAC-SHA256.
"""
import hashlib
import os
import re
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import config
from crypto_core import derive_key

MAGIC = b"KGP2"
LEGACY_MAGIC = b"KGP1"
VERSION = 1
HEADER_FMT = ">4sBI16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 37
_ITER_MIN, _ITER_MAX = 1_000, 5_000_000


class FileCryptoError(Exception):
    """Kesalahan enkripsi/dekripsi berkas yang aman ditampilkan ke pengguna."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name or "naskah_soal"


def validate_exam_file(filename: str, data: bytes) -> str:
    """Pastikan ekstensi PDF/DOCX dan signature isi sesuai. Mengembalikan ekstensi."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in config.ALLOWED_EXAM_EXT:
        raise FileCryptoError("Hanya berkas PDF atau DOCX yang diperbolehkan.")
    if not data:
        raise FileCryptoError("Berkas kosong.")
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise FileCryptoError(f"Ukuran berkas melebihi {config.MAX_UPLOAD_MB} MB.")
    if ext == "pdf" and not data.startswith(b"%PDF"):
        raise FileCryptoError("Isi berkas bukan PDF yang valid.")
    if ext == "docx" and not data.startswith(b"PK\x03\x04"):
        raise FileCryptoError("Isi berkas bukan DOCX yang valid.")
    return ext


def encrypt_file(data: bytes, filename: str, passphrase: str) -> bytes:
    if len(passphrase) < 8:
        raise FileCryptoError("Token/passphrase minimal 8 karakter.")
    validate_exam_file(filename, data)
    name_bytes = _safe_name(filename).encode("utf-8")[:1024]
    salt, nonce = os.urandom(16), os.urandom(12)
    iterations = config.FILE_KDF_ITERATIONS
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, iterations, salt, nonce)
    key = derive_key(passphrase, salt, iterations)
    payload = struct.pack(">H", len(name_bytes)) + name_bytes + data
    return header + ChaCha20Poly1305(key).encrypt(nonce, payload, header)


def is_kgp1(blob: bytes) -> bool:
    return len(blob) >= HEADER_SIZE + 16 and blob[:4] in (MAGIC, LEGACY_MAGIC)


def decrypt_file(blob: bytes, passphrase: str) -> tuple[str, bytes]:
    if not is_kgp1(blob):
        raise FileCryptoError("Berkas bukan format KGP1/KGP2 (magic header tidak cocok).")
    magic, version, iterations, salt, nonce = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    if version != VERSION:
        raise FileCryptoError(f"Versi format KGP{version} tidak didukung.")
    if not _ITER_MIN <= iterations <= _ITER_MAX:
        raise FileCryptoError("Parameter KDF pada header tidak valid.")
    key = derive_key(passphrase, salt, iterations)
    try:
        aead = ChaCha20Poly1305(key) if magic == MAGIC else AESGCM(key)
        payload = aead.decrypt(nonce, blob[HEADER_SIZE:], blob[:HEADER_SIZE])
    except InvalidTag as exc:
        raise FileCryptoError("Dekripsi gagal: token salah atau berkas telah diubah.") from exc
    if len(payload) < 2:
        raise FileCryptoError("Payload rusak.")
    (name_len,) = struct.unpack(">H", payload[:2])
    if 2 + name_len > len(payload):
        raise FileCryptoError("Payload rusak.")
    name = _safe_name(payload[2:2 + name_len].decode("utf-8", errors="replace"))
    return name, payload[2 + name_len:]
