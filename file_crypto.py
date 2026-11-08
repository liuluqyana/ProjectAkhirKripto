
"""Enkripsi file KGP4: 3DES-CBC + HMAC-SHA256.
Tetap mendukung dekripsi KGP1, KGP2, dan KGP3.
Khusus demonstrasi akademik, bukan keamanan produksi.
"""

import hashlib
import hmac
import os
import re
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

import config
from crypto_core import derive_key

MAGIC = b"KGP4"
AES_MAGIC = b"KGP3"
PREVIOUS_MAGIC = b"KGP2"
LEGACY_MAGIC = b"KGP1"

VERSION = 1
HEADER_FMT = ">4sBI16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

KGP4_HEADER_FMT = ">4sBI16s8s"
KGP4_HEADER_SIZE = struct.calcsize(KGP4_HEADER_FMT)
KGP4_TAG_SIZE = 32

_ITER_MIN = 1_000
_ITER_MAX = 5_000_000


class FileCryptoError(Exception):
    """Kesalahan enkripsi atau dekripsi file."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name or "naskah_soal"


def validate_exam_file(filename: str, data: bytes) -> str:
    """Validasi file PDF atau DOCX."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in config.ALLOWED_EXAM_EXT:
        raise FileCryptoError("Hanya berkas PDF atau DOCX yang diperbolehkan.")

    if not data:
        raise FileCryptoError("Berkas kosong.")

    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise FileCryptoError(
            f"Ukuran berkas melebihi {config.MAX_UPLOAD_MB} MB."
        )

    if ext == "pdf" and not data.startswith(b"%PDF"):
        raise FileCryptoError("Isi berkas bukan PDF yang valid.")

    if ext == "docx" and not data.startswith(b"PK\x03\x04"):
        raise FileCryptoError("Isi berkas bukan DOCX yang valid.")

    return ext


def encrypt_file(data: bytes, filename: str, passphrase: str) -> bytes:
    """Enkripsi PDF/DOCX menjadi KGP4 dengan 3DES-CBC + HMAC."""
    if len(passphrase) < 8:
        raise FileCryptoError("Token/passphrase minimal 8 karakter.")

    validate_exam_file(filename, data)

    name_bytes = _safe_name(filename).encode("utf-8")[:1024]
    salt = os.urandom(16)
    iv = os.urandom(8)
    iterations = config.FILE_KDF_ITERATIONS

    if not _ITER_MIN <= iterations <= _ITER_MAX:
        raise FileCryptoError("Parameter KDF tidak valid.")

    header = struct.pack(
        KGP4_HEADER_FMT, MAGIC, VERSION, iterations, salt, iv
    )

    material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations,
        dklen=56
    )

    encryption_key = material[:24]
    mac_key = material[24:]

    payload = struct.pack(">H", len(name_bytes)) + name_bytes + data

    padder = padding.PKCS7(64).padder()
    padded = padder.update(payload) + padder.finalize()

    cipher = Cipher(TripleDES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    tag = hmac.new(
        mac_key,
        header + ciphertext,
        hashlib.sha256
    ).digest()

    return header + ciphertext + tag


def is_kgp1(blob: bytes) -> bool:
    """Mengenali file terenkripsi KGP1 sampai KGP4."""
    return (
        len(blob) >= HEADER_SIZE + 16
        and blob[:4] in (
            MAGIC,
            AES_MAGIC,
            PREVIOUS_MAGIC,
            LEGACY_MAGIC
        )
    )


def decrypt_file(blob: bytes, passphrase: str) -> tuple[str, bytes]:
    """Dekripsi file KGP1, KGP2, KGP3, atau KGP4."""
    if not is_kgp1(blob):
        raise FileCryptoError(
            "Berkas bukan format KGP1/KGP2/KGP3/KGP4."
        )

    if blob[:4] == MAGIC:
        if len(blob) < KGP4_HEADER_SIZE + 8 + KGP4_TAG_SIZE:
            raise FileCryptoError("Berkas KGP4 terlalu pendek atau rusak.")

        header = blob[:KGP4_HEADER_SIZE]

        _, version, iterations, salt, iv = struct.unpack(
            KGP4_HEADER_FMT, header
        )

        if version != VERSION or not _ITER_MIN <= iterations <= _ITER_MAX:
            raise FileCryptoError(
                "Versi atau parameter KDF KGP4 tidak valid."
            )

        ciphertext = blob[KGP4_HEADER_SIZE:-KGP4_TAG_SIZE]
        tag = blob[-KGP4_TAG_SIZE:]

        if not ciphertext or len(ciphertext) % 8:
            raise FileCryptoError(
                "Panjang ciphertext KGP4 tidak valid."
            )

        material = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            salt,
            iterations,
            dklen=56
        )

        encryption_key = material[:24]
        mac_key = material[24:]

        expected = hmac.new(
            mac_key,
            header + ciphertext,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(tag, expected):
            raise FileCryptoError(
                "Dekripsi gagal: token salah atau berkas telah diubah."
            )

        cipher = Cipher(TripleDES(encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        try:
            unpadder = padding.PKCS7(64).unpadder()
            payload = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise FileCryptoError("Payload KGP4 rusak.") from exc

    else:
        magic, version, iterations, salt, nonce = struct.unpack(
            HEADER_FMT,
            blob[:HEADER_SIZE]
        )

        if version != VERSION:
            raise FileCryptoError(
                f"Versi format {version} tidak didukung."
            )

        if not _ITER_MIN <= iterations <= _ITER_MAX:
            raise FileCryptoError(
                "Parameter KDF pada header tidak valid."
            )

        key = derive_key(passphrase, salt, iterations)

        try:
            if magic == PREVIOUS_MAGIC:
                aead = ChaCha20Poly1305(key)
            else:
                aead = AESGCM(key)

            payload = aead.decrypt(
                nonce,
                blob[HEADER_SIZE:],
                blob[:HEADER_SIZE]
            )

        except InvalidTag as exc:
            raise FileCryptoError(
                "Dekripsi gagal: token salah atau berkas telah diubah."
            ) from exc

    if len(payload) < 2:
        raise FileCryptoError("Payload rusak.")

    (name_len,) = struct.unpack(">H", payload[:2])

    if 2 + name_len > len(payload):
        raise FileCryptoError("Payload rusak.")

    name = _safe_name(
        payload[2:2 + name_len].decode(
            "utf-8",
            errors="replace"
        )
    )

    return name, payload[2 + name_len:]
