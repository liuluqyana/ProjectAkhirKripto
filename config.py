"""Konfigurasi terpusat Secure Exam Distribution Vault.

Semua rahasia (SECRET_KEY, MASTER_KEY) dibuat acak saat pertama kali dijalankan
dan disimpan di folder instance/ (permission 0600). Untuk produksi, isi lewat
variabel lingkungan KGP_SECRET_KEY dan KGP_MASTER_KEY (base64url dari 32 byte).
"""
import base64
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.environ.get("KGP_INSTANCE_DIR", BASE_DIR / "instance")).resolve()
PACKAGE_DIR = INSTANCE_DIR / "packages"
DEMO_DONGLE_DIR = INSTANCE_DIR / "demo_dongles"
DB_PATH = INSTANCE_DIR / "kriptoguard.db"
LOGO_PATH = BASE_DIR / "static" / "img" / "Logo_UPN_Yogyakarta.png"

for _d in (INSTANCE_DIR, PACKAGE_DIR, DEMO_DONGLE_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _load_secret(env_name: str, filename: str, size: int = 32) -> bytes:
    """Ambil rahasia dari env, atau file instance/, atau buat baru."""
    value = os.environ.get(env_name)
    if value:
        raw = _b64u_decode(value.strip())
        if len(raw) != size:
            raise RuntimeError(f"{env_name} harus base64url dari {size} byte.")
        return raw
    path = INSTANCE_DIR / filename
    if path.exists():
        return _b64u_decode(path.read_text().strip())
    raw = secrets.token_bytes(size)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.urlsafe_b64encode(raw).decode("ascii"))
    return raw


SECRET_KEY = _load_secret("KGP_SECRET_KEY", "secret.key")
MASTER_KEY = _load_secret("KGP_MASTER_KEY", "master.key")  # kunci enkripsi kolom DB

# --- Parameter kriptografi ---------------------------------------------------
PBKDF2_ITERATIONS = int(os.environ.get("KGP_PBKDF2_ITERATIONS", 600_000))  # hash password
FILE_KDF_ITERATIONS = int(os.environ.get("KGP_FILE_ITERATIONS", 300_000))  # enkripsi file KGP1
TEXT_KDF_ITERATIONS = int(os.environ.get("KGP_TEXT_ITERATIONS", 300_000))  # super enkripsi teks

# --- Autentikasi -------------------------------------------------------------
# DONGLE_MODE: "demo" (challenge-response virtual), "webauthn" (FIDO2/biometrik),
# atau "both" (default; keduanya tersedia).
DONGLE_MODE = os.environ.get("KGP_DONGLE_MODE", "both").lower()
DEMO_ENABLED = DONGLE_MODE in ("demo", "both")
WEBAUTHN_ENABLED = DONGLE_MODE in ("webauthn", "both")
DEMO_TOKEN_DOWNLOAD = os.environ.get("KGP_DEMO_TOKEN_DOWNLOAD", "0") == "1"

WEBAUTHN_RP_ID = os.environ.get("KGP_RP_ID", "localhost")
WEBAUTHN_RP_NAME = "Secure Exam Distribution Vault"
WEBAUTHN_ORIGIN = os.environ.get("KGP_ORIGIN", "http://localhost:5000")

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 300
CHALLENGE_TTL_SECONDS = 120
PENDING_LOGIN_TTL_SECONDS = 300
SESSION_MINUTES = 30
COOKIE_SECURE = os.environ.get("KGP_COOKIE_SECURE", "0") == "1"

# --- Upload ------------------------------------------------------------------
MAX_UPLOAD_MB = 25
ALLOWED_EXAM_EXT = {"pdf", "docx"}
MAX_IMAGE_PIXELS = 16_000_000

# Buat akun demo (pusat, pengawas1, pengawas2) bila tabel users masih kosong.
SEED_DEMO = os.environ.get("KGP_SEED_DEMO", "1") == "1"
