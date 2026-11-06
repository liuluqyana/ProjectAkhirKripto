
"""Autentikasi Secure Exam Vault.

Password: PBKDF2-HMAC-SHA256.
Role: Pusat dan Pengawas.
Penguncian akun akibat percobaan login gagal dinonaktifkan
untuk kebutuhan demonstrasi tugas.
"""

import base64
import functools
import hashlib
import hmac
import os
import re
import secrets
import time

from flask import abort, g, session

import config
import database
import dongle


_ALGO = "pbkdf2_sha256"
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")


# ---------------- PASSWORD HASHING ----------------

def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or config.PBKDF2_ITERATIONS
    salt = os.urandom(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )

    return (
        f"{_ALGO}${iterations}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(dk).decode()}"
    )


_DUMMY_HASH = None


def verify_password(password: str, stored: str | None) -> bool:
    global _DUMMY_HASH

    if stored is None:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password("dummy-password-for-timing")

        _check(password, _DUMMY_HASH)
        return False

    return _check(password, stored)


def _check(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")

        if algo != _ALGO:
            return False

        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
            dklen=len(expected)
        )

    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    try:
        return int(stored.split("$")[1]) < config.PBKDF2_ITERATIONS
    except (IndexError, ValueError):
        return True


def validate_password_strength(password: str) -> None:
    if len(password) < 10 or not (
        re.search(r"[a-z]", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"\d", password)
    ):
        raise ValueError(
            "Password minimal 10 karakter dengan "
            "huruf besar, huruf kecil, dan angka."
        )


# ---------------- MANAJEMEN AKUN ----------------

def create_user(
    db,
    username: str,
    password: str,
    role: str,
    full_name: str
) -> int:

    username = username.strip().lower()

    if not USERNAME_RE.match(username):
        raise ValueError(
            "Username 3-32 karakter: huruf kecil, angka, "
            "titik, garis bawah, atau strip."
        )

    if role not in ("pusat", "pengawas"):
        raise ValueError("Role harus 'pusat' atau 'pengawas'.")

    validate_password_strength(password)

    secret = dongle.new_dongle_secret()

    user_id = database.create_user(
        db,
        username,
        hash_password(password),
        role,
        full_name.strip(),
        secret
    )

    if config.DEMO_ENABLED:
        dongle.write_demo_token(username, secret)

    return user_id


DEMO_USERS = [
    (
        "pusat",
        "Pusat#Vault2026",
        "pusat",
        "Admin Pusat Ujian"
    ),
    (
        "pengawas1",
        "Pengawas#Vault2026",
        "pengawas",
        "Pengawas Ruang 1"
    ),
    (
        "pengawas2",
        "Pengawas#Vault2026",
        "pengawas",
        "Pengawas Ruang 2"
    ),
]


def seed_demo_users() -> list[str]:
    db = database.connect()

    try:
        if database.count_users(db) > 0:
            return []

        lines = [
            "[SEED] Akun demo dibuat:"
        ]

        for username, password, role, name in DEMO_USERS:
            create_user(
                db,
                username,
                password,
                role,
                name
            )

            lines.append(
                f"       {role:<8} "
                f"username={username:<10} "
                f"password={password}"
            )

        if config.DEMO_ENABLED:
            lines.append(
                f"[SEED] Token dongle demo: "
                f"{config.DEMO_DONGLE_DIR}"
            )

        return lines

    finally:
        db.close()


# ---------------- LOGIN TANPA PENGUNCIAN ----------------

def is_locked(user) -> bool:
    """
    Akun tidak dikunci sementara akibat login gagal.

    Fungsi tetap tersedia agar pemanggilan dari app.py
    tidak perlu diubah.
    """
    return False


def register_failure(db, user) -> None:
    """
    Login gagal tidak menambah penghitung percobaan
    dan tidak menyebabkan penguncian akun.
    """
    return None


def clear_failures(db, user) -> None:
    """
    Bersihkan status penguncian lama jika ada.
    """
    if user["failed_attempts"] or user["locked_until"]:
        database.set_lock_state(
            db,
            user["id"],
            0,
            None
        )


# ---------------- SESI LOGIN ----------------

def start_pending(user) -> None:
    session["pending"] = {
        "uid": user["id"],
        "t": int(time.time())
    }


def pending_user(db):
    pending = session.get("pending")

    if not pending:
        return None

    if (
        time.time() - pending["t"]
        > config.PENDING_LOGIN_TTL_SECONDS
    ):
        return None

    return database.get_user(
        db,
        pending["uid"]
    )


def complete_login(user) -> None:
    session.clear()
    session.permanent = True

    session["uid"] = user["id"]
    session["role"] = user["role"]
    session["csrf"] = secrets.token_urlsafe(32)


# ---------------- CSRF ----------------

def csrf_token() -> str:
    token = session.get("csrf")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token

    return token


def check_csrf(supplied) -> bool:
    expected = session.get("csrf")

    return bool(
        expected
        and supplied
        and hmac.compare_digest(expected, supplied)
    )


# ---------------- ROLE BASED ACCESS ----------------

def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):

        if g.get("user") is None:
            abort(401)

        return view(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(view):

        @functools.wraps(view)
        def wrapper(*args, **kwargs):

            if g.get("user") is None:
                abort(401)

            if g.user["role"] not in roles:
                abort(403)

            return view(*args, **kwargs)

        return wrapper

    return decorator
