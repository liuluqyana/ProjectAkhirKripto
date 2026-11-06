"""Lapisan database SQLite (kriptoguard.db).

* Seluruh query memakai parameterized queries (placeholder '?').
* Kolom sensitif (nama lengkap, nama ujian, log, berita acara, kunci jawaban,
  rahasia dongle) disimpan terenkripsi AES-256-GCM (*_enc) dan diikat ke
  nama kolomnya lewat AAD.
"""
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import g

import blockchain
import config
from crypto_core import CryptoError, decrypt_field, encrypt_field

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('pusat', 'pengawas')),
    full_name_enc TEXT NOT NULL,
    dongle_secret_enc TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS face_templates (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    template_enc TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_challenges (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, kind)
);
CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    exam_name_enc TEXT NOT NULL,
    original_name_enc TEXT NOT NULL,
    encrypted_sha256 TEXT NOT NULL,
    stego_sha256 TEXT NOT NULL,
    enc_path TEXT NOT NULL,
    stego_path TEXT NOT NULL,
    released_by INTEGER NOT NULL REFERENCES users(id),
    released_at TEXT NOT NULL,
    available_from TEXT NOT NULL,
    block_index INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS supervisor_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    action_enc TEXT NOT NULL,
    detail_enc TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS berita_acara (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES packages(id),
    supervisor_id INTEGER NOT NULL REFERENCES users(id),
    content_enc TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS answer_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title_enc TEXT NOT NULL,
    cipher_enc TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blockchain (
    idx INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    data_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE
);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, isolation_level=None, timeout=15)  # autocommit; transaksi eksplisit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        blockchain.ensure_genesis(conn)
    finally:
        conn.close()


def enc(value: str, context: str) -> str:
    return encrypt_field(value, context)


def dec(token: str, context: str) -> str:
    try:
        return decrypt_field(token, context)
    except CryptoError:
        return "[tidak dapat didekripsi]"


# ------------------------------- Users -------------------------------------
def count_users(db) -> int:
    return db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def create_user(db, username, password_hash, role, full_name, dongle_secret) -> int:
    cur = db.execute(
        "INSERT INTO users(username, password_hash, role, full_name_enc, dongle_secret_enc, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (username, password_hash, role, enc(full_name, "users.full_name"),
         enc(dongle_secret, "users.dongle_secret"), utcnow_iso()),
    )
    return cur.lastrowid


def _user_dict(row):
    if row is None:
        return None
    user = dict(row)
    user["full_name"] = dec(user["full_name_enc"], "users.full_name")
    return user


def get_user_by_username(db, username):
    return _user_dict(db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())


def get_user(db, user_id):
    return _user_dict(db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def get_dongle_secret(user) -> str:
    return decrypt_field(user["dongle_secret_enc"], "users.dongle_secret")


def set_lock_state(db, user_id, attempts, locked_until) -> None:
    db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
               (attempts, locked_until, user_id))


def update_password_hash(db, user_id, new_hash) -> None:
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))


# --------------------------- Challenge & WebAuthn ---------------------------
def store_challenge(db, user_id, kind, challenge) -> None:
    db.execute(
        "INSERT OR REPLACE INTO auth_challenges(user_id, kind, challenge, expires_at) VALUES (?,?,?,?)",
        (user_id, kind, challenge, int(time.time()) + config.CHALLENGE_TTL_SECONDS),
    )


def pop_challenge(db, user_id, kind):
    """Ambil sekaligus hapus challenge (sekali pakai). None bila tidak ada/kedaluwarsa."""
    row = db.execute("SELECT challenge, expires_at FROM auth_challenges WHERE user_id = ? AND kind = ?",
                     (user_id, kind)).fetchone()
    db.execute("DELETE FROM auth_challenges WHERE user_id = ? AND kind = ?", (user_id, kind))
    if row is None or row["expires_at"] < time.time():
        return None
    return row["challenge"]


def list_webauthn_credentials(db, user_id) -> list:
    return db.execute("SELECT * FROM webauthn_credentials WHERE user_id = ?", (user_id,)).fetchall()


def add_webauthn_credential(db, user_id, credential_id, public_key, sign_count) -> None:
    db.execute(
        "INSERT INTO webauthn_credentials(user_id, credential_id, public_key, sign_count, created_at) "
        "VALUES (?,?,?,?,?)",
        (user_id, credential_id, public_key, sign_count, utcnow_iso()),
    )


def update_sign_count(db, credential_row_id, sign_count) -> None:
    db.execute("UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?", (sign_count, credential_row_id))


# ------------------------------- Packages -----------------------------------
def insert_package(db, pkg: dict) -> None:
    db.execute(
        "INSERT INTO packages(id, exam_name_enc, original_name_enc, encrypted_sha256, stego_sha256, "
        "enc_path, stego_path, released_by, released_at, available_from, block_index) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pkg["id"], enc(pkg["exam_name"], "packages.exam_name"),
         enc(pkg["original_name"], "packages.original_name"), pkg["encrypted_sha256"], pkg["stego_sha256"],
         pkg["enc_path"], pkg["stego_path"], pkg["released_by"], pkg["released_at"],
         pkg["available_from"], pkg["block_index"]),
    )


def _package_dict(row) -> dict:
    return {
        "id": row["id"],
        "exam_name": dec(row["exam_name_enc"], "packages.exam_name"),
        "original_name": dec(row["original_name_enc"], "packages.original_name"),
        "encrypted_sha256": row["encrypted_sha256"],
        "stego_sha256": row["stego_sha256"],
        "enc_path": row["enc_path"],
        "stego_path": row["stego_path"],
        "released_by": row["username"],
        "released_at": row["released_at"],
        "available_from": row["available_from"],
        "block_index": row["block_index"],
        "available": row["available_from"] <= utcnow_iso(),
    }


_PKG_SELECT = "SELECT p.*, u.username FROM packages p JOIN users u ON u.id = p.released_by"


def list_packages(db) -> list[dict]:
    return [_package_dict(r) for r in db.execute(_PKG_SELECT + " ORDER BY p.released_at DESC").fetchall()]


def get_package(db, package_id):
    row = db.execute(_PKG_SELECT + " WHERE p.id = ?", (package_id,)).fetchone()
    return _package_dict(row) if row else None


# --------------------------------- Logs --------------------------------------
def add_log(db, user_id, action: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO supervisor_logs(user_id, action_enc, detail_enc, created_at) VALUES (?,?,?,?)",
        (user_id, enc(action, "supervisor_logs.action"), enc(detail, "supervisor_logs.detail"), utcnow_iso()),
    )


def list_logs(db, user_id=None, limit=100) -> list[dict]:
    sql = ("SELECT l.id, l.action_enc, l.detail_enc, l.created_at, u.username, u.role "
           "FROM supervisor_logs l JOIN users u ON u.id = l.user_id")
    params: list = []
    if user_id is not None:
        sql += " WHERE l.user_id = ?"
        params.append(user_id)
    sql += " ORDER BY l.id DESC LIMIT ?"
    params.append(limit)
    return [
        {"id": r["id"], "username": r["username"], "role": r["role"], "created_at": r["created_at"],
         "action": dec(r["action_enc"], "supervisor_logs.action"),
         "detail": dec(r["detail_enc"], "supervisor_logs.detail")}
        for r in db.execute(sql, params).fetchall()
    ]


# ---------------------------- Berita acara -----------------------------------
def add_berita_acara(db, package_id, supervisor_id, content: dict) -> None:
    db.execute(
        "INSERT INTO berita_acara(package_id, supervisor_id, content_enc, created_at) VALUES (?,?,?,?)",
        (package_id, supervisor_id, enc(json.dumps(content, ensure_ascii=False), "berita_acara.content"),
         utcnow_iso()),
    )


def list_berita_acara(db, supervisor_id=None, limit=100) -> list[dict]:
    sql = ("SELECT b.id, b.package_id, b.content_enc, b.created_at, u.username, p.exam_name_enc "
           "FROM berita_acara b JOIN users u ON u.id = b.supervisor_id "
           "JOIN packages p ON p.id = b.package_id")
    params: list = []
    if supervisor_id is not None:
        sql += " WHERE b.supervisor_id = ?"
        params.append(supervisor_id)
    sql += " ORDER BY b.id DESC LIMIT ?"
    params.append(limit)
    result = []
    for r in db.execute(sql, params).fetchall():
        try:
            content = json.loads(dec(r["content_enc"], "berita_acara.content"))
        except ValueError:
            content = {}
        result.append({
            "id": r["id"], "package_id": r["package_id"], "username": r["username"],
            "created_at": r["created_at"], "exam_name": dec(r["exam_name_enc"], "packages.exam_name"),
            "ruangan": content.get("ruangan", ""), "hadir": content.get("hadir", 0),
            "tidak_hadir": content.get("tidak_hadir", 0), "catatan": content.get("catatan", ""),
        })
    return result


# ----------------------------- Kunci jawaban ----------------------------------
def save_answer_key(db, title: str, ciphertext: str, user_id: int) -> int:
    cur = db.execute(
        "INSERT INTO answer_keys(title_enc, cipher_enc, created_by, created_at) VALUES (?,?,?,?)",
        (enc(title, "answer_keys.title"), enc(ciphertext, "answer_keys.cipher"), user_id, utcnow_iso()),
    )
    return cur.lastrowid


def list_answer_keys(db) -> list[dict]:
    rows = db.execute("SELECT id, title_enc, created_at FROM answer_keys ORDER BY id DESC").fetchall()
    return [{"id": r["id"], "title": dec(r["title_enc"], "answer_keys.title"), "created_at": r["created_at"]}
            for r in rows]


def get_answer_key(db, key_id):
    r = db.execute("SELECT id, title_enc, cipher_enc FROM answer_keys WHERE id = ?", (key_id,)).fetchone()
    if r is None:
        return None
    return {"id": r["id"], "title": dec(r["title_enc"], "answer_keys.title"),
            "ciphertext": dec(r["cipher_enc"], "answer_keys.cipher")}

# ------------------------ Template wajah (terenkripsi) -----------------------
def get_face_template(db, user_id):
    row = db.execute('SELECT template_enc FROM face_templates WHERE user_id = ?', (user_id,)).fetchone()
    return decrypt_field(row['template_enc'], 'face_templates.template') if row else None


def save_face_template(db, user_id, template):
    db.execute('INSERT INTO face_templates(user_id,template_enc,created_at) VALUES (?,?,?) '
               'ON CONFLICT(user_id) DO UPDATE SET template_enc=excluded.template_enc, created_at=excluded.created_at',
               (user_id, enc(template, 'face_templates.template'), utcnow_iso()))
