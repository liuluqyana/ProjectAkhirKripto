"""Secure Exam Vault: lapisan database MariaDB/MySQL (XAMPP).

Menggantikan database.py SQLite tanpa mengubah antarmuka fungsi yang
sudah digunakan app.py, auth.py dan blockchain.py.

Sebelum menjalankan:
  1. Buat database `secure_exam_vault` di phpMyAdmin.
  2. pip install PyMySQL
  3. Atur KGP_DB_USER dan KGP_DB_PASSWORD sesuai akun database Anda.

Kunci enkripsi aplikasi tetap tersimpan di instance/master.key.
Database SQLite lama tidak dipindahkan otomatis.
"""
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import pymysql
from pymysql.cursors import DictCursor
from flask import g

import blockchain
import config
from crypto_core import CryptoError, decrypt_field, encrypt_field

# app.py lama masih menangkap database.sqlite3.IntegrityError.
# Pertahankan antarmuka tersebut dengan alias exception MariaDB.
sqlite3 = SimpleNamespace(IntegrityError=pymysql.err.IntegrityError)

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(32) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('pusat','pengawas') NOT NULL,
        full_name_enc LONGTEXT NOT NULL,
        dongle_secret_enc LONGTEXT NOT NULL,
        failed_attempts INT NOT NULL DEFAULT 0,
        locked_until BIGINT NULL,
        created_at VARCHAR(32) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS face_templates (
        user_id INT NOT NULL PRIMARY KEY,
        template_enc LONGTEXT NOT NULL,
        created_at VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        credential_id VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
        public_key LONGTEXT NOT NULL,
        sign_count BIGINT NOT NULL DEFAULT 0,
        created_at VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS auth_challenges (
        user_id INT NOT NULL,
        kind VARCHAR(40) NOT NULL,
        challenge LONGTEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        PRIMARY KEY (user_id,kind),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS blockchain (
        idx INT NOT NULL PRIMARY KEY,
        timestamp VARCHAR(32) NOT NULL,
        data_json LONGTEXT NOT NULL,
        prev_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS packages (
        id VARCHAR(128) NOT NULL PRIMARY KEY,
        exam_name_enc LONGTEXT NOT NULL,
        original_name_enc LONGTEXT NOT NULL,
        encrypted_sha256 CHAR(64) NOT NULL,
        stego_sha256 CHAR(64) NOT NULL,
        enc_path TEXT NOT NULL,
        stego_path TEXT NOT NULL,
        released_by INT NOT NULL,
        released_at VARCHAR(32) NOT NULL,
        available_from VARCHAR(32) NOT NULL,
        block_index INT NOT NULL,
        FOREIGN KEY (released_by) REFERENCES users(id),
        FOREIGN KEY (block_index) REFERENCES blockchain(idx)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS supervisor_logs (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        action_enc LONGTEXT NOT NULL,
        detail_enc LONGTEXT NOT NULL,
        created_at VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS berita_acara (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        package_id VARCHAR(128) NOT NULL,
        supervisor_id INT NOT NULL,
        content_enc LONGTEXT NOT NULL,
        created_at VARCHAR(32) NOT NULL,
        FOREIGN KEY (package_id) REFERENCES packages(id),
        FOREIGN KEY (supervisor_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS answer_keys (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        title_enc LONGTEXT NOT NULL,
        cipher_enc LONGTEXT NOT NULL,
        created_by INT NOT NULL,
        created_at VARCHAR(32) NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MariaConnection:
    """Adaptor untuk pola db.execute() yang sudah dipakai proyek SQLite."""

    def __init__(self, connection):
        self._connection = connection
        self.in_transaction = False

    def execute(self, sql, params=()):
        statement = sql.strip()
        command = statement.upper()
        if command == "BEGIN IMMEDIATE" or command == "BEGIN":
            self._connection.begin()
            self.in_transaction = True
            return None
        if command == "COMMIT":
            self._connection.commit()
            self.in_transaction = False
            return None
        if command == "ROLLBACK":
            self._connection.rollback()
            self.in_transaction = False
            return None
        # Semua '?' pada query proyek adalah parameter SQLite.
        # Pemakaian query tetap harus parameterized (bukan interpolasi string).
        statement = statement.replace("?", "%s")
        cursor = self._connection.cursor()
        try:
            cursor.execute(statement, params)
        except Exception:
            cursor.close()
            raise
        return cursor

    def close(self):
        self._connection.close()

    def commit(self):
        self.execute("COMMIT")

    def rollback(self):
        self.execute("ROLLBACK")


def connect() -> MariaConnection:
    try:
        raw = pymysql.connect(
            host=os.environ.get("KGP_DB_HOST", "127.0.0.1"),
            port=int(os.environ.get("KGP_DB_PORT", "3306")),
            user=os.environ.get("KGP_DB_USER", "root"),
            password=os.environ.get("KGP_DB_PASSWORD", ""),
            database=os.environ.get("KGP_DB_NAME", "secure_exam_vault"),
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=True,
            connect_timeout=10,
        )
    except pymysql.MySQLError as exc:
        raise RuntimeError(
            "Gagal terhubung ke MariaDB XAMPP. Pastikan MySQL aktif, "
            "database secure_exam_vault sudah dibuat, dan KGP_DB_USER/"
            "KGP_DB_PASSWORD benar."
        ) from exc
    return MariaConnection(raw)


def get_db() -> MariaConnection:
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
    db = connect()
    try:
        for sql in SCHEMA:
            cursor = db.execute(sql)
            cursor.close()
        blockchain.ensure_genesis(db)
    finally:
        db.close()


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
        "INSERT INTO auth_challenges(user_id, kind, challenge, expires_at) VALUES (?,?,?,?) "
        "ON DUPLICATE KEY UPDATE challenge=VALUES(challenge), expires_at=VALUES(expires_at)",
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
               'ON DUPLICATE KEY UPDATE template_enc=VALUES(template_enc), created_at=VALUES(created_at)',
               (user_id, enc(template, 'face_templates.template'), utcnow_iso()))
