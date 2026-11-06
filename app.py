"""Secure Exam Distribution Vault - aplikasi Flask utama (semua route)."""
import hashlib
import io
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import click
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.utils import secure_filename

import auth
import blockchain
import config
import database
import dongle
import file_crypto
import face_auth
import steganography
from crypto_core import CryptoError, super_decrypt, super_encrypt
from file_crypto import FileCryptoError
from steganography import StegoError

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    MAX_CONTENT_LENGTH=(config.MAX_UPLOAD_MB + 5) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=config.SESSION_MINUTES),
)
app.teardown_appcontext(database.close_db)

PID_RE = re.compile(r"^[0-9a-f]{12}$")
KNOWN_ERRORS = (CryptoError, FileCryptoError, StegoError, dongle.DongleError, face_auth.FaceError)


def bootstrap() -> None:
    database.init_db()
    steganography.ensure_logo(config.LOGO_PATH)
    if config.SEED_DEMO:
        for line in auth.seed_demo_users():
            print(line)


bootstrap()


# ------------------------------ Util & hooks ---------------------------------
def fail(message: str, status: int = 400):
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=message), status
    return render_template("error.html", code=status, message=message), status


@app.before_request
def load_context():
    g.user = None
    uid = session.get("uid")
    if uid:
        user = database.get_user(database.get_db(), uid)
        if user is None:
            session.clear()
        else:
            g.user = user
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        if not auth.check_csrf(supplied):
            return fail("Token CSRF tidak valid. Muat ulang halaman lalu coba lagi.", 403)


@app.context_processor
def inject_globals():
    return {
        "current_user": g.get("user"),
        "csrf_token": auth.csrf_token(),
        "demo_enabled": config.DEMO_ENABLED,
        "webauthn_available": dongle.WEBAUTHN_AVAILABLE and config.WEBAUTHN_ENABLED,
        "demo_token_download": config.DEMO_TOKEN_DOWNLOAD,
    }


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/") or request.path.startswith("/packages/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def handle_known(exc):
    return fail(str(exc), 400)


for _exc in KNOWN_ERRORS:
    app.register_error_handler(_exc, handle_known)


@app.errorhandler(401)
def err_401(_e):
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error="Sesi berakhir. Silakan login kembali."), 401
    return redirect(url_for("login_page"))


@app.errorhandler(403)
def err_403(_e):
    return fail("Anda tidak memiliki akses ke halaman ini.", 403)


@app.errorhandler(404)
def err_404(_e):
    return fail("Halaman tidak ditemukan.", 404)


@app.errorhandler(413)
def err_413(_e):
    return fail(f"Ukuran unggahan melebihi batas {config.MAX_UPLOAD_MB} MB.", 413)


@app.errorhandler(500)
def err_500(_e):
    return fail("Terjadi kesalahan pada server.", 500)


def log(action: str, detail: str = "") -> None:
    database.add_log(database.get_db(), g.user["id"], action, f"{detail} | ip={request.remote_addr}".strip(" |"))


def file_response(data: bytes, name: str, mimetype: str | None = None):
    if mimetype is None:
        mimetype = {
            "pdf": "application/pdf",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "kgp": "application/octet-stream",
            "png": "image/png",
        }.get(name.rsplit(".", 1)[-1].lower(), "application/octet-stream")
    resp = send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=name)
    resp.headers["X-Filename"] = quote(name)
    return resp


def parse_available_from(value) -> str:
    if not value:
        return database.utcnow_iso()
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Format waktu rilis tidak valid.") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cover_image():
    upload = request.files.get("cover")
    if upload and upload.filename:
        return steganography.load_image(upload.read())
    return steganography.load_image(config.LOGO_PATH.read_bytes())


# ---------------------------- Halaman & login ---------------------------------
@app.get("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login_page"))


@app.get("/login")
def login_page():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.get("/verify-face")
def verify_face_page():
    user = auth.pending_user(database.get_db())
    if not user or not database.get_face_template(database.get_db(), user["id"]):
        return redirect(url_for("login_page"))
    return render_template("face_verify.html", username=user["username"])


@app.get("/verify-dongle")
def verify_dongle_page():
    user = auth.pending_user(database.get_db())
    if not user:
        return redirect(url_for("login_page"))
    if database.get_face_template(database.get_db(), user["id"]) and not session.get("face_ok"):
        return redirect(url_for("verify_face_page"))
    return render_template("dongle_verify.html", username=user["username"])


@app.get("/activate-face")
def activate_face_page():
    user = auth.pending_user(database.get_db())
    if not user or not session.get("dongle_ok") or database.get_face_template(database.get_db(), user["id"]):
        return redirect(url_for("login_page"))
    return render_template("face_enroll.html", username=user["username"])


@app.post("/api/face/enroll")
def api_face_enroll():
    db = database.get_db()
    user = auth.pending_user(db)
    if not user or not session.get("dongle_ok"):
        abort(401)
    if database.get_face_template(db, user["id"]):
        return fail("Wajah sudah terdaftar; perubahan memerlukan prosedur reset admin.", 403)
    payload = request.get_json(silent=True) or {}
    try:
        auth.validate_password_strength(str(payload.get("new_password", "")))
    except ValueError as exc:
        return fail(str(exc), 400)
    template = face_auth.enroll(payload.get("frames"))
    database.update_password_hash(db, user["id"], auth.hash_password(payload["new_password"]))
    database.save_face_template(db, user["id"], template)
    database.add_log(db, user["id"], "FACE_ENROLL", "Aktivasi biometrik webcam")
    session["face_ok"] = True
    return _finish_login(user)


@app.post("/api/face/verify")
def api_face_verify():
    db = database.get_db()
    user = auth.pending_user(db)
    if not user:
        abort(401)
    template = database.get_face_template(db, user["id"])
    if not template:
        return fail("Wajah belum didaftarkan. Lakukan aktivasi dengan dongle.", 403)
    frame = (request.get_json(silent=True) or {}).get("frame")
    if auth.is_locked(user):
        return fail("Akun dikunci sementara akibat percobaan gagal.", 423)
    if not face_auth.verify(template, frame):
        auth.register_failure(db, user)
        return fail("Wajah tidak cocok. Pastikan pencahayaan dan posisi kamera sesuai.", 401)
    session["face_ok"] = True
    return jsonify(ok=True, redirect=url_for("verify_dongle_page"))



@app.post("/api/login/password")
def api_login_password():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()[:64]
    password = str(data.get("password", ""))[:256]
    db = database.get_db()
    user = database.get_user_by_username(db, username)
    if user and auth.is_locked(user):
        return fail("Akun terkunci sementara karena terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.", 423)
    if not auth.verify_password(password, user["password_hash"] if user else None) or user is None:
        if user:
            auth.register_failure(db, user)
        return fail("Username atau password salah.", 401)
    if auth.needs_rehash(user["password_hash"]):
        database.update_password_hash(db, user["id"], auth.hash_password(password))
    session.pop("face_ok", None)
    session.pop("dongle_ok", None)
    auth.start_pending(user)
    has_webauthn = bool(database.list_webauthn_credentials(db, user["id"]))
    factors = {
        "demo": config.DEMO_ENABLED,
        "webauthn": dongle.WEBAUTHN_AVAILABLE and config.WEBAUTHN_ENABLED and has_webauthn,
    }
    if not any(factors.values()):
        return fail("Belum ada faktor kedua yang tersedia. Aktifkan mode demo untuk pendaftaran awal.", 403)
    registered = bool(database.get_face_template(db, user["id"]))
    return jsonify(ok=True, factors=factors, username=user["username"],
                   redirect=url_for("verify_face_page" if registered else "verify_dongle_page"),
                   activation_required=not registered)


def _finish_login(user):
    db = database.get_db()
    auth.clear_failures(db, user)
    auth.complete_login(user)
    database.add_log(db, user["id"], "LOGIN", f"ip={request.remote_addr}")
    return jsonify(ok=True, redirect=url_for("dashboard"))


@app.get("/api/login/dongle/demo-token")
def api_demo_token():
    user = auth.pending_user(database.get_db())
    if user is None:
        abort(401)
    if not (config.DEMO_ENABLED and config.DEMO_TOKEN_DOWNLOAD):
        abort(403)
    payload = dongle.demo_token_payload(user["username"], database.get_dongle_secret(user))
    resp = jsonify(payload)
    resp.headers["Content-Disposition"] = f'attachment; filename="{user["username"]}.dongle.json"'
    return resp


@app.post("/api/login/dongle/challenge")
def api_dongle_challenge():
    db = database.get_db()
    user = auth.pending_user(db)
    if user is None:
        abort(401)
    if database.get_face_template(db, user["id"]) and not session.get("face_ok"):
        return fail("Selesaikan verifikasi wajah dahulu.", 403)
    if not config.DEMO_ENABLED:
        return fail("Mode dongle demo dinonaktifkan.", 403)
    challenge = dongle.new_challenge()
    database.store_challenge(db, user["id"], "dongle", challenge)
    return jsonify(ok=True, challenge=challenge, username=user["username"], ttl=config.CHALLENGE_TTL_SECONDS)


@app.post("/api/login/dongle/verify")
def api_dongle_verify():
    db = database.get_db()
    user = auth.pending_user(db)
    if user is None:
        abort(401)
    if auth.is_locked(user):
        return fail("Akun dikunci sementara akibat percobaan gagal.", 423)
    response = str((request.get_json(silent=True) or {}).get("response", ""))
    challenge = database.pop_challenge(db, user["id"], "dongle")
    if challenge is None:
        return fail("Challenge kedaluwarsa atau sudah dipakai. Ulangi verifikasi.", 400)
    if not dongle.verify_response(database.get_dongle_secret(user), challenge, user["username"], response):
        auth.register_failure(db, user)
        return fail("Respons dongle tidak valid.", 401)
    if database.get_face_template(db, user["id"]):
        if not session.get("face_ok"):
            return fail("Verifikasi wajah wajib dilakukan sebelum dongle.", 403)
        return _finish_login(user)
    session["dongle_ok"] = True
    return jsonify(ok=True, redirect=url_for("activate_face_page"))


@app.post("/api/login/webauthn/options")
def api_webauthn_login_options():
    db = database.get_db()
    user = auth.pending_user(db)
    if user is None:
        abort(401)
    if database.get_face_template(db, user["id"]) and not session.get("face_ok"):
        return fail("Selesaikan verifikasi wajah dahulu.", 403)
    creds = database.list_webauthn_credentials(db, user["id"])
    if not creds:
        return fail("Belum ada perangkat WebAuthn terdaftar untuk akun ini.", 400)
    options_json, challenge = dongle.webauthn_authentication_options([c["credential_id"] for c in creds])
    database.store_challenge(db, user["id"], "webauthn_auth", challenge)
    return app.response_class(options_json, mimetype="application/json")


@app.post("/api/login/webauthn/verify")
def api_webauthn_login_verify():
    db = database.get_db()
    user = auth.pending_user(db)
    if user is None:
        abort(401)
    if auth.is_locked(user):
        return fail("Akun dikunci sementara akibat percobaan gagal.", 423)
    credential = request.get_json(silent=True) or {}
    challenge = database.pop_challenge(db, user["id"], "webauthn_auth")
    if challenge is None:
        return fail("Challenge kedaluwarsa. Ulangi verifikasi.", 400)
    row = next((c for c in database.list_webauthn_credentials(db, user["id"])
                if c["credential_id"] == credential.get("id")), None)
    if row is None:
        auth.register_failure(db, user)
        return fail("Perangkat tidak terdaftar untuk akun ini.", 401)
    try:
        new_count = dongle.webauthn_verify_authentication(credential, challenge, row["public_key"], row["sign_count"])
    except dongle.DongleError:
        auth.register_failure(db, user)
        raise
    database.update_sign_count(db, row["id"], new_count)
    if database.get_face_template(db, user["id"]):
        if not session.get("face_ok"):
            return fail("Verifikasi wajah wajib dilakukan sebelum perangkat.", 403)
        return _finish_login(user)
    session["dongle_ok"] = True
    return jsonify(ok=True, redirect=url_for("activate_face_page"))


@app.post("/logout")
@auth.login_required
def logout():
    log("LOGOUT")
    session.clear()
    return redirect(url_for("login_page"))


# ----------------------- Pendaftaran WebAuthn (sudah login) -------------------
@app.post("/api/webauthn/register/options")
@auth.login_required
def api_webauthn_register_options():
    db = database.get_db()
    existing = [c["credential_id"] for c in database.list_webauthn_credentials(db, g.user["id"])]
    options_json, challenge = dongle.webauthn_registration_options(
        g.user["id"], g.user["username"], g.user["full_name"], existing)
    database.store_challenge(db, g.user["id"], "webauthn_reg", challenge)
    return app.response_class(options_json, mimetype="application/json")


@app.post("/api/webauthn/register/verify")
@auth.login_required
def api_webauthn_register_verify():
    db = database.get_db()
    challenge = database.pop_challenge(db, g.user["id"], "webauthn_reg")
    if challenge is None:
        return fail("Challenge kedaluwarsa. Ulangi pendaftaran.", 400)
    result = dongle.webauthn_verify_registration(request.get_json(silent=True) or {}, challenge)
    database.add_webauthn_credential(db, g.user["id"], result["credential_id"], result["public_key"],
                                     result["sign_count"])
    log("WEBAUTHN_REGISTER")
    return jsonify(ok=True)


# --------------------------------- Dashboard -----------------------------------
@app.get("/dashboard")
@auth.login_required
def dashboard():
    return redirect(url_for("pusat_page" if g.user["role"] == "pusat" else "pengawas_page"))


@app.get("/pusat")
@auth.role_required("pusat")
def pusat_page():
    db = database.get_db()
    packages = database.list_packages(db)
    reports = database.list_berita_acara(db)
    chain_len = len(blockchain.get_chain(db))
    return render_template(
        "dashboard_pusat.html", packages=packages, reports=reports,
        logs=database.list_logs(db, limit=40), keys=database.list_answer_keys(db), chain_len=chain_len,
        webauthn_count=len(database.list_webauthn_credentials(db, g.user["id"])),
    )


@app.get("/pusat/pengguna")
@auth.role_required("pusat")
def daftar_pengawas():
    users = database.get_db().execute("SELECT id, username, role, created_at FROM users ORDER BY id DESC").fetchall()
    return render_template("manage_users.html", users=users)


@app.post("/pusat/pengguna")
@auth.role_required("pusat")
def tambah_pengawas():
    username = request.form.get("username", "").strip().lower()
    name = request.form.get("name", "").strip()
    password = request.form.get("password", "")
    if not 3 <= len(name) <= 100:
        flash("Nama Pengawas harus berisi 3–100 karakter.", "error")
        return redirect(url_for("daftar_pengawas"))
    try:
        auth.create_user(database.get_db(), username, password, "pengawas", name)
    except (ValueError, database.sqlite3.IntegrityError) as exc:
        flash("Gagal membuat akun: " + str(exc), "error")
        return redirect(url_for("daftar_pengawas"))
    log("CREATE_SUPERVISOR", f"username={username}")
    flash(f"Pengawas {username} dibuat. Token disiapkan di instance/demo_dongles/{username}.dongle.json; berikan secara aman.", "ok")
    return redirect(url_for("daftar_pengawas"))


@app.get("/pengawas")
@auth.role_required("pengawas")
def pengawas_page():
    db = database.get_db()
    return render_template(
        "dashboard_pengawas.html", packages=database.list_packages(db),
        reports=database.list_berita_acara(db, supervisor_id=g.user["id"]),
        logs=database.list_logs(db, user_id=g.user["id"], limit=30),
        webauthn_count=len(database.list_webauthn_credentials(db, g.user["id"])),
    )


@app.post("/pengawas/berita-acara")
@auth.role_required("pengawas")
def berita_acara_submit():
    db = database.get_db()
    package_id = request.form.get("package_id", "")
    ruangan = request.form.get("ruangan", "").strip()
    catatan = request.form.get("catatan", "").strip()
    try:
        hadir, tidak_hadir = int(request.form.get("hadir", "")), int(request.form.get("tidak_hadir", ""))
    except ValueError:
        flash("Jumlah peserta harus berupa angka.", "error")
        return redirect(url_for("pengawas_page"))
    if not PID_RE.match(package_id) or database.get_package(db, package_id) is None:
        flash("Paket soal tidak valid.", "error")
    elif not (1 <= len(ruangan) <= 60) or len(catatan) > 2000 or not (0 <= hadir <= 10000) \
            or not (0 <= tidak_hadir <= 10000):
        flash("Data berita acara tidak valid (ruangan 1-60 karakter, catatan maks 2000 karakter).", "error")
    else:
        database.add_berita_acara(db, package_id, g.user["id"], {
            "ruangan": ruangan, "hadir": hadir, "tidak_hadir": tidak_hadir, "catatan": catatan})
        log("BERITA_ACARA", f"paket={package_id} ruangan={ruangan}")
        flash("Berita acara tersimpan (terenkripsi).", "ok")
    return redirect(url_for("pengawas_page"))


# ------------------------------ Super Enkripsi Teks -----------------------------
@app.get("/text-crypto")
@auth.role_required("pusat")
def text_crypto_page():
    return render_template("text_crypto.html", keys=database.list_answer_keys(database.get_db()))


def _json_fields(*names, max_len=200_000):
    data = request.get_json(silent=True) or {}
    values = []
    for name in names:
        value = data.get(name, "")
        if not isinstance(value, str) or len(value) > max_len:
            raise CryptoError("Input tidak valid atau terlalu panjang.")
        values.append(value)
    return values


@app.post("/api/text/encrypt")
@auth.role_required("pusat")
def api_text_encrypt():
    text, vkey, passphrase, title = _json_fields("text", "vigenere_key", "passphrase", "title")
    result = super_encrypt(text, vkey, passphrase)
    saved_id = None
    if title.strip():
        saved_id = database.save_answer_key(database.get_db(), title.strip()[:120], result["ciphertext"],
                                            g.user["id"])
        log("SAVE_ANSWER_KEY", f"id={saved_id}")
    log("TEXT_ENCRYPT", f"panjang={len(text)}")
    return jsonify(ok=True, layer1=result["layer1"], ciphertext=result["ciphertext"], saved_id=saved_id)


@app.post("/api/text/decrypt")
@auth.role_required("pusat")
def api_text_decrypt():
    token, vkey, passphrase = _json_fields("ciphertext", "vigenere_key", "passphrase")
    result = super_decrypt(token, vkey, passphrase)
    log("TEXT_DECRYPT")
    return jsonify(ok=True, layer1=result["layer1"], plaintext=result["plaintext"])


@app.get("/api/text/keys/<int:key_id>")
@auth.role_required("pusat")
def api_text_key(key_id):
    key = database.get_answer_key(database.get_db(), key_id)
    if key is None:
        return fail("Kunci jawaban tidak ditemukan.", 404)
    return jsonify(ok=True, **key)


# ------------------------------- Enkripsi File Soal ------------------------------
@app.get("/file-crypto")
@auth.login_required
def file_crypto_page():
    return render_template("file_crypto.html")


@app.post("/api/files/release")
@auth.role_required("pusat")
def api_release():
    exam_name = request.form.get("exam_name", "").strip()
    if not 3 <= len(exam_name) <= 120:
        return fail("Nama ujian harus 3-120 karakter.")
    upload = request.files.get("exam_file")
    if not upload or not upload.filename:
        return fail("Berkas naskah soal wajib diunggah.")
    try:
        available_from = parse_available_from(request.form.get("available_from"))
    except ValueError as exc:
        return fail(str(exc))
    original = secure_filename(upload.filename)
    data = upload.read()
    file_crypto.validate_exam_file(original, data)
    cover = cover_image()

    token = secrets.token_urlsafe(24)  # token dekripsi: hanya ada di dalam gambar stego
    enc_blob = file_crypto.encrypt_file(data, original, token)
    stego_png = steganography.image_to_png_bytes(steganography.embed_message(cover, token.encode("ascii")))

    pid = secrets.token_hex(6)
    enc_name, stego_name = f"{pid}.kgp", f"{pid}.png"
    enc_sha, stego_sha = hashlib.sha256(enc_blob).hexdigest(), hashlib.sha256(stego_png).hexdigest()
    (config.PACKAGE_DIR / enc_name).write_bytes(enc_blob)
    (config.PACKAGE_DIR / stego_name).write_bytes(stego_png)

    db = database.get_db()
    try:
        with database.transaction(db):
            block = blockchain.add_block(db, {
                "type": "RELEASE", "package_id": pid,
                "exam_name_sha256": hashlib.sha256(exam_name.encode("utf-8")).hexdigest(),
                "encrypted_sha256": enc_sha, "stego_sha256": stego_sha,
                "released_by": g.user["username"], "available_from": available_from,
            })
            database.insert_package(db, {
                "id": pid, "exam_name": exam_name, "original_name": original, "encrypted_sha256": enc_sha,
                "stego_sha256": stego_sha, "enc_path": enc_name, "stego_path": stego_name,
                "released_by": g.user["id"], "released_at": database.utcnow_iso(),
                "available_from": available_from, "block_index": block["index"],
            })
    except Exception:
        (config.PACKAGE_DIR / enc_name).unlink(missing_ok=True)
        (config.PACKAGE_DIR / stego_name).unlink(missing_ok=True)
        raise
    log("RELEASE_PACKAGE", f"paket={pid} blok={block['index']}")
    return jsonify(ok=True, package_id=pid, block_index=block["index"], block_hash=block["hash"],
                   encrypted_sha256=enc_sha, stego_sha256=stego_sha, available_from=available_from)


@app.post("/api/files/encrypt")
@auth.role_required("pusat")
def api_file_encrypt():
    upload = request.files.get("file")
    passphrase = request.form.get("passphrase", "")
    if not upload or not upload.filename:
        return fail("Pilih berkas PDF/DOCX.")
    name = secure_filename(upload.filename)
    blob = file_crypto.encrypt_file(upload.read(), name, passphrase)
    log("FILE_ENCRYPT", f"nama={name}")
    return file_response(blob, f"{name}.kgp", "application/octet-stream")


@app.post("/api/files/decrypt")
@auth.login_required
def api_file_decrypt():
    kgp = request.files.get("kgp_file")
    if not kgp or not kgp.filename:
        return fail("Pilih berkas .kgp.")
    passphrase = request.form.get("passphrase", "").strip()
    stego = request.files.get("stego_image")
    if not passphrase:
        if not (stego and stego.filename):
            return fail("Isi token atau unggah gambar stego Logo UPN yang berisi token.")
        passphrase = steganography.extract_message(steganography.load_image(stego.read())).decode("utf-8", "replace")
    name, data = file_crypto.decrypt_file(kgp.read(), passphrase)
    log("FILE_DECRYPT", f"nama={name}")
    return file_response(data, name)


@app.get("/packages/<pid>/download/<kind>")
@auth.login_required
def package_download(pid, kind):
    if not PID_RE.match(pid) or kind not in ("enc", "stego"):
        abort(404)
    pkg = database.get_package(database.get_db(), pid)
    if pkg is None:
        abort(404)
    if g.user["role"] == "pengawas" and not pkg["available"]:
        return fail("Paket ini belum dirilis untuk pengawas (belum mencapai waktu rilis).", 403)
    rel = pkg["enc_path"] if kind == "enc" else pkg["stego_path"]
    path = config.PACKAGE_DIR / rel
    if not path.is_file():
        abort(404)
    log("DOWNLOAD_PACKAGE", f"paket={pid} jenis={kind}")
    download_name = f"paket_{pid}.kgp" if kind == "enc" else f"logo_upn_{pid}.png"
    return send_file(path, as_attachment=True, download_name=download_name)


# -------------------------------- Steganografi ----------------------------------
@app.get("/stego")
@auth.login_required
def stego_page():
    logo = steganography.load_image(config.LOGO_PATH.read_bytes())
    return render_template("stego.html", capacity=steganography.capacity_bytes(logo),
                           logo_size=f"{logo.width}x{logo.height}")


@app.post("/api/stego/embed")
@auth.role_required("pusat")
def api_stego_embed():
    message = request.form.get("message", "")
    if not message.strip():
        return fail("Pesan rahasia tidak boleh kosong.")
    img = steganography.embed_message(cover_image(), message.encode("utf-8"))
    log("STEGO_EMBED", f"panjang={len(message.encode('utf-8'))}")
    return file_response(steganography.image_to_png_bytes(img), "stego_logo_upn.png", "image/png")


@app.post("/api/stego/extract")
@auth.login_required
def api_stego_extract():
    upload = request.files.get("image")
    if not upload or not upload.filename:
        return fail("Pilih gambar stego (PNG).")
    message = steganography.extract_message(steganography.load_image(upload.read()))
    log("STEGO_EXTRACT", f"panjang={len(message)}")
    return jsonify(ok=True, message=message.decode("utf-8", "replace"), length=len(message))


# --------------------------------- Blockchain -----------------------------------
@app.get("/blockchain")
@auth.login_required
def blockchain_page():
    db = database.get_db()
    names = {p["id"]: p["exam_name"] for p in database.list_packages(db)}
    chain = blockchain.get_chain(db)
    for block in chain:
        block["exam_name"] = names.get(block["data"].get("package_id"), "")
    return render_template("blockchain.html", chain=list(reversed(chain)), verify=blockchain.verify_chain(db),
                           issues=blockchain.verify_packages(db))


@app.get("/api/blockchain/verify")
@auth.login_required
def api_blockchain_verify():
    db = database.get_db()
    result = blockchain.verify_chain(db)
    issues = blockchain.verify_packages(db)
    return jsonify(ok=True, valid=result["valid"] and not issues, length=result["length"],
                   errors=result["errors"] + issues)


# ----------------------------------- CLI ----------------------------------------
@app.cli.command("create-user")
@click.argument("username")
@click.option("--role", type=click.Choice(["pusat", "pengawas"]), required=True)
@click.option("--name", required=True, help="Nama lengkap")
@click.password_option()
def cli_create_user(username, role, name, password):
    """Buat akun baru: flask --app app create-user USERNAME --role pengawas --name "Nama"."""
    db = database.connect()
    try:
        auth.create_user(db, username, password, role, name)
    finally:
        db.close()
    click.echo(f"Akun '{username}' ({role}) dibuat.")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
