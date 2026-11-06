"""Uji asap: python test_smoke.py  (memakai database sementara, iterasi KDF rendah)."""
import io
import json
import os
import re
import sqlite3
import tempfile

_tmp = tempfile.mkdtemp(prefix="kgp_test_")
os.environ.update(KGP_INSTANCE_DIR=_tmp, KGP_PBKDF2_ITERATIONS="2000", KGP_FILE_ITERATIONS="2000",
                  KGP_TEXT_ITERATIONS="2000")

import config  # noqa: E402
import crypto_core  # noqa: E402
import dongle  # noqa: E402
import file_crypto  # noqa: E402
import steganography  # noqa: E402
from app import app  # noqa: E402
import face_auth  # noqa: E402


def test_primitives():
    assert crypto_core.vigenere("Attack at Dawn!", "LEMON") == "Lxfopv ef Rnhr!"
    assert crypto_core.vigenere("Lxfopv ef Rnhr!", "LEMON", decrypt=True) == "Attack at Dawn!"
    out = crypto_core.super_encrypt("Kunci: 1-A, 2-C. Rubrik: 10 poin", "UPN", "passphrase-aes")
    back = crypto_core.super_decrypt(out["ciphertext"], "UPN", "passphrase-aes")
    assert back["plaintext"] == "Kunci: 1-A, 2-C. Rubrik: 10 poin"
    try:
        crypto_core.super_decrypt(out["ciphertext"], "UPN", "salah-salah")
        raise AssertionError("harus gagal")
    except crypto_core.CryptoError:
        pass
    blob = file_crypto.encrypt_file(b"%PDF-1.4 isi", "soal.pdf", "token-rahasia")
    assert blob[:4] == b"KGP2" and file_crypto.decrypt_file(blob, "token-rahasia") == ("soal.pdf", b"%PDF-1.4 isi")
    tampered = bytearray(blob); tampered[-1] ^= 1
    try:
        file_crypto.decrypt_file(bytes(tampered), "token-rahasia")
        raise AssertionError("harus gagal")
    except file_crypto.FileCryptoError:
        pass
    img = steganography.load_image(config.LOGO_PATH.read_bytes())
    png = steganography.image_to_png_bytes(steganography.embed_message(img, "tok3n-rahasia".encode()))
    assert steganography.extract_message(steganography.load_image(png)) == b"tok3n-rahasia"
    print("primitives OK")


class Session:
    def __init__(self):
        self.c = app.test_client()

    def csrf(self, path="/login"):
        html = self.c.get(path, follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)

    def login(self, user, pw):
        h = {"X-CSRF-Token": self.csrf()}
        r = self.c.post("/api/login/password", json={"username": user, "password": pw}, headers=h)
        assert r.status_code == 200, r.get_json()
        ch = self.c.post("/api/login/dongle/challenge", json={}, headers=h).get_json()
        tok = json.load(open(config.DEMO_DONGLE_DIR / f"{user}.dongle.json"))
        resp = dongle.compute_response(tok["secret"], ch["challenge"], user)
        r = self.c.post("/api/login/dongle/verify", json={"response": resp}, headers=h)
        assert r.status_code == 200 and r.get_json()["ok"], r.get_json()
        # Pada akun baru, aktifkan wajah sebelum dashboard. Uji integrasi memakai
        # mock ekstraksi citra; pengenalan wajah asli membutuhkan webcam nyata.
        import database
        db = database.connect()
        try:
            with app.app_context():
                row = database.get_user_by_username(db, user)
                has_face = database.get_face_template(db, row['id']) is not None
        finally:
            db.close()
        if not has_face:
            original = face_auth.enroll
            try:
                face_auth.enroll = lambda frames: '{"version":1,"samples":[]}'
                r = self.c.post('/api/face/enroll', json={
                    'frames':['demo']*5,
                    'new_password': pw if user != 'pusat' else 'Pusat#Vault2026'}, headers=h)
                assert r.status_code == 200, r.get_json()
            finally:
                face_auth.enroll = original
        self.h = {"X-CSRF-Token": self.csrf("/dashboard")}


def test_flow():
    # login gagal & anti-brute-force
    s0 = Session(); h0 = {"X-CSRF-Token": s0.csrf()}
    assert s0.c.post("/api/login/password", json={"username": "pusat", "password": "x"}, headers=h0).status_code == 401
    assert s0.c.post("/api/login/password", json={"username": "pusat", "password": "x"}, headers={}).status_code == 403

    pusat = Session(); pusat.login("pusat", "Pusat#Vault2026")
    pdf = b"%PDF-1.4\n%contoh naskah soal\n"
    r = pusat.c.post("/api/files/release", headers=pusat.h, content_type="multipart/form-data", data={
        "exam_name": "UTS Kriptografi", "exam_file": (io.BytesIO(pdf), "soal uts.pdf")})
    assert r.status_code == 200, r.get_data(as_text=True)
    pid = r.get_json()["package_id"]

    # teks super enkripsi + simpan
    r = pusat.c.post("/api/text/encrypt", headers=pusat.h, json={
        "text": "1.A 2.B", "vigenere_key": "KUNCI", "passphrase": "passphrase-aes", "title": "Kunci UTS"})
    cipher = r.get_json()["ciphertext"]
    r = pusat.c.post("/api/text/decrypt", headers=pusat.h, json={
        "ciphertext": cipher, "vigenere_key": "KUNCI", "passphrase": "passphrase-aes"})
    assert r.get_json()["plaintext"] == "1.A 2.B"

    # pengawas: unduh paket, ekstrak token dari stego, dekripsi
    pw = Session(); pw.login("pengawas1", "Pengawas#Vault2026")
    assert pw.c.get("/pusat").status_code == 403
    kgp = pw.c.get(f"/packages/{pid}/download/enc").data
    stego = pw.c.get(f"/packages/{pid}/download/stego").data
    r = pw.c.post("/api/stego/extract", headers=pw.h, content_type="multipart/form-data",
                  data={"image": (io.BytesIO(stego), "logo.png")})
    token = r.get_json()["message"]
    r = pw.c.post("/api/files/decrypt", headers=pw.h, content_type="multipart/form-data", data={
        "kgp_file": (io.BytesIO(kgp), "p.kgp"), "stego_image": (io.BytesIO(stego), "logo.png")})
    assert r.status_code == 200 and r.data == pdf, r.get_data(as_text=True)
    r = pw.c.post("/api/files/decrypt", headers=pw.h, content_type="multipart/form-data", data={
        "kgp_file": (io.BytesIO(kgp), "p.kgp"), "passphrase": token})
    assert r.data == pdf

    # berita acara terenkripsi
    r = pw.c.post("/pengawas/berita-acara", headers=pw.h, data={
        "package_id": pid, "ruangan": "R-101", "hadir": "30", "tidak_hadir": "2", "catatan": "Aman"})
    assert r.status_code == 302
    raw = sqlite3.connect(config.DB_PATH).execute("SELECT content_enc FROM berita_acara").fetchone()[0]
    assert raw.startswith("v1:") and "R-101" not in raw
    assert "R-101" in pusat.c.get("/pusat").get_data(as_text=True)
    for path in ("/pengawas", "/blockchain", "/stego", "/file-crypto"):
        assert pw.c.get(path).status_code == 200, path

    # blockchain valid lalu dirusak
    assert pusat.c.get("/api/blockchain/verify").get_json()["valid"] is True
    con = sqlite3.connect(config.DB_PATH)
    con.execute("UPDATE blockchain SET data_json = replace(data_json, 'pusat', 'penyusup') WHERE idx = 1")
    con.commit(); con.close()
    res = pusat.c.get("/api/blockchain/verify").get_json()
    assert res["valid"] is False and res["errors"], res
    print("flow OK; deteksi manipulasi:", res["errors"][0])


def test_webauthn_options():
    assert dongle.WEBAUTHN_AVAILABLE
    opts, ch = dongle.webauthn_registration_options(1, "pusat", "Admin", [])
    assert json.loads(opts)["challenge"] == ch
    print("webauthn options OK")


if __name__ == "__main__":
    test_primitives(); test_flow(); test_webauthn_options()
    print("SEMUA UJI LULUS")
