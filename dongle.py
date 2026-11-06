"""
Faktor kedua: WebAuthn (biometrik / USB security key FIDO2) dan
Challenge-Response dongle fisik / virtual dengan dukungan pemindaian USB.
"""
import hashlib
import hmac
import json
import os
import string
import time
import secrets
import config

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    WEBAUTHN_AVAILABLE = True
except ImportError:  
    WEBAUTHN_AVAILABLE = False


class DongleError(Exception):
    """Kesalahan autentikasi perangkat atau dongle."""
    pass


# --------------------------- Pengaturan Dongle Fisik & USB ----------------------------
NAMA_FILE = "artvault.key"
MAGIC = "ARTVAULT-DONGGLE"
FILE_DAFTAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dongle.json")

HANYA_REMOVABLE = getattr(config, "DONGGLE_HANYA_REMOVABLE", True)
LOKASI_TAMBAHAN = getattr(config, "DONGGLE_LOKASI_TAMBAHAN", [])
CACHE_DETIK = getattr(config, "DONGGLE_CACHE_DETIK", 2)

_cache = {"waktu": 0.0, "hasil": None}


def lokasi_drive():
    """Daftar folder akar drive eksternal yang tercolok (flashdisk)."""
    hasil = []
    if os.name == "nt":                                        # Windows: E:\, F:\, ...
        import ctypes
        kernel = ctypes.windll.kernel32
        bitmask = kernel.GetLogicalDrives()
        for i, huruf in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                akar = huruf + ":\\"
                tipe = kernel.GetDriveTypeW(akar)              # 2 = removable, 3 = fixed
                if tipe == 2 or (not HANYA_REMOVABLE and tipe == 3 and huruf != "C"):
                    hasil.append(akar)
    else:                                                      # Linux / macOS
        for dasar in ("/media", "/run/media", "/Volumes", "/mnt"):
            if not os.path.isdir(dasar):
                continue
            for nama in sorted(os.listdir(dasar)):
                p1 = os.path.join(dasar, nama)
                if os.path.isdir(p1):
                    hasil.append(p1)
                    try:
                        for sub in sorted(os.listdir(p1)):
                            p2 = os.path.join(p1, sub)
                            if os.path.isdir(p2):
                                hasil.append(p2)
                    except OSError:
                        pass
    for p in LOKASI_TAMBAHAN:
        if os.path.isdir(p):
            hasil.append(p)
    return hasil


def serial_volume(lokasi):
    """Nomor seri partisi (Windows). Di OS lain: None."""
    if os.name != "nt":
        return None
    import ctypes
    drive = os.path.splitdrive(os.path.abspath(lokasi))[0]
    if not drive:
        return None
    serial = ctypes.c_uint32(0)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive + "\\"), None, 0, ctypes.byref(serial), None, None, None, 0)
    return "%08X" % serial.value if ok else None


def hitung_hash_fisik(token, serial):
    return hashlib.sha256(("%s|%s" % (token, serial or "")).encode()).hexdigest()


def baca_pendaftaran():
    """Isi donggle.json (hash donggle fisik yang sah) atau None."""
    try:
        with open(FILE_DAFTAR, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data.get("hash"), str):
            return data
    except (OSError, ValueError):
        pass
    return None


def baca_token(lokasi):
    """Baca token dari artvault.key di flashdisk."""
    try:
        with open(os.path.join(lokasi, NAMA_FILE), "r", encoding="utf-8") as f:
            baris = [b.strip() for b in f.read().splitlines() if b.strip()]
        if len(baris) >= 2 and baris[0] == MAGIC:
            return baris[1]
    except (OSError, UnicodeDecodeError):
        pass
    return None


def daftarkan(lokasi, pakai_serial=True):
    """
    Jadikan folder/drive 'lokasi' sebagai donggle fisik: tulis artvault.key, simpan hash di donggle.json.
    """
    token = secrets.token_hex(32)
    serial = serial_volume(lokasi) if pakai_serial else None
    if pakai_serial and serial is None and os.name == "nt":
        raise RuntimeError("Serial flashdisk tidak terbaca. Coba lagi atau pakai --tanpa-serial")
    pakai_serial = serial is not None

    with open(os.path.join(lokasi, NAMA_FILE), "w", encoding="utf-8") as f:
        f.write("%s\n%s\n" % (MAGIC, token))

    h = hitung_hash_fisik(token, serial)
    with open(FILE_DAFTAR, "w", encoding="utf-8") as f:
        json.dump({"hash": h, "pakai_serial": pakai_serial}, f, indent=2)
    return h, serial


def _periksa_fisik():
    daftar = baca_pendaftaran()
    if daftar is None:
        return False, "Donggle belum didaftarkan. Jalankan: python buat_donggle.py", None

    ada_file = False
    for lokasi in lokasi_drive():
        token = baca_token(lokasi)
        if token is None:
            continue
        ada_file = True
        serial = serial_volume(lokasi) if daftar.get("pakai_serial") else None
        if daftar.get("pakai_serial") and serial is None:
            continue
        if hmac.compare_digest(hitung_hash_fisik(token, serial), daftar["hash"]):
            return True, "Donggle terdeteksi di %s" % lokasi, lokasi

    if ada_file:
        return False, "Flashdisk terdeteksi, tetapi BUKAN donggle ArtVault yang sah.", None
    return False, "Donggle tidak ditemukan. Colokkan flashdisk donggle.", None


def cek(paksa=False):
    """
    Cek apakah donggle fisik sah sedang tercolok. Hasil: (ok, pesan, lokasi).
    """
    sekarang = time.time()
    if not paksa and _cache["hasil"] is not None and sekarang - _cache["waktu"] < CACHE_DETIK:
        return _cache["hasil"]
    hasil = _periksa_fisik()
    _cache["waktu"], _cache["hasil"] = sekarang, hasil
    return hasil


# --------------------------- Challenge-Response (Virtual / User Specific) ----------------------------
def new_dongle_secret() -> str:
    return secrets.token_hex(32)
    

def new_challenge() -> str:
    return secrets.token_hex(32)


def compute_response(secret_hex: str, challenge_hex: str, username: str) -> str:
    message = f"KGP-DONGLE|{username}|{challenge_hex}".encode("utf-8")
    return hmac.new(bytes.fromhex(secret_hex), message, hashlib.sha256).hexdigest()


def verify_response(secret_hex: str, challenge_hex: str, username: str, response_hex: str) -> bool:
    try:
        expected = compute_response(secret_hex, challenge_hex, username)
    except ValueError:
        return False
    return hmac.compare_digest(expected, str(response_hex).lower())


def write_demo_token(username: str, secret_hex: str) -> None:
    path = config.DEMO_DONGLE_DIR / f"{username}.dongle.json"
    path.write_text(json.dumps(demo_token_payload(username, secret_hex), indent=2), encoding="utf-8")


def demo_token_payload(username: str, secret_hex: str) -> dict:
    return {
        "type": "KGP-DEMO-DONGLE",
        "version": 1,
        "username": username,
        "secret": secret_hex,
        "note": "Dongle virtual MODE DEMO. Jangan dipakai di produksi.",
    }


# ------------------------------- WebAuthn ----------------------------------
def _require_webauthn() -> None:
    if not (WEBAUTHN_AVAILABLE and config.WEBAUTHN_ENABLED):
        raise DongleError("WebAuthn tidak aktif (library 'webauthn' belum terpasang atau mode dinonaktifkan).")


def _descriptors(credential_ids):
    return [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c)) for c in credential_ids]


def webauthn_registration_options(user_id: int, username: str, full_name: str, existing_ids) -> tuple[str, str]:
    _require_webauthn()
    options = generate_registration_options(
        rp_id=config.WEBAUTHN_RP_ID,
        rp_name=config.WEBAUTHN_RP_NAME,
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=full_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=_descriptors(existing_ids),
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def webauthn_verify_registration(credential: dict, challenge_b64u: str) -> dict:
    _require_webauthn()
    try:
        result = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64u),
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc: 
        raise DongleError(f"Registrasi WebAuthn gagal: {str(exc)[:160]}") from exc
    return {
        "credential_id": bytes_to_base64url(result.credential_id),
        "public_key": bytes_to_base64url(result.credential_public_key),
        "sign_count": result.sign_count,
    }


def webauthn_authentication_options(credential_ids) -> tuple[str, str]:
    _require_webauthn()
    options = generate_authentication_options(
        rp_id=config.WEBAUTHN_RP_ID,
        allow_credentials=_descriptors(credential_ids),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def webauthn_verify_authentication(credential: dict, challenge_b64u: str, public_key_b64u: str, sign_count: int) -> int:
    _require_webauthn()
    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64u),
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            credential_public_key=base64url_to_bytes(public_key_b64u),
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    except Exception as exc: 
        raise DongleError(f"Verifikasi WebAuthn gagal: {str(exc)[:160]}") from exc
    return result.new_sign_count