
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


# -------------------- Dongle Fisik dan USB --------------------

NAMA_FILE = "artvault.key"
MAGIC = "ARTVAULT-DONGGLE"

# Registrasi lokal, tidak disinkronkan lewat Git.
FILE_DAFTAR = os.path.join(
    str(config.INSTANCE_DIR),
    "physical_dongles.json"
)

# Kompatibilitas dengan registrasi versi lama.
FILE_LAMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dongle.json"
)

HANYA_REMOVABLE = getattr(
    config, "DONGGLE_HANYA_REMOVABLE", True
)
LOKASI_TAMBAHAN = getattr(
    config, "DONGGLE_LOKASI_TAMBAHAN", []
)
CACHE_DETIK = getattr(
    config, "DONGGLE_CACHE_DETIK", 2
)

_cache = {"waktu": 0.0, "hasil": None}


def lokasi_drive():
    """Daftar folder akar drive eksternal."""
    hasil = []

    if os.name == "nt":
        import ctypes
        kernel = ctypes.windll.kernel32
        bitmask = kernel.GetLogicalDrives()

        for i, huruf in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                akar = huruf + ":\\"
                tipe = kernel.GetDriveTypeW(akar)

                if tipe == 2 or (
                    not HANYA_REMOVABLE
                    and tipe == 3
                    and huruf != "C"
                ):
                    hasil.append(akar)
    else:
        for dasar in (
            "/media",
            "/run/media",
            "/Volumes",
            "/mnt",
        ):
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
    """Nomor seri partisi Windows. OS lain: None."""
    if os.name != "nt":
        return None

    import ctypes

    drive = os.path.splitdrive(
        os.path.abspath(lokasi)
    )[0]

    if not drive:
        return None

    serial = ctypes.c_uint32(0)

    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive + "\\"),
        None,
        0,
        ctypes.byref(serial),
        None,
        None,
        None,
        0,
    )

    return "%08X" % serial.value if ok else None


def hitung_hash_fisik(token, serial):
    data = "%s|%s" % (token, serial or "")
    return hashlib.sha256(data.encode()).hexdigest()


def _baca_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def baca_pendaftaran():
    """
    Baca daftar hash dongle sah.
    Kompatibel dengan format tunggal versi lama.
    """
    data = _baca_json(FILE_DAFTAR)

    if data is None:
        # Migrasi otomatis sekali dari dongle.json lama.
        data = _baca_json(FILE_LAMA)

        if data is None:
            return []

        if (
            isinstance(data, dict)
            and isinstance(data.get("hash"), str)
        ):
            data = {
                "version": 2,
                "dongles": [
                    {
                        "hash": data["hash"],
                        "pakai_serial": bool(
                            data.get("pakai_serial")
                        ),
                    }
                ],
            }

            _simpan_pendaftaran(data)

    if (
        isinstance(data, dict)
        and isinstance(data.get("hash"), str)
    ):
        return [
            {
                "hash": data["hash"],
                "pakai_serial": bool(
                    data.get("pakai_serial")
                ),
            }
        ]

    if (
        isinstance(data, dict)
        and isinstance(data.get("dongles"), list)
    ):
        return [
            d
            for d in data["dongles"]
            if (
                isinstance(d, dict)
                and isinstance(d.get("hash"), str)
                and len(d["hash"]) == 64
            )
        ]

    return []


def _simpan_pendaftaran(data):
    os.makedirs(
        os.path.dirname(FILE_DAFTAR),
        exist_ok=True,
    )

    import tempfile

    fd, tmp = tempfile.mkstemp(
        prefix="dongles-",
        suffix=".tmp",
        dir=os.path.dirname(FILE_DAFTAR),
    )

    try:
        with os.fdopen(
            fd, "w", encoding="utf-8"
        ) as f:
            json.dump(data, f, indent=2)

        os.replace(tmp, FILE_DAFTAR)

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def baca_token(lokasi):
    """Baca token artvault.key dari flashdisk."""
    try:
        path = os.path.join(lokasi, NAMA_FILE)

        with open(
            path, "r", encoding="utf-8"
        ) as f:
            baris = [
                b.strip()
                for b in f.read().splitlines()
                if b.strip()
            ]

        if (
            len(baris) >= 2
            and baris[0] == MAGIC
        ):
            return baris[1]

    except (OSError, UnicodeDecodeError):
        pass

    return None


def daftarkan(lokasi, pakai_serial=True):
    """
    Tambahkan dongle fisik ke daftar lokal
    tanpa menimpa dongle lain.
    """
    if not os.path.isdir(lokasi):
        raise RuntimeError(
            "Lokasi flashdisk tidak ditemukan"
        )

    if os.path.abspath(lokasi) not in [
        os.path.abspath(d)
        for d in lokasi_drive()
    ]:
        raise RuntimeError(
            "Pilih drive eksternal yang terdeteksi"
        )

    serial = (
        serial_volume(lokasi)
        if pakai_serial
        else None
    )

    if (
        pakai_serial
        and serial is None
        and os.name == "nt"
    ):
        raise RuntimeError(
            "Serial flashdisk tidak terbaca. "
            "Coba --tanpa-serial"
        )

    pakai_serial = serial is not None
    daftar = baca_pendaftaran()
    token_lama = baca_token(lokasi)

    if token_lama:
        h_lama = hitung_hash_fisik(
            token_lama, serial
        )

        if any(
            hmac.compare_digest(
                d["hash"], h_lama
            )
            and bool(
                d.get("pakai_serial")
            ) == pakai_serial
            for d in daftar
        ):
            return h_lama, serial

    # Jangan menimpa token dongle lain.
    if token_lama:
        raise RuntimeError(
            "artvault.key sudah ada tetapi belum "
            "terdaftar di laptop ini. "
            "Salin registrasi dari laptop asal "
            "secara aman atau gunakan flashdisk kosong."
        )

    token = secrets.token_hex(32)
    h = hitung_hash_fisik(token, serial)

    path = os.path.join(lokasi, NAMA_FILE)

    try:
        with open(
            path, "x", encoding="utf-8"
        ) as f:
            f.write(
                "%s\n%s\n" % (MAGIC, token)
            )

        daftar.append(
            {
                "hash": h,
                "pakai_serial": pakai_serial,
            }
        )

        _simpan_pendaftaran(
            {
                "version": 2,
                "dongles": daftar,
            }
        )

    except Exception:
        if os.path.exists(path):
            os.unlink(path)
        raise

    _cache["hasil"] = None

    return h, serial


def _periksa_fisik():
    daftar = baca_pendaftaran()

    if not daftar:
        return (
            False,
            "Belum ada dongle terdaftar. "
            "Jalankan: python buat_dongle.py",
            None,
        )

    ada_file = False

    for lokasi in lokasi_drive():
        token = baca_token(lokasi)

        if token is None:
            continue

        ada_file = True

        for d in daftar:
            serial = (
                serial_volume(lokasi)
                if d.get("pakai_serial")
                else None
            )

            if (
                d.get("pakai_serial")
                and serial is None
            ):
                continue

            if hmac.compare_digest(
                hitung_hash_fisik(
                    token, serial
                ),
                d["hash"],
            ):
                return (
                    True,
                    "Dongle terdaftar terdeteksi di %s"
                    % lokasi,
                    lokasi,
                )

    if ada_file:
        return (
            False,
            "Flashdisk terdeteksi, tetapi "
            "dongle belum terdaftar.",
            None,
        )

    return (
        False,
        "Dongle tidak ditemukan. "
        "Colokkan flashdisk terdaftar.",
        None,
    )


def cek(paksa=False):
    """
    Cek dongle fisik yang terpasang.
    Hasil: (ok, pesan, lokasi).
    """
    sekarang = time.time()

    if (
        not paksa
        and _cache["hasil"] is not None
        and sekarang - _cache["waktu"] < CACHE_DETIK
    ):
        return _cache["hasil"]

    hasil = _periksa_fisik()

    _cache["waktu"] = sekarang
    _cache["hasil"] = hasil

    return hasil


# ---------------- Challenge-Response Virtual ----------------

def new_dongle_secret() -> str:
    return secrets.token_hex(32)


def new_challenge() -> str:
    return secrets.token_hex(32)


def compute_response(
    secret_hex: str,
    challenge_hex: str,
    username: str,
) -> str:
    message = (
        f"KGP-DONGLE|{username}|{challenge_hex}"
    ).encode("utf-8")

    return hmac.new(
        bytes.fromhex(secret_hex),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_response(
    secret_hex: str,
    challenge_hex: str,
    username: str,
    response_hex: str,
) -> bool:
    try:
        expected = compute_response(
            secret_hex,
            challenge_hex,
            username,
        )
    except ValueError:
        return False

    return hmac.compare_digest(
        expected,
        str(response_hex).lower(),
    )


def write_demo_token(
    username: str,
    secret_hex: str,
) -> None:
    path = (
        config.DEMO_DONGLE_DIR
        / f"{username}.dongle.json"
    )

    path.write_text(
        json.dumps(
            demo_token_payload(
                username, secret_hex
            ),
            indent=2,
        ),
        encoding="utf-8",
    )


def demo_token_payload(
    username: str,
    secret_hex: str,
) -> dict:
    return {
        "type": "KGP-DEMO-DONGLE",
        "version": 1,
        "username": username,
        "secret": secret_hex,
        "note": (
            "Dongle virtual MODE DEMO. "
            "Jangan dipakai di produksi."
        ),
    }


# ---------------------- WebAuthn ----------------------

def _require_webauthn() -> None:
    if not (
        WEBAUTHN_AVAILABLE
        and config.WEBAUTHN_ENABLED
    ):
        raise DongleError(
            "WebAuthn tidak aktif "
            "(library 'webauthn' belum terpasang "
            "atau mode dinonaktifkan)."
        )


def _descriptors(credential_ids):
    return [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(c)
        )
        for c in credential_ids
    ]


def webauthn_registration_options(
    user_id: int,
    username: str,
    full_name: str,
    existing_ids,
) -> tuple[str, str]:
    _require_webauthn()

    options = generate_registration_options(
        rp_id=config.WEBAUTHN_RP_ID,
        rp_name=config.WEBAUTHN_RP_NAME,
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=full_name,
        authenticator_selection=(
            AuthenticatorSelectionCriteria(
                resident_key=(
                    ResidentKeyRequirement.DISCOURAGED
                ),
                user_verification=(
                    UserVerificationRequirement.REQUIRED
                ),
            )
        ),
        exclude_credentials=_descriptors(
            existing_ids
        ),
    )

    return (
        options_to_json(options),
        bytes_to_base64url(options.challenge),
    )


def webauthn_verify_registration(
    credential: dict,
    challenge_b64u: str,
) -> dict:
    _require_webauthn()

    try:
        result = verify_registration_response(
            credential=credential,
            expected_challenge=(
                base64url_to_bytes(challenge_b64u)
            ),
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )

    except Exception as exc:
        raise DongleError(
            f"Registrasi WebAuthn gagal: "
            f"{str(exc)[:160]}"
        ) from exc

    return {
        "credential_id": bytes_to_base64url(
            result.credential_id
        ),
        "public_key": bytes_to_base64url(
            result.credential_public_key
        ),
        "sign_count": result.sign_count,
    }


def webauthn_authentication_options(
    credential_ids,
) -> tuple[str, str]:
    _require_webauthn()

    options = generate_authentication_options(
        rp_id=config.WEBAUTHN_RP_ID,
        allow_credentials=_descriptors(
            credential_ids
        ),
        user_verification=(
            UserVerificationRequirement.REQUIRED
        ),
    )

    return (
        options_to_json(options),
        bytes_to_base64url(options.challenge),
    )


def webauthn_verify_authentication(
    credential: dict,
    challenge_b64u: str,
    public_key_b64u: str,
    sign_count: int,
) -> int:
    _require_webauthn()

    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=(
                base64url_to_bytes(challenge_b64u)
            ),
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            credential_public_key=(
                base64url_to_bytes(public_key_b64u)
            ),
            credential_current_sign_count=(
                sign_count
            ),
            require_user_verification=True,
        )

    except Exception as exc:
        raise DongleError(
            f"Verifikasi WebAuthn gagal: "
            f"{str(exc)[:160]}"
        ) from exc

    return result.new_sign_count
