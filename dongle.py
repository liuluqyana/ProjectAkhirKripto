"""Faktor kedua: WebAuthn (biometrik / USB security key FIDO2) dan
Challenge-Response dongle dengan MODE DEMO yang transparan.

MODE DEMO
---------
Perangkat USB fisik tidak selalu tersedia, maka "dongle virtual" dipakai:
* Tiap pengguna punya rahasia 256-bit (disimpan terenkripsi di database).
* Rahasia yang sama ada di berkas token demo (instance/demo_dongles/<user>.dongle.json).
* Login: server mengirim challenge acak sekali pakai; browser menghitung
  HMAC-SHA256(rahasia, "KGP-DONGLE|<user>|<challenge>") dan mengirim hasilnya.
  Rahasia tidak pernah dikirim lewat jaringan. Server memverifikasi dengan
  perbandingan waktu-konstan.
Token keras yang dapat menghitung HMAC yang sama dapat menggantikan berkas demo;
untuk perangkat FIDO2 asli gunakan jalur WebAuthn.
"""
import hashlib
import hmac
import json
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
except ImportError:  # library opsional; mode demo tetap berfungsi
    WEBAUTHN_AVAILABLE = False


class DongleError(Exception):
    """Kesalahan autentikasi perangkat."""


# --------------------------- Challenge-Response ----------------------------
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
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
        raise DongleError(f"Verifikasi WebAuthn gagal: {str(exc)[:160]}") from exc
    return result.new_sign_count
