import base64
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.core.security import hash_password, verify_password


def _fernet() -> Fernet:
    if not settings.mfa_encryption_key:
        raise RuntimeError("MFA is not configured.")
    try:
        return Fernet(settings.mfa_encryption_key.encode())
    except (TypeError, ValueError) as exc:
        raise RuntimeError("MFA is not configured.") from exc


def is_configured() -> bool:
    """Return whether the server can safely encrypt authenticator secrets."""
    try:
        _fernet()
    except RuntimeError:
        return False
    return True


def new_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Stored MFA configuration is unavailable.") from exc


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="ScamShield AI")


def valid_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def new_recovery_codes(count: int = 8) -> list[str]:
    # 80 bits of entropy per code; rendered in a transcription-friendly alphabet.
    return [base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=") for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    return hash_password(code)


def valid_recovery_code(code: str, stored_hash: str) -> bool:
    return verify_password(code, stored_hash)
