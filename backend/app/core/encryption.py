"""
OfSec V3 — Encryption Module
==============================
AES/Fernet data encryption for secrets and scan results.
"""

from cryptography.fernet import Fernet

from app.config import settings


# Derive a Fernet key from the secret (in production, use a proper KMS)
def _get_fernet() -> Fernet:
    """Get Fernet encryption instance from secret key."""
    import hashlib
    import base64
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    )
    return Fernet(key)


def encrypt_data(plaintext: str) -> str:
    """Encrypt a string and return base64-encoded ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    """Decrypt base64-encoded ciphertext and return plaintext."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()
