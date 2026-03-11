"""
OfSec V3 — Encryption Module
==============================
AES/Fernet data encryption for secrets and scan results.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings

STATIC_SALT = b"ofsec_vault_static_salt_v1"


# Derive a Fernet key from the secret (in production, use a proper KMS)
def _get_fernet() -> Fernet:
    """Get Fernet encryption instance from secret key."""
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_data(plaintext: str) -> str:
    """Encrypt a string and return base64-encoded ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    """Decrypt base64-encoded ciphertext and return plaintext."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()


def _derive_key(master_password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=STATIC_SALT,
        iterations=600_000,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode())


def encrypt_secret(plain_text: str, master_password: str) -> str:
    """Encrypt a secret string using AES-GCM and a master password."""
    key = _derive_key(master_password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_secret(cipher_text: str, master_password: str) -> str:
    """Decrypt an AES-GCM encrypted secret using the master password."""
    key = _derive_key(master_password)
    aesgcm = AESGCM(key)
    data = base64.b64decode(cipher_text.encode("utf-8"))
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
