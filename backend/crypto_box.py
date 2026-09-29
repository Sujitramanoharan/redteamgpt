"""Encryption for secrets customers store with us (their upstream LLM keys).

A database dump alone must not reveal them, so they are encrypted with a key
that lives only in the environment (ENCRYPTION_KEY).
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from config import settings

logger = logging.getLogger(__name__)

_DEV_KEY = "development-only-key-never-use-in-production"


def _fernet() -> Fernet:
    secret = settings.encryption_key or _DEV_KEY
    # Fernet wants exactly 32 url-safe base64 bytes; derive them so operators
    # can use any long random string (Render's generated values, for one).
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        # Almost always a rotated ENCRYPTION_KEY: the stored secret is now
        # unreadable and the customer has to enter it again.
        raise ValueError("Stored secret cannot be decrypted; re-enter it in settings") from exc
