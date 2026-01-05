"""Cryptographic functions for koffer."""

from __future__ import annotations

import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 256-bit key from password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_value(key: bytes, plaintext: str, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM, return (ciphertext, nonce).

    Args:
        key: 32-byte encryption key.
        plaintext: Value to encrypt.
        aad: Optional associated data to bind metadata (authenticated, not encrypted).
    """
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)
    return ciphertext, nonce


def decrypt_value(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes | None = None) -> str:
    """Decrypt with AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad).decode()
