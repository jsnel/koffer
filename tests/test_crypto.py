"""Tests for cryptographic functions."""

from __future__ import annotations

import secrets

import pytest

from koffer.crypto import (
    decrypt_value,
    derive_key,
    encrypt_value,
)


class TestDeriveKey:
    """Tests for password key derivation."""

    def test_derive_key_properties(self) -> None:
        """Derivation should be stable and sensitive to inputs."""
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        key_a1 = derive_key("password-a", salt1)
        key_a1_again = derive_key("password-a", salt1)
        key_b1 = derive_key("password-b", salt1)
        key_a2 = derive_key("password-a", salt2)

        assert len(key_a1) == 32
        assert key_a1 == key_a1_again
        assert key_a1 != key_b1
        assert key_a1 != key_a2


class TestEncryption:
    """Tests for encryption and decryption."""

    def test_encrypt_decrypt_roundtrip_and_nonce_uniqueness(self) -> None:
        key = secrets.token_bytes(32)
        plaintext = "my-secret-api-key"

        ciphertext1, nonce1 = encrypt_value(key, plaintext)
        ciphertext2, nonce2 = encrypt_value(key, plaintext)

        assert decrypt_value(key, ciphertext1, nonce1) == plaintext
        assert decrypt_value(key, ciphertext2, nonce2) == plaintext
        assert nonce1 != nonce2

    @pytest.mark.parametrize(
        "mode",
        ["wrong_key", "wrong_nonce"],
    )
    def test_decrypt_with_wrong_inputs_fails(self, mode: str) -> None:
        key = secrets.token_bytes(32)
        plaintext = "my-secret-api-key"

        ciphertext, nonce = encrypt_value(key, plaintext)

        if mode == "wrong_key":
            key = secrets.token_bytes(32)
        else:
            nonce = secrets.token_bytes(12)

        with pytest.raises(Exception):
            decrypt_value(key, ciphertext, nonce)

    @pytest.mark.parametrize(
        "plaintext",
        ["", "secret-🔑-key-ひみつ", "x" * 8192],
    )
    def test_encrypt_handles_edge_values(self, plaintext: str) -> None:
        """Encryption should roundtrip empty, unicode, and large payloads."""
        key = secrets.token_bytes(32)
        ciphertext, nonce = encrypt_value(key, plaintext)
        decrypted = decrypt_value(key, ciphertext, nonce)
        assert decrypted == plaintext
