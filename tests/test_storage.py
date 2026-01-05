"""Tests for koffer storage operations."""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

import pytest

import koffer.storage as storage_mod
from koffer.crypto import encrypt_value

pytestmark = pytest.mark.usefixtures("fast_kdf")


def _koffer_with_one_entry(
    *, key: bytes, salt: bytes, value: str = "secret-value"
) -> storage_mod.Koffer:
    koffer = storage_mod.Koffer(salt=salt)
    ciphertext, nonce = encrypt_value(key, value)
    koffer.entries["test"] = storage_mod.SecretEntry(
        name="test",
        env_var="TEST",
        secret_type="key",
        ciphertext=ciphertext,
        nonce=nonce,
    )
    return koffer


class TestKoffer:
    """Tests for Koffer dataclass."""

    def test_koffer_roundtrip_empty(self) -> None:
        """Koffer should roundtrip through dict without losing fields."""
        salt = secrets.token_bytes(16)
        koffer = storage_mod.Koffer(salt=salt)

        restored = storage_mod.Koffer.from_dict(koffer.to_dict())

        assert restored.salt == salt
        assert restored.entries == {}

    def test_koffer_roundtrip_with_entries(self) -> None:
        """Koffer should serialize/deserialize entries correctly."""
        salt = secrets.token_bytes(16)
        ciphertext = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        koffer = storage_mod.Koffer(salt=salt)
        koffer.entries["openai"] = storage_mod.SecretEntry(
            name="openai",
            env_var="OPENAI_API_KEY",
            secret_type="key",
            ciphertext=ciphertext,
            nonce=nonce,
        )

        data = koffer.to_dict()
        restored = storage_mod.Koffer.from_dict(data)

        assert restored.salt == salt
        assert "openai" in restored.entries
        assert restored.entries["openai"].name == "openai"
        assert restored.entries["openai"].env_var == "OPENAI_API_KEY"
        assert restored.entries["openai"].ciphertext == ciphertext
        assert restored.entries["openai"].nonce == nonce

    def test_koffer_v1_compatibility(self) -> None:
        """Koffer should handle v1 entries without secret_type."""
        data = {
            "version": 2,
            "salt": base64.b64encode(b"x" * 16).decode(),
            "entries": {
                "test": {
                    "name": "test",
                    "env_var": "TEST_KEY",
                    # No secret_type field (v1)
                    "ciphertext": base64.b64encode(b"cipher").decode(),
                    "nonce": base64.b64encode(b"nonce123456.").decode(),
                }
            },
        }

        koffer = storage_mod.Koffer.from_dict(data)

        # Should default to "key" for v1 compatibility
        assert koffer.entries["test"].secret_type == "key"


class TestKofferPersistence:
    """Tests for koffer load/save operations."""

    def test_load_koffer_nonexistent(self, temp_koffer: Path) -> None:
        """Loading non-existent koffer should return None."""
        assert storage_mod.load_koffer() is None

    def test_save_and_load_koffer(self, temp_koffer: Path) -> None:
        """Koffer should save and load correctly."""
        salt = secrets.token_bytes(16)
        koffer = storage_mod.Koffer(salt=salt)

        storage_mod.save_koffer(koffer)
        loaded = storage_mod.load_koffer()

        assert loaded is not None
        assert loaded.salt == salt

    def test_koffer_file_is_valid_json(self, temp_koffer: Path) -> None:
        """Saved koffer should be valid JSON."""
        koffer = storage_mod.Koffer(salt=secrets.token_bytes(16))
        storage_mod.save_koffer(koffer)

        content = temp_koffer.read_text()
        data = json.loads(content)

        assert "version" in data
        assert "salt" in data
        assert "entries" in data

    @pytest.mark.skipif(
        pytest.importorskip("platform").system() == "Windows",
        reason="Windows requires admin privileges for symlinks",
    )
    def test_save_koffer_follows_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Saving koffer should write to symlink target, not replace the symlink."""
        # Create target file in a "windows" directory
        windows_dir = tmp_path / "windows"
        windows_dir.mkdir()
        target_file = windows_dir / ".koffer.enc"
        target_file.write_text("{}")

        # Create symlink in a "wsl" directory pointing to the target
        wsl_dir = tmp_path / "wsl"
        wsl_dir.mkdir()
        symlink_path = wsl_dir / ".koffer.enc"
        symlink_path.symlink_to(target_file)

        # Point KOFFER_PATH to the symlink
        monkeypatch.setattr(storage_mod, "KOFFER_PATH", symlink_path)

        # Save a koffer
        salt = secrets.token_bytes(16)
        koffer = storage_mod.Koffer(salt=salt)
        storage_mod.save_koffer(koffer)

        # Symlink should still be a symlink
        assert symlink_path.is_symlink(), "save_koffer replaced symlink instead of following it"

        # Target should have the new content
        target_data = json.loads(target_file.read_text())
        assert "version" in target_data
        assert target_data["salt"] == base64.b64encode(salt).decode()

        # Both should have the same content
        assert symlink_path.read_text() == target_file.read_text()


class TestVerifyPassword:
    """Tests for password verification."""

    def test_verify_password_empty_koffer(self, temp_koffer: Path) -> None:
        """Verification should succeed for empty koffer."""
        koffer = storage_mod.Koffer(salt=secrets.token_bytes(16))
        key = secrets.token_bytes(32)

        assert storage_mod.verify_password(koffer, key) is True

    def test_verify_password_correct(self, temp_koffer: Path) -> None:
        """Verification should succeed with correct password."""
        salt = secrets.token_bytes(16)

        key = secrets.token_bytes(32)
        koffer = _koffer_with_one_entry(key=key, salt=salt)

        assert storage_mod.verify_password(koffer, key) is True

    def test_verify_password_incorrect(self, temp_koffer: Path) -> None:
        """Verification should fail with incorrect password."""
        salt = secrets.token_bytes(16)

        correct_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        koffer = _koffer_with_one_entry(key=correct_key, salt=salt)

        assert storage_mod.verify_password(koffer, wrong_key) is False
