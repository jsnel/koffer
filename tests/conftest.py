"""Pytest configuration and fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from koffer import cli, crypto, storage


@pytest.fixture
def temp_koffer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a temporary koffer path for testing."""
    koffer_path = tmp_path / ".koffer.enc"
    monkeypatch.setattr(storage, "KOFFER_PATH", koffer_path)
    monkeypatch.setattr(cli, "KOFFER_PATH", koffer_path)
    return koffer_path


@pytest.fixture
def mock_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Mock keyring to avoid system credential manager access."""
    storage: dict[str, str] = {}

    def mock_set(service: str, username: str, password: str) -> None:
        storage[f"{service}:{username}"] = password

    def mock_get(service: str, username: str) -> str | None:
        return storage.get(f"{service}:{username}")

    def mock_delete(service: str, username: str) -> None:
        key = f"{service}:{username}"
        storage.pop(key, None)

    monkeypatch.setattr("keyring.set_password", mock_set)
    monkeypatch.setattr("keyring.get_password", mock_get)
    monkeypatch.setattr("keyring.delete_password", mock_delete)

    return storage


@pytest.fixture
def sample_koffer_data() -> dict[str, Any]:
    """Create sample koffer data for testing."""
    return {
        "version": 2,
        "salt": "AAAAAAAAAAAAAAAAAAAAAA==",  # 16 bytes of zeros, base64 encoded
        "entries": {},
    }


@pytest.fixture
def mock_getpass(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Mock getpass to provide passwords programmatically."""
    mock = MagicMock(return_value="test-password-123")
    monkeypatch.setattr("getpass.getpass", mock)
    return mock


@pytest.fixture
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast deterministic KDF for non-crypto tests.

    This keeps encryption/decryption behavior meaningful (wrong password -> wrong key -> decrypt fails)
    while avoiding the heavy Argon2 parameters during command tests.
    """

    def _derive_key_fast(password: str, salt: bytes) -> bytes:
        return hashlib.sha256(password.encode() + salt).digest()

    monkeypatch.setattr(crypto, "derive_key", _derive_key_fast)
    monkeypatch.setattr(cli, "derive_key", _derive_key_fast)
