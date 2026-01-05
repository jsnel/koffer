"""Koffer storage and persistence."""

from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from koffer.crypto import decrypt_value

# Storage location
KOFFER_PATH = Path.home() / ".koffer.enc"
KOFFER_BACKUP_PATH = Path.home() / ".koffer-backup.enc"


@dataclass
class SecretEntry:
    """Single secret entry (API key, token, etc.)."""

    name: str
    env_var: str
    secret_type: str  # "key", "token", "secret"
    ciphertext: bytes
    nonce: bytes
    companions: dict[str, str] = field(default_factory=dict)  # Additional env vars to set


@dataclass
class Koffer:
    """Encrypted secrets koffer."""

    salt: bytes
    entries: dict[str, SecretEntry] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "version": 3,
            "salt": base64.b64encode(self.salt).decode(),
            "entries": {
                name: {
                    "name": e.name,
                    "env_var": e.env_var,
                    "secret_type": e.secret_type,
                    "ciphertext": base64.b64encode(e.ciphertext).decode(),
                    "nonce": base64.b64encode(e.nonce).decode(),
                    **(({"companions": e.companions}) if e.companions else {}),
                }
                for name, e in self.entries.items()
            },
        }
        if self.config:
            result["config"] = self.config
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Koffer:
        koffer = cls(salt=base64.b64decode(data["salt"]))
        for name, e in data.get("entries", {}).items():
            koffer.entries[name] = SecretEntry(
                name=e["name"],
                env_var=e["env_var"],
                secret_type=e.get("secret_type", "key"),  # v1 compat
                ciphertext=base64.b64decode(e["ciphertext"]),
                nonce=base64.b64decode(e["nonce"]),
                companions=e.get("companions", {}),  # v2 compat
            )
        koffer.config = data.get("config", {})
        return koffer

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a config value with optional default."""
        return self.config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Set a config value."""
        self.config[key] = value


def entry_aad(entry: SecretEntry) -> bytes:
    """Compute stable associated data for a secret entry.

    This binds non-secret metadata (name/env_var/type/companions) to the ciphertext
    so tampering with those fields causes decryption to fail.
    """
    companions_json = json.dumps(entry.companions or {}, sort_keys=True, separators=(",", ":"))
    return (f"{entry.name}\0{entry.env_var}\0{entry.secret_type}\0{companions_json}").encode()


def secure_file_permissions(path: Path) -> None:
    """Set file permissions to user-only."""
    if platform.system() != "Windows":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def load_koffer() -> Koffer | None:
    """Load koffer from disk."""
    if not KOFFER_PATH.exists():
        return None
    try:
        return Koffer.from_dict(json.loads(KOFFER_PATH.read_text()))
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def save_koffer(koffer: Koffer) -> None:
    """Save koffer with secure permissions using atomic write.

    If KOFFER_PATH is a symlink, writes to the symlink target to preserve
    the link (important for WSL2/Windows shared koffer setups).
    """
    # Resolve symlinks to write to the actual target file
    target_path = KOFFER_PATH.resolve() if KOFFER_PATH.is_symlink() else KOFFER_PATH

    # Create a temporary file in the same directory as the target
    fd, temp_path_str = tempfile.mkstemp(dir=target_path.parent, prefix=".koffer.tmp")
    temp_path = Path(temp_path_str)

    try:
        with os.fdopen(fd, "w") as f:
            json.dump(koffer.to_dict(), f, indent=2)

        # Set permissions before moving
        secure_file_permissions(temp_path)

        # Atomic rename to the resolved target
        temp_path.replace(target_path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def verify_password(koffer: Koffer, key: bytes) -> bool:
    """Verify password by attempting to decrypt first entry."""
    if not koffer.entries:
        return True
    try:
        first = next(iter(koffer.entries.values()))
        try:
            decrypt_value(key, first.ciphertext, first.nonce, aad=entry_aad(first))
        except InvalidTag:
            # Legacy vaults did not bind metadata as AAD.
            decrypt_value(key, first.ciphertext, first.nonce, aad=None)
        return True
    except (InvalidTag, ValueError, TypeError):
        return False


def backup_koffer() -> bool:
    """Create a backup of the koffer file. Returns True on success."""
    if not KOFFER_PATH.exists():
        return False
    try:
        shutil.copy2(KOFFER_PATH, KOFFER_BACKUP_PATH)
        secure_file_permissions(KOFFER_BACKUP_PATH)
        return True
    except (OSError, shutil.Error):
        return False


def should_auto_backup(koffer: Koffer | None) -> bool:
    """Check if auto-backup is enabled (defaults to True)."""
    if koffer is None:
        return True
    return koffer.get_config("AUTO_BACKUP", default=True)
