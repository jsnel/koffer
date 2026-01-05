"""Tests for CLI commands."""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from koffer import cli

pytestmark = pytest.mark.usefixtures("fast_kdf")


def _decode_unlock_script(text: str) -> str:
    """Extract and decode the base64 payload produced by `cmd_unlock`."""
    bash_match = re.search(r"echo '([^']+)'\|base64 -d\|source /dev/stdin", text)
    if bash_match:
        return base64.b64decode(bash_match.group(1)).decode()

    ps_match = re.search(r"FromBase64String\(\"([^\"]+)\"\)", text)
    if ps_match:
        return base64.b64decode(ps_match.group(1)).decode()

    raise AssertionError("Could not find base64 payload in unlock output")


def create_test_koffer(
    koffer_path: Path,
    password: str = "test-password",
    entries: dict[str, tuple[str, str, str]] | None = None,
) -> tuple[cli.Koffer, bytes]:
    """Create a test koffer with optional entries.

    Args:
        koffer_path: Path to save koffer
        password: Master password
        entries: Dict of {name: (env_var, secret_type, value)}

    Returns:
        Tuple of (koffer, key)
    """
    salt = secrets.token_bytes(16)
    key = cli.derive_key(password, salt)
    koffer = cli.Koffer(salt=salt)

    if entries:
        for name, (env_var, secret_type, value) in entries.items():
            ciphertext, nonce = cli.encrypt_value(key, value)
            koffer.entries[name] = cli.SecretEntry(
                name=name,
                env_var=env_var,
                secret_type=secret_type,
                ciphertext=ciphertext,
                nonce=nonce,
            )

    koffer_path.write_text(json.dumps(koffer.to_dict(), indent=2))
    return koffer, key


class TestCmdAdd:
    """Tests for the 'add' command."""

    def test_add_creates_new_koffer(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Adding first secret should create new koffer."""
        mock_getpass.side_effect = ["Testpass1!", "Testpass1!", "sk-secret123"]

        args = argparse.Namespace(
            name="openai",
            env_var=None,
            type=None,
            no_keyring=True,
        )

        cli.cmd_add(args)

        assert temp_koffer.exists()
        koffer = cli.load_koffer()
        assert koffer is not None
        assert "openai" in koffer.entries

    @pytest.mark.parametrize(
        ("name", "env_var", "secret_type", "expected_env", "expected_type"),
        [
            ("openai", None, None, "OPENAI_API_KEY", "key"),
            ("openai", "MY_CUSTOM_KEY", None, "MY_CUSTOM_KEY", "key"),
            ("OpenAI", None, None, "OPENAI_API_KEY", "key"),
        ],
    )
    def test_add_assigns_env_and_type(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        name: str,
        env_var: str | None,
        secret_type: str | None,
        expected_env: str,
        expected_type: str,
    ) -> None:
        """Add should normalize name and select env/type from defaults or overrides."""
        mock_getpass.side_effect = ["Testpass1!", "Testpass1!", "sk-secret123"]
        args = argparse.Namespace(
            name=name,
            env_var=env_var,
            type=secret_type,
            no_keyring=True,
        )
        cli.cmd_add(args)
        koffer = cli.load_koffer()
        assert koffer is not None
        assert "openai" in koffer.entries
        entry = koffer.entries["openai"]
        assert entry.env_var == expected_env
        assert entry.secret_type == expected_type

    def test_add_empty_secret_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Adding empty secret should fail."""
        mock_getpass.side_effect = ["Testpass1!", "Testpass1!", ""]

        args = argparse.Namespace(
            name="openai",
            env_var=None,
            type=None,
            no_keyring=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_add(args)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "empty value" in captured.err


class TestCmdRemove:
    """Tests for the 'remove' command."""

    def test_remove_existing_secret(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Removing existing secret should work."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(name="openai", no_keyring=True)
        cli.cmd_remove(args)

        koffer = cli.load_koffer()
        assert koffer is not None
        assert "openai" not in koffer.entries

    def test_remove_nonexistent_secret(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Removing non-existent secret should fail."""
        create_test_koffer(temp_koffer)
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(name="nonexistent", no_keyring=True)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_remove(args)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "'nonexistent' not found" in captured.err

    def test_remove_no_koffer(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Removing from non-existent koffer should fail."""
        args = argparse.Namespace(name="openai", no_keyring=True)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_remove(args)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "no koffer found" in captured.err


class TestCmdList:
    """Tests for the 'list' command."""

    def test_list_empty_koffer(
        self,
        temp_koffer: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Listing empty koffer should show message."""
        cli.cmd_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "No secrets stored" in captured.err

    def test_list_with_entries(
        self,
        temp_koffer: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Listing koffer with entries should show them."""
        create_test_koffer(
            temp_koffer,
            entries={
                "openai": ("OPENAI_API_KEY", "key", "sk-secret"),
                "github": ("GITHUB_TOKEN", "token", "ghp-token"),
            },
        )

        cli.cmd_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "openai" in captured.err
        assert "github" in captured.err
        assert "OPENAI_API_KEY" in captured.err
        assert "GITHUB_TOKEN" in captured.err


class TestCmdUnlock:
    """Tests for the 'unlock' command."""

    def test_unlock_outputs_exports(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock should output export commands when obfuscation is disabled."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=[],
            shell="bash",
            show_keys=False,
            obfuscate=False,
            stdout=True,
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        cli.cmd_unlock(args)

        captured = capsys.readouterr()
        # Plain (non-wrapped) mode still avoids printing plaintext secrets.
        assert "export OPENAI_API_KEY=" in captured.out
        assert "sk-secret123" not in captured.out
        assert "Unlocked 1 secret" in captured.err

    def test_unlock_with_show_keys(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock with --show-keys should output plaintext commands."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=[],
            shell="bash",
            show_keys=True,
            stdout=False,  # --show-keys always outputs to stdout regardless
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        cli.cmd_unlock(args)

        captured = capsys.readouterr()
        # With --show-keys, output should be plaintext
        assert "export OPENAI_API_KEY=" in captured.out
        assert "sk-secret123" in captured.out

    def test_unlock_specific_secrets(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock should filter by specified names."""
        create_test_koffer(
            temp_koffer,
            entries={
                "openai": ("OPENAI_API_KEY", "key", "sk-secret"),
                "github": ("GITHUB_TOKEN", "token", "ghp-token"),
            },
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=["openai"],
            shell="bash",
            show_keys=False,
            obfuscate=False,
            stdout=True,
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        cli.cmd_unlock(args)

        captured = capsys.readouterr()
        assert "export OPENAI_API_KEY=" in captured.out
        assert "GITHUB_TOKEN" not in captured.out
        assert "Unlocked 1 secret" in captured.err

    def test_unlock_empty_koffer(
        self,
        temp_koffer: Path,
    ) -> None:
        """Unlock with no secrets should fail."""
        args = argparse.Namespace(
            names=[],
            shell="bash",
            show_keys=False,
            stdout=True,
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_unlock(args)

        assert exc_info.value.code == 1

    def test_unlock_clipboard_mode(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock with --obfuscate should copy to clipboard."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=[],
            shell="bash",
            show_keys=False,
            obfuscate=True,
            stdout=False,  # Clipboard mode with obfuscate
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        copied: dict[str, str] = {}

        def _fake_copy(text: str) -> None:
            copied["value"] = text

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "_clipboard_copy", _fake_copy)
            cli.cmd_unlock(args)

        script = _decode_unlock_script(copied["value"])
        assert "export OPENAI_API_KEY=" in script
        assert "sk-secret123" not in script

        captured = capsys.readouterr()
        assert "Unlocked 1 secret" in captured.err

    def test_unlock_powershell(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock for PowerShell should output correct format."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=[],
            shell="powershell",
            show_keys=False,
            obfuscate=False,
            stdout=True,
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        cli.cmd_unlock(args)

        captured = capsys.readouterr()
        # Plain mode for PowerShell
        assert "$env:OPENAI_API_KEY" in captured.out
        assert "Unlocked 1 secret" in captured.err

    def test_unlock_obfuscate_mode(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Unlock with --obfuscate should base64-encode the output."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=[],
            shell="bash",
            show_keys=False,
            obfuscate=True,
            stdout=True,
            clear=False,
            keep_history=True,
            no_keyring=True,
        )

        cli.cmd_unlock(args)

        captured = capsys.readouterr()
        # Obfuscate mode uses base64 encoding
        script = _decode_unlock_script(captured.out)
        assert "export OPENAI_API_KEY=" in script
        assert "sk-secret123" not in script
        assert "Unlocked 1 secret" in captured.err


class TestCmdExport:
    """Tests for the 'export' command."""

    def test_export_creates_backup(
        self,
        temp_koffer: Path,
        tmp_path: Path,
    ) -> None:
        """Export should create backup file."""
        create_test_koffer(temp_koffer)
        backup_path = tmp_path / "backup.enc"

        args = argparse.Namespace(output=str(backup_path))
        cli.cmd_export(args)

        assert backup_path.exists()
        # Backup should be valid koffer
        data = json.loads(backup_path.read_text())
        assert "version" in data
        assert "salt" in data

    def test_export_no_koffer(
        self,
        temp_koffer: Path,
        tmp_path: Path,
    ) -> None:
        """Export with no koffer should fail."""
        backup_path = tmp_path / "backup.enc"

        args = argparse.Namespace(output=str(backup_path))

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_export(args)

        assert exc_info.value.code == 1


class TestCmdImport:
    """Tests for the 'import' command."""

    def test_import_restores_koffer(
        self,
        temp_koffer: Path,
        tmp_path: Path,
    ) -> None:
        """Import should restore koffer from backup."""
        # Create backup file
        backup_path = tmp_path / "backup.enc"
        backup_data = {"version": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "entries": {}}
        backup_path.write_text(json.dumps(backup_data))

        args = argparse.Namespace(input=str(backup_path), force=False)
        cli.cmd_import(args)

        assert temp_koffer.exists()
        koffer = cli.load_koffer()
        assert koffer is not None

    def test_import_fails_without_force(
        self,
        temp_koffer: Path,
        tmp_path: Path,
    ) -> None:
        """Import should fail if koffer exists without --force."""
        # Create existing koffer
        create_test_koffer(temp_koffer)

        # Create backup
        backup_path = tmp_path / "backup.enc"
        backup_path.write_text(
            json.dumps({"version": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "entries": {}})
        )

        args = argparse.Namespace(input=str(backup_path), force=False)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_import(args)

        assert exc_info.value.code == 1

    def test_import_with_force(
        self,
        temp_koffer: Path,
        tmp_path: Path,
    ) -> None:
        """Import with --force should overwrite existing koffer."""
        # Create existing koffer
        create_test_koffer(temp_koffer, entries={"old": ("OLD_KEY", "key", "old-value")})

        # Create backup without entries
        backup_path = tmp_path / "backup.enc"
        backup_path.write_text(
            json.dumps({"version": 2, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "entries": {}})
        )

        args = argparse.Namespace(input=str(backup_path), force=True)
        cli.cmd_import(args)

        koffer = cli.load_koffer()
        assert koffer is not None
        assert "old" not in koffer.entries

    @pytest.mark.parametrize(
        ("content", "expected_err"),
        [
            (None, "not found"),
            ("not valid json", "invalid JSON"),
            (json.dumps({"invalid": "structure"}), "invalid koffer"),
        ],
    )
    def test_import_rejects_invalid_inputs(
        self,
        temp_koffer: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        content: str | None,
        expected_err: str,
    ) -> None:
        """Import should fail for missing/invalid koffer files."""
        backup_path = tmp_path / "backup.enc"
        if content is not None:
            backup_path.write_text(content)
        else:
            backup_path = tmp_path / "nonexistent.enc"

        args = argparse.Namespace(input=str(backup_path), force=False)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_import(args)

        assert exc_info.value.code == 1
        assert expected_err.lower() in capsys.readouterr().err.lower()


class TestCmdRotate:
    """Tests for the 'rotate' command (password change)."""

    def test_rotate_changes_password(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Rotate should re-encrypt all secrets with new password."""
        old_password = "Oldpass1!"
        new_password = "Newpass1!"

        create_test_koffer(
            temp_koffer,
            password=old_password,
            entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")},
        )

        # Mock password prompts: old password, then new password twice (with confirm)
        mock_getpass.side_effect = [old_password, new_password, new_password]

        args = argparse.Namespace(no_keyring=True)
        cli.cmd_rotate(args)

        captured = capsys.readouterr()
        assert "rotated" in captured.err.lower()

        # Verify new password works
        new_koffer = cli.load_koffer()
        assert new_koffer is not None
        new_key = cli.derive_key(new_password, new_koffer.salt)
        decrypted = cli.decrypt_value(
            new_key,
            new_koffer.entries["openai"].ciphertext,
            new_koffer.entries["openai"].nonce,
            aad=cli.entry_aad(new_koffer.entries["openai"]),
        )
        assert decrypted == "sk-secret123"

    def test_rotate_wrong_password_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Rotate with wrong current password should fail."""
        create_test_koffer(
            temp_koffer,
            password="correct-password",
            entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")},
        )
        mock_getpass.return_value = "wrong-password"

        args = argparse.Namespace(no_keyring=True)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_rotate(args)

        assert exc_info.value.code == 1

    def test_rotate_no_koffer_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
    ) -> None:
        """Rotate with no koffer should fail."""
        args = argparse.Namespace(no_keyring=True)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_rotate(args)

        assert exc_info.value.code == 1


class TestCmdRun:
    """Tests for the 'run' command (execute with injected secrets)."""

    def test_run_injects_env_vars(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Run should inject secrets into command environment."""
        create_test_koffer(
            temp_koffer, entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=None,
            no_keyring=True,
            cmd=["python", "-c", "print('ok')"],
        )

        calls: dict[str, Any] = {}

        def _fake_run(command: list[str], env: dict[str, str]) -> SimpleNamespace:
            calls["command"] = command
            calls["env"] = env
            return SimpleNamespace(returncode=0)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "_run_subprocess", _fake_run)

            # cmd_run calls sys.exit with the subprocess returncode
            with pytest.raises(SystemExit) as exc_info:
                cli.cmd_run(args)

        assert exc_info.value.code == 0
        assert isinstance(calls.get("env"), dict)
        assert calls["env"].get("OPENAI_API_KEY") == "sk-secret123"
        captured = capsys.readouterr()
        assert "Injecting 1 secret" in captured.err

    def test_run_filters_by_name(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Run should only inject specified secrets."""
        create_test_koffer(
            temp_koffer,
            entries={
                "openai": ("OPENAI_API_KEY", "key", "sk-secret"),
                "github": ("GITHUB_TOKEN", "token", "ghp-token"),
            },
        )
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=["openai"],
            no_keyring=True,
            cmd=["python", "-c", "print('ok')"],
        )

        calls: dict[str, Any] = {}

        def _fake_run(command: list[str], env: dict[str, str]) -> SimpleNamespace:
            calls["command"] = command
            calls["env"] = env
            return SimpleNamespace(returncode=0)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "_run_subprocess", _fake_run)

            with pytest.raises(SystemExit) as exc_info:
                cli.cmd_run(args)

        assert exc_info.value.code == 0
        assert isinstance(calls.get("env"), dict)
        assert calls["env"].get("OPENAI_API_KEY") == "sk-secret"
        assert "GITHUB_TOKEN" not in calls["env"]
        captured = capsys.readouterr()
        assert "openai" in captured.err
        assert "github" not in captured.err

    def test_run_no_command_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
    ) -> None:
        """Run without command should fail."""
        create_test_koffer(temp_koffer, entries={"test": ("TEST", "key", "value")})

        args = argparse.Namespace(
            names=None,
            no_keyring=True,
            cmd=[],
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_run(args)

        assert exc_info.value.code == 1

    def test_run_no_koffer_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
    ) -> None:
        """Run with no koffer should fail."""
        args = argparse.Namespace(
            names=None,
            no_keyring=True,
            cmd=["echo", "test"],
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_run(args)

        assert exc_info.value.code == 1

    def test_run_strips_double_dash(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Run should strip leading '--' from command."""
        create_test_koffer(temp_koffer, entries={"test": ("TEST_VAR", "key", "value")})
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=None,
            no_keyring=True,
            cmd=["--", "python", "-c", "print('ok')"],  # Leading --
        )

        calls: dict[str, Any] = {}

        def _fake_run(command: list[str], env: dict[str, str]) -> SimpleNamespace:
            calls["command"] = command
            return SimpleNamespace(returncode=0)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "_run_subprocess", _fake_run)

            with pytest.raises(SystemExit) as exc_info:
                cli.cmd_run(args)

        assert exc_info.value.code == 0
        assert isinstance(calls.get("command"), list)
        assert calls["command"][0] == "python"

    def test_run_command_not_found(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Run with non-existent command should fail gracefully."""
        create_test_koffer(temp_koffer, entries={"test": ("TEST_VAR", "key", "value")})
        mock_getpass.return_value = "test-password"

        args = argparse.Namespace(
            names=None,
            no_keyring=True,
            cmd=["nonexistent_command_xyz_12345"],
        )

        def _fake_run(command: list[str], env: dict[str, str]) -> SimpleNamespace:
            raise FileNotFoundError

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cli, "_run_subprocess", _fake_run)

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_run(args)

        assert exc_info.value.code == 1


class TestCmdAddEdgeCases:
    """Additional edge case tests for 'add' command."""

    def test_add_secret_too_long(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Adding secret exceeding max length should fail."""
        mock_getpass.side_effect = ["test-password", "test-password", "x" * 10000]

        args = argparse.Namespace(
            name="test",
            env_var=None,
            type=None,
            no_keyring=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_add(args)

        assert exc_info.value.code == 1

    def test_add_with_existing_koffer_wrong_password(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
    ) -> None:
        """Adding to existing koffer with wrong password should fail."""
        create_test_koffer(
            temp_koffer,
            password="correct-password",
            entries={"existing": ("EXISTING_KEY", "key", "value")},
        )
        mock_getpass.side_effect = ["wrong-password", "new-secret"]

        args = argparse.Namespace(
            name="newservice",
            env_var=None,
            type=None,
            no_keyring=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_add(args)

        assert exc_info.value.code == 1


class TestCmdPurgeKeyring:
    """Tests for the 'purge-keyring' command."""

    def test_purge_removes_stored_password(
        self,
        mock_keyring: dict[str, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Purge should remove stored master password."""
        key = f"{cli.KEYRING_SERVICE}:{cli.KEYRING_USERNAME}"
        mock_keyring[key] = "stored-password"

        cli.cmd_purge_keyring(argparse.Namespace())

        assert key not in mock_keyring
        assert "removed" in capsys.readouterr().err.lower()

    def test_purge_no_password_reports(
        self,
        mock_keyring: dict[str, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Purge should be a no-op when nothing is stored."""
        cli.cmd_purge_keyring(argparse.Namespace())

        captured = capsys.readouterr()
        assert "no stored master password" in captured.err.lower()


class TestCmdStoreKeyring:
    """Tests for the 'store-keyring' command."""

    def test_store_keyring_stores_password(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """store-keyring should store password after verification."""
        create_test_koffer(
            temp_koffer,
            password="test-password",
            entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")},
        )
        mock_getpass.return_value = "test-password"

        cli.cmd_store_keyring(argparse.Namespace())

        key = f"{cli.KEYRING_SERVICE}:{cli.KEYRING_USERNAME}"
        assert mock_keyring.get(key) == "test-password"
        assert "stored" in capsys.readouterr().err.lower()

    def test_store_keyring_wrong_password_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        mock_getpass: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """store-keyring should fail with incorrect password."""
        create_test_koffer(
            temp_koffer,
            password="correct-password",
            entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")},
        )
        mock_getpass.return_value = "wrong-password"

        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_store_keyring(argparse.Namespace())

        assert exc_info.value.code == 1
        assert "incorrect password" in capsys.readouterr().err.lower()

    def test_store_keyring_no_koffer_fails(
        self,
        temp_koffer: Path,
        mock_keyring: dict[str, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """store-keyring should fail when no koffer exists."""
        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_store_keyring(argparse.Namespace())

        assert exc_info.value.code == 1
        assert "no koffer found" in capsys.readouterr().err.lower()
