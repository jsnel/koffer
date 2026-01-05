"""CLI wiring smoke tests.

These focus on argparse parsing + command dispatch only.
They intentionally do not exercise vault/crypto logic (covered elsewhere).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from koffer import cli


def _run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
    monkeypatch.setattr(cli.sys, "argv", argv)
    cli.main()


@pytest.mark.parametrize(
    ("func_name", "argv"),
    [
        ("cmd_add", ["koffer", "add", "openai", "--no-keyring"]),
        ("cmd_remove", ["koffer", "remove", "openai", "--no-keyring"]),
        ("cmd_list", ["koffer", "list"]),
        ("cmd_unlock", ["koffer", "unlock", "--stdout", "--no-keyring"]),
        ("cmd_rotate", ["koffer", "rotate", "--no-keyring"]),
        ("cmd_export", ["koffer", "export", "backup.enc"]),
        ("cmd_import", ["koffer", "import", "backup.enc", "--force"]),
        ("cmd_run", ["koffer", "run", "--no-keyring", "--", "echo", "hi"]),
        ("cmd_purge_keyring", ["koffer", "purge-keyring"]),
    ],
)
def test_cli_dispatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, func_name: str, argv: list[str]
) -> None:
    called: dict[str, object] = {}

    def _fake(args: object) -> None:
        called["args"] = args

    if func_name in {"cmd_export", "cmd_import"}:
        argv = [*argv]
        argv[2] = str(tmp_path / argv[2])

    monkeypatch.setattr(cli, func_name, _fake)
    _run_cli(monkeypatch, argv)

    assert "args" in called
