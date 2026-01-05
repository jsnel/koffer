"""Tests for CLI utility functions."""

from __future__ import annotations

import pytest

from koffer.utils import (
    anonymize_secret,
    detect_shell,
    format_export,
    infer_env_var,
    validate_name,
)


class TestValidateName:
    """Tests for service name validation."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("openai", "openai"),
            ("github", "github"),
            ("my_service", "my_service"),
            ("my-service", "my-service"),
            ("OpenAI", "openai"),
            ("  openai  ", "openai"),
        ],
    )
    def test_valid_names_normalize(self, raw: str, expected: str) -> None:
        """Valid names should normalize to lowercase/stripped form."""
        assert validate_name(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "123service",
            "service name",
            "a" * 100,
            "service@name",
        ],
    )
    def test_invalid_names_rejected(self, raw: str) -> None:
        """Invalid patterns should exit with error."""
        with pytest.raises(SystemExit):
            validate_name(raw)


class TestInferEnvVar:
    """Tests for environment variable name inference."""

    @pytest.mark.parametrize(
        ("name", "secret_type", "expected"),
        [
            ("myservice", "key", "MYSERVICE_API_KEY"),
            ("myservice", "token", "MYSERVICE_TOKEN"),
            ("myservice", "secret", "MYSERVICE_SECRET"),
            ("my-service", "key", "MY_SERVICE_API_KEY"),
            ("my service", "key", "MY_SERVICE_API_KEY"),
        ],
    )
    def test_infer_env_var(self, name: str, secret_type: str, expected: str) -> None:
        assert infer_env_var(name, secret_type) == expected


class TestAnonymizeSecret:
    """Tests for secret anonymization."""

    def test_anonymize_long_secret(self) -> None:
        """Long secrets should show first 10 and last 2 chars."""
        result = anonymize_secret("sk-1234567890abcdefghij")
        assert result == "sk-1234567...ij"

    def test_anonymize_short_secret(self) -> None:
        """Short and edge-case secrets should be mostly/fully hidden."""
        assert anonymize_secret("abc") == "***bc"
        assert anonymize_secret("a") == "***"
        assert anonymize_secret("123456789012") == "***12"


class TestDetectShell:
    """Tests for shell detection."""

    @pytest.mark.parametrize(
        ("env", "expected"),
        [
            ({"PSModulePath": "C:/Users/test/Documents/PowerShell"}, "powershell"),
            ({"SHELL": "/bin/bash"}, "bash"),
            ({"SHELL": "/bin/zsh"}, "bash"),
            ({"WSL_DISTRO_NAME": "Ubuntu"}, "bash"),
        ],
    )
    def test_detect_shell_variants(
        self, monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: str
    ) -> None:
        """Shell detection should map common environments to expected value."""
        for key in ("PSModulePath", "SHELL", "WSL_DISTRO_NAME"):
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        assert detect_shell() == expected


class TestFormatExport:
    """Tests for shell export formatting."""

    @pytest.mark.parametrize(
        ("shell", "must_contain"),
        [
            ("powershell", "FromBase64String"),
            ("bash", "base64 -d"),
        ],
    )
    def test_format_obfuscated_does_not_leak_plaintext(
        self, shell: str, must_contain: str
    ) -> None:
        result = format_export("TEST_KEY", "secret123", shell)
        assert must_contain in result
        assert "secret123" not in result

    @pytest.mark.parametrize(
        "shell",
        ["powershell", "bash"],
    )
    def test_format_show_full_includes_plaintext(self, shell: str) -> None:
        result = format_export("TEST_KEY", "secret123", shell, show_full=True)
        assert "secret123" in result

    def test_format_escapes_special_chars_powershell(self) -> None:
        """PowerShell escaping should protect $, quotes, and backticks."""
        result = format_export(
            "TEST_KEY", 'value$with"special`chars', "powershell", show_full=True
        )
        assert result == '$env:TEST_KEY = "value`$with`"special``chars"'

    def test_format_escapes_special_chars_bash(self) -> None:
        """Bash escaping should wrap single quotes correctly."""
        result = format_export("TEST_KEY", "value'with'quotes", "bash", show_full=True)
        assert result == "export TEST_KEY='value'\"'\"'with'\"'\"'quotes'"
