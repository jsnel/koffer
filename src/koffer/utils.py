"""Utility functions for koffer."""

from __future__ import annotations

import base64
import os
import platform
import re
import sys
from typing import NoReturn

# Validation constants
MAX_NAME_LENGTH = 64
MAX_SECRET_LENGTH = 8192
NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")

ANONYMIZE_PREFIX_LEN = 10
ANONYMIZE_SUFFIX_LEN = 2
ANONYMIZE_MIN_LEN = ANONYMIZE_PREFIX_LEN + ANONYMIZE_SUFFIX_LEN


def error_exit(message: str, code: int = 1) -> NoReturn:
    """Print error message and exit with code."""
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(code)


def validate_name(name: str) -> str:
    """Validate and normalize service name."""
    name = name.strip().lower()
    if not name:
        error_exit("name cannot be empty")
    if len(name) > MAX_NAME_LENGTH:
        error_exit(f"name too long (max {MAX_NAME_LENGTH} characters)")
    if not NAME_PATTERN.match(name):
        error_exit(
            "invalid name: must start with a letter and contain only "
            "letters, numbers, underscores, and hyphens"
        )
    return name


def detect_shell() -> str:
    """Detect current shell type."""
    # PowerShell uses `PSModulePath` (mixed case). On Windows env vars are
    # case-insensitive, but on Linux/macOS they are case-sensitive.
    if os.environ.get("PSModulePath") or os.environ.get("PSMODULEPATH"):  # noqa: SIM112
        return "powershell"
    shell = os.environ.get("SHELL", "")
    if "bash" in shell or "zsh" in shell or os.environ.get("WSL_DISTRO_NAME"):
        return "bash"
    return "powershell" if platform.system() == "Windows" else "bash"


def anonymize_secret(value: str) -> str:
    """Anonymize secret for display (first 10 chars + last 2)."""
    if len(value) <= ANONYMIZE_MIN_LEN:
        return (
            "***" + value[-ANONYMIZE_SUFFIX_LEN:] if len(value) >= ANONYMIZE_SUFFIX_LEN else "***"
        )
    return value[:ANONYMIZE_PREFIX_LEN] + "..." + value[-ANONYMIZE_SUFFIX_LEN:]


def infer_env_var(name: str, secret_type: str) -> str:
    """Infer env var name from service name and type."""
    name_upper = name.upper().replace("-", "_").replace(" ", "_")
    suffixes = {"key": "_API_KEY", "token": "_TOKEN", "secret": "_SECRET"}
    return f"{name_upper}{suffixes.get(secret_type, '_SECRET')}"


def format_export(env_var: str, value: str, shell: str, *, show_full: bool = False) -> str:
    """Format environment variable export for shell."""
    if show_full:
        # Show plaintext for convenience
        if shell == "powershell":
            escaped = value.replace("`", "``").replace('"', '`"').replace("$", "`$")
            return f'$env:{env_var} = "{escaped}"'
        escaped = value.replace("'", "'\"'\"'")
        return f"export {env_var}='{escaped}'"
    # Obfuscate with base64 encoding
    encoded = base64.b64encode(value.encode()).decode()
    anonymized = anonymize_secret(value)

    if shell == "powershell":
        return f'$env:{env_var} = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}"))  # {anonymized}'
    return f"export {env_var}=$(echo '{encoded}' | base64 -d)  # {anonymized}"
