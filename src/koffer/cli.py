"""Secure API key and token koffer CLI."""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import keyring
import pyperclip
from cryptography.exceptions import InvalidTag
from keyring.errors import KeyringError

from koffer.crypto import decrypt_value, derive_key, encrypt_value
from koffer.storage import (
    KOFFER_BACKUP_PATH,
    KOFFER_PATH,
    Koffer,
    SecretEntry,
    backup_koffer,
    entry_aad,
    load_koffer,
    save_koffer,
    should_auto_backup,
    verify_password,
)
from koffer.utils import (
    detect_shell,
    error_exit,
    format_export,
    infer_env_var,
    validate_name,
)

KEYRING_SERVICE = "koffer"
KEYRING_USERNAME = "master-password"
MAX_SECRET_LENGTH = 8192
MIN_MASTER_PASSWORD_LENGTH = 8


def _validate_master_password_strength(password: str) -> None:
    """Enforce a minimal strength policy for master password creation.

    Policy: length >= 8 and includes at least one letter, one number, and one special character.
    """
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        error_exit(f"master password too short (min {MIN_MASTER_PASSWORD_LENGTH} characters)")
    if not any(ch.isalpha() for ch in password):
        error_exit("master password must include at least one letter")
    if not any(ch.isdigit() for ch in password):
        error_exit("master password must include at least one number")
    if not any((not ch.isalnum()) for ch in password):
        error_exit("master password must include at least one special character")


def _clipboard_copy(text: str) -> None:
    pyperclip.copy(text)


def _run_subprocess(command: list[str], env: dict[str, str]) -> Any:
    return subprocess.run(command, check=False, env=env)


def _decrypt_entry_with_migration(
    _koffer: Koffer, key: bytes, entry: SecretEntry
) -> tuple[str, bool]:
    """Decrypt an entry and upgrade legacy entries to AAD-bound encryption.

    Returns (plaintext, migrated).
    """
    aad = entry_aad(entry)
    try:
        return decrypt_value(key, entry.ciphertext, entry.nonce, aad=aad), False
    except InvalidTag:
        plaintext = decrypt_value(key, entry.ciphertext, entry.nonce, aad=None)
        entry.ciphertext, entry.nonce = encrypt_value(key, plaintext, aad=aad)
        return plaintext, True


def store_password_in_keyring(password: str) -> bool:
    """Store master password in system credential store. Returns True on success."""
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, password)
        return True
    except (KeyringError, OSError) as e:
        print(
            f"Warning: could not store password in credential manager: {e}",
            file=sys.stderr,
        )
        return False


def get_password_from_keyring() -> str | None:
    """Retrieve master password from system credential store."""
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except (KeyringError, OSError):
        return None


def delete_password_from_keyring() -> None:
    """Remove master password from system credential store."""
    with contextlib.suppress(KeyringError, OSError):
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)


def get_password(confirm: bool = False, use_keyring: bool = True) -> str:
    """Prompt for master password, or retrieve from credential store."""
    if use_keyring and not confirm:
        stored = get_password_from_keyring()
        if stored:
            return stored

    password = getpass.getpass("Master password: ")
    if confirm:
        if password != getpass.getpass("Confirm password: "):
            print("Error: passwords don't match", file=sys.stderr)
            sys.exit(1)
        _validate_master_password_strength(password)
    return password


# Service -> (env_var, type, companions) mappings
# companions is optional dict of additional env vars to set when this secret is unlocked
DEFAULT_MAPPINGS: dict[str, tuple[str, str] | tuple[str, str, dict[str, str]]] = {
    # API Keys
    "openai": ("OPENAI_API_KEY", "key"),
    "anthropic": ("ANTHROPIC_API_KEY", "key"),
    "anthropic-openrouter": (
        "ANTHROPIC_AUTH_TOKEN",
        "token",
        {
            "ANTHROPIC_BASE_URL": "https://openrouter.ai/api",
            "ANTHROPIC_API_KEY": "",  # Must be empty for Claude Code
        },
    ),
    "gemini": ("GEMINI_API_KEY", "key"),
    "google": ("GOOGLE_API_KEY", "key"),
    "openrouter": ("OPENROUTER_API_KEY", "key"),
    "groq": ("GROQ_API_KEY", "key"),
    "mistral": ("MISTRAL_API_KEY", "key"),
    "cohere": ("COHERE_API_KEY", "key"),
    "together": ("TOGETHER_API_KEY", "key"),
    "perplexity": ("PERPLEXITY_API_KEY", "key"),
    "fireworks": ("FIREWORKS_API_KEY", "key"),
    "deepseek": ("DEEPSEEK_API_KEY", "key"),
    "xai": ("XAI_API_KEY", "key"),
    # Tokens
    "huggingface": ("HF_TOKEN", "token"),
    "hf": ("HF_TOKEN", "token"),
    "replicate": ("REPLICATE_API_TOKEN", "token"),
    "github": ("GITHUB_TOKEN", "token"),
    "gitlab": ("GITLAB_TOKEN", "token"),
    "ngrok": ("NGROK_AUTHTOKEN", "token"),
    "railway": ("RAILWAY_TOKEN", "token"),
    "vercel": ("VERCEL_TOKEN", "token"),
    "netlify": ("NETLIFY_AUTH_TOKEN", "token"),
    "fly": ("FLY_ACCESS_TOKEN", "token"),
    "render": ("RENDER_API_KEY", "key"),
    "aws": ("AWS_SECRET_ACCESS_KEY", "key"),
    "digitalocean": ("DIGITALOCEAN_TOKEN", "token"),
    "linode": ("LINODE_TOKEN", "token"),
    "vultr": ("VULTR_API_KEY", "key"),
    # Misc
    "discord": ("DISCORD_TOKEN", "token"),
    "slack": ("SLACK_TOKEN", "token"),
    "telegram": ("TELEGRAM_BOT_TOKEN", "token"),
    "twilio": ("TWILIO_AUTH_TOKEN", "token"),
    "sendgrid": ("SENDGRID_API_KEY", "key"),
    "stripe": ("STRIPE_API_KEY", "key"),
    "sentry": ("SENTRY_DSN", "secret"),
    "sentry_build": ("SENTRY_AUTH_TOKEN", "token"),
    "sentry_runtime": ("SENTRY_DSN", "secret"),
}


def _parse_companions(companion_args: list[str] | None) -> dict[str, str]:
    """Parse --companion VAR=VALUE arguments into a dict."""
    companions: dict[str, str] = {}
    if not companion_args:
        return companions
    for item in companion_args:
        if "=" not in item:
            error_exit(f"invalid companion format: '{item}' (expected VAR=VALUE)")
        var, _, value = item.partition("=")
        var = var.strip()
        if not var:
            error_exit("companion variable name cannot be empty")
        companions[var] = value
    return companions


def cmd_add(args: argparse.Namespace) -> None:
    """Add or update a secret."""
    name = validate_name(args.name)

    # Get defaults from mappings (supports 2-tuple or 3-tuple with companions)
    default_companions: dict[str, str] = {}
    if name in DEFAULT_MAPPINGS:
        mapping = DEFAULT_MAPPINGS[name]
        default_env, default_type = mapping[0], mapping[1]
        if len(mapping) == 3:
            default_companions = mapping[2]  # type: ignore[misc]
    else:
        default_type = args.type or "key"
        default_env = infer_env_var(name, default_type)

    env_var = args.env_var or default_env
    secret_type = args.type or default_type

    # Merge default companions with user-provided ones (user overrides defaults)
    companions = {
        **default_companions,
        **_parse_companions(getattr(args, "companion", None)),
    }

    koffer = load_koffer()
    is_new = koffer is None

    try:
        if is_new:
            print("Creating new koffer. Choose a strong master password.")
            password = get_password(confirm=True, use_keyring=False)
            koffer = Koffer(salt=secrets.token_bytes(16))
            if (not args.no_keyring) and store_password_in_keyring(password):
                print("Password stored in system credential manager.", file=sys.stderr)
        else:
            password = get_password(use_keyring=not args.no_keyring)
            key = derive_key(password, koffer.salt)
            if not verify_password(koffer, key):
                error_exit("incorrect password")

        key = derive_key(password, koffer.salt)

        type_label = {"key": "API key", "token": "token", "secret": "secret"}[secret_type]
        secret_value = getpass.getpass(f"Enter {type_label} for {name}: ")
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)

    if not secret_value:
        error_exit("empty value")
    if len(secret_value) > MAX_SECRET_LENGTH:
        error_exit(f"secret too long (max {MAX_SECRET_LENGTH} characters)")

    aad = entry_aad(
        SecretEntry(
            name=name,
            env_var=env_var,
            secret_type=secret_type,
            ciphertext=b"",
            nonce=b"",
            companions=companions,
        )
    )

    ciphertext, nonce = encrypt_value(key, secret_value, aad=aad)
    koffer.entries[name] = SecretEntry(
        name=name,
        env_var=env_var,
        secret_type=secret_type,
        ciphertext=ciphertext,
        nonce=nonce,
        companions=companions,
    )
    save_koffer(koffer)
    print(f"Stored '{name}' ({secret_type}) -> ${env_var}", file=sys.stderr)
    if companions:
        print(
            f"  with companions: {', '.join(f'${k}' for k in companions)}",
            file=sys.stderr,
        )


def cmd_remove(args: argparse.Namespace) -> None:
    """Remove a secret."""
    koffer = load_koffer()
    if koffer is None:
        error_exit("no koffer found")

    name = validate_name(args.name)
    if name not in koffer.entries:
        error_exit(f"'{name}' not found")

    try:
        key = derive_key(get_password(use_keyring=not args.no_keyring), koffer.salt)
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)

    if not verify_password(koffer, key):
        error_exit("incorrect password")

    # Auto-backup before destructive operation
    backed_up = False
    if should_auto_backup(koffer):
        backed_up = backup_koffer()

    del koffer.entries[name]
    save_koffer(koffer)
    print(f"Removed '{name}'", file=sys.stderr)
    if backed_up:
        print(
            f"Backup available at {KOFFER_BACKUP_PATH} to undo if needed.",
            file=sys.stderr,
        )


def cmd_list(_args: argparse.Namespace) -> None:
    """List stored secrets."""
    koffer = load_koffer()
    if koffer is None or not koffer.entries:
        print("No secrets stored.", file=sys.stderr)
        return

    print("Stored secrets:", file=sys.stderr)
    for name, entry in sorted(koffer.entries.items()):
        print(f"  {name} ({entry.secret_type}) -> ${entry.env_var}", file=sys.stderr)
        if entry.companions:
            for comp_var, comp_value in entry.companions.items():
                display_value = comp_value if comp_value else '""'
                print(f"    + ${comp_var}={display_value}", file=sys.stderr)


def _ensure_history_scrubbing_supported(shell: str, force: bool) -> None:
    """Fail hard when we cannot honor history scrubbing guarantees."""
    if force:
        return
    if shell in {"bash", "powershell"}:
        return
    error_exit("history scrubbing is not supported for the selected shell.")


def cmd_unlock(args: argparse.Namespace) -> None:
    """Decrypt and output shell export commands."""
    koffer = load_koffer()
    if koffer is None or not koffer.entries:
        print("# No secrets to unlock", file=sys.stderr)
        sys.exit(1)

    try:
        if not args.no_keyring:
            password = get_password_from_keyring()
            if not password:
                password = getpass.getpass("Master password: ", stream=sys.stderr)
        else:
            password = getpass.getpass("Master password: ", stream=sys.stderr)
    except KeyboardInterrupt:
        print("\n# Cancelled", file=sys.stderr)
        sys.exit(130)

    key = derive_key(password, koffer.salt)

    shell = args.shell or detect_shell()
    show_full = args.show_keys
    obfuscate = bool(getattr(args, "obfuscate", True)) and not show_full
    force_unlock = getattr(args, "force", False)

    names = {n.lower() for n in args.names} if args.names else None

    export_commands: list[str] = []
    unlocked_names: list[str] = []
    migrated_any = False
    for name, entry in sorted(koffer.entries.items()):
        if names and name not in names:
            continue
        try:
            plaintext, migrated = _decrypt_entry_with_migration(koffer, key, entry)
            migrated_any = migrated_any or migrated
            companion_info = f" (+{len(entry.companions)} companions)" if entry.companions else ""
            unlocked_names.append(f"{name} -> ${entry.env_var}{companion_info}")

            export_commands.append(
                format_export(entry.env_var, plaintext, shell, show_full=show_full)
            )
            # Add companion env vars
            for comp_var, comp_value in entry.companions.items():
                export_commands.append(
                    format_export(comp_var, comp_value, shell, show_full=show_full)
                )
        except (InvalidTag, ValueError):
            print(f"# Failed to decrypt '{name}' - wrong password?", file=sys.stderr)
            sys.exit(1)

    if migrated_any:
        save_koffer(koffer)

    if not export_commands:
        print("# No matching secrets found", file=sys.stderr)
        sys.exit(1)

    # PowerShell needs semicolons to avoid array issues with Invoke-Expression
    separator = "; " if shell == "powershell" else "\n"
    script = separator.join(export_commands)

    should_clear = not show_full and obfuscate and args.clear
    should_clear_history = not show_full and obfuscate and not args.keep_history
    if should_clear_history:
        _ensure_history_scrubbing_supported(shell, force_unlock)

    use_clipboard = not args.stdout and not show_full and obfuscate

    if show_full or not obfuscate:
        print(script)
        print(f"# Unlocked {len(export_commands)} secret(s):", file=sys.stderr)
        for name_info in unlocked_names:
            print(f"#   {name_info}", file=sys.stderr)
    elif use_clipboard:
        if should_clear_history:
            count = len(export_commands)
            if shell == "powershell":
                script = (
                    script + f"\nClear-History -Count {count + 1} -ErrorAction SilentlyContinue"
                )
            else:
                script = (
                    script
                    + f"\nfor (( _i=0; _i<{count}; _i++ )); do history -d -1 2>/dev/null || true; done; unset _i"
                )

        if should_clear:
            if shell == "powershell":
                script = script + "\nClear-Host"
            else:
                script = script + "\nclear"

        encoded = base64.b64encode(script.encode()).decode()

        if shell == "powershell":
            clipboard_content = f'[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}"))|iex'
        else:
            clipboard_content = f"echo '{encoded}'|base64 -d|source /dev/stdin"

        try:
            _clipboard_copy(clipboard_content)
            if shell == "powershell":
                print("Invoke-Expression (Get-Clipboard)")
            else:
                print(
                    'eval "$(xclip -selection clipboard -o 2>/dev/null || xsel -ob 2>/dev/null || pbpaste 2>/dev/null)"'
                )

            print(f"# Unlocked {len(export_commands)} secret(s):", file=sys.stderr)
            for name_info in unlocked_names:
                print(f"#   {name_info}", file=sys.stderr)
        except (pyperclip.PyperclipException, OSError) as e:
            print(f"# Warning: could not copy to clipboard: {e}", file=sys.stderr)
            print("# Falling back to stdout", file=sys.stderr)
            print(clipboard_content)
    else:
        if should_clear_history:
            count = len(export_commands)
            if shell == "powershell":
                script = (
                    script + f"\nClear-History -Count {count + 1} -ErrorAction SilentlyContinue"
                )
            else:
                script = (
                    script
                    + f"\nfor (( _i=0; _i<{count}; _i++ )); do history -d -1 2>/dev/null || true; done; unset _i"
                )

        if should_clear:
            if shell == "powershell":
                script = script + "\nClear-Host"
            else:
                script = script + "\nclear"

        encoded = base64.b64encode(script.encode()).decode()

        if shell == "powershell":
            print(
                f'[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}"))|iex'
            )
        else:
            print(f"echo '{encoded}'|base64 -d|source /dev/stdin")

        print(f"# Unlocked {len(export_commands)} secret(s):", file=sys.stderr)
        for name_info in unlocked_names:
            print(f"#   {name_info}", file=sys.stderr)


def cmd_rotate(args: argparse.Namespace) -> None:
    """Change master password."""
    koffer = load_koffer()
    if koffer is None:
        error_exit("no koffer found")

    try:
        print("Enter current master password.")
        old_key = derive_key(get_password(use_keyring=not args.no_keyring), koffer.salt)

        decrypted: dict[str, str] = {}
        for name, entry in koffer.entries.items():
            try:
                try:
                    decrypted[name] = decrypt_value(
                        old_key, entry.ciphertext, entry.nonce, aad=entry_aad(entry)
                    )
                except InvalidTag:
                    decrypted[name] = decrypt_value(
                        old_key, entry.ciphertext, entry.nonce, aad=None
                    )
            except (InvalidTag, ValueError):
                error_exit("incorrect password")

        print("\nEnter new master password.")
        new_password = get_password(confirm=True, use_keyring=False)
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)

    # Auto-backup before destructive operation
    if should_auto_backup(koffer):
        backup_koffer()

    koffer.salt = secrets.token_bytes(16)
    new_key = derive_key(new_password, koffer.salt)

    for name, plaintext in decrypted.items():
        entry = koffer.entries[name]
        entry.ciphertext, entry.nonce = encrypt_value(new_key, plaintext, aad=entry_aad(entry))

    save_koffer(koffer)

    if not args.no_keyring:
        delete_password_from_keyring()
        if store_password_in_keyring(new_password):
            print(
                "Master password rotated and updated in credential manager.",
                file=sys.stderr,
            )
        else:
            print("Master password rotated.", file=sys.stderr)
    else:
        print("Master password rotated.", file=sys.stderr)


def cmd_purge_keyring(_args: argparse.Namespace) -> None:
    """Remove stored master password from the credential manager."""
    try:
        existing = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except (KeyringError, OSError) as e:
        error_exit(f"could not check credential manager: {e}")

    if not existing:
        print("No stored master password found in credential manager.", file=sys.stderr)
        return

    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except (KeyringError, OSError) as e:
        error_exit(f"failed to purge credential manager: {e}")

    print("Master password removed from credential manager.", file=sys.stderr)


def cmd_store_keyring(_args: argparse.Namespace) -> None:
    """Store master password in the system credential manager."""
    koffer = load_koffer()
    if koffer is None:
        error_exit("no koffer found")

    try:
        password = getpass.getpass("Master password: ")
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)

    key = derive_key(password, koffer.salt)
    if not verify_password(koffer, key):
        error_exit("incorrect password")

    if store_password_in_keyring(password):
        print("Master password stored in credential manager.", file=sys.stderr)
    else:
        error_exit("failed to store password in credential manager")


def cmd_export(args: argparse.Namespace) -> None:
    """Export koffer to encrypted JSON (for backup/transfer)."""
    koffer = load_koffer()
    if koffer is None:
        error_exit("no koffer found")

    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(KOFFER_PATH.read_text())
        if os.name != "nt":
            output.chmod(0o600)
    except OSError as e:
        error_exit(f"failed to export koffer: {e}")

    print(f"Exported koffer to {output}", file=sys.stderr)


def cmd_import(args: argparse.Namespace) -> None:
    """Import koffer from encrypted JSON backup."""
    input_path = Path(args.input)
    if not input_path.exists():
        error_exit(f"{input_path} not found")

    if KOFFER_PATH.exists() and not args.force:
        error_exit("koffer already exists. Use --force to overwrite.")

    try:
        data = json.loads(input_path.read_text())
        Koffer.from_dict(data)
    except json.JSONDecodeError as e:
        error_exit(f"invalid JSON in koffer file: {e}")
    except (KeyError, TypeError) as e:
        error_exit(f"invalid koffer file format: {e}")
    except (OSError, ValueError) as e:
        error_exit(f"invalid koffer file: {e}")

    KOFFER_PATH.write_text(input_path.read_text())
    if os.name != "nt":
        KOFFER_PATH.chmod(0o600)
    print(f"Imported koffer from {input_path}", file=sys.stderr)


def cmd_run(args: argparse.Namespace) -> None:
    """Run a command with secrets injected into environment."""
    command = args.cmd
    if command and command[0] == "--":
        command = command[1:]

    if not command:
        error_exit("no command specified. Usage: koffer run [--names NAME...] -- <command>")

    koffer = load_koffer()
    if koffer is None or not koffer.entries:
        error_exit("no koffer found or koffer is empty")

    try:
        if not args.no_keyring:
            password = get_password_from_keyring()
            if not password:
                password = getpass.getpass("Master password: ", stream=sys.stderr)
        else:
            password = getpass.getpass("Master password: ", stream=sys.stderr)
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)

    key = derive_key(password, koffer.salt)

    names = {n.lower() for n in args.names} if args.names else None

    env = os.environ.copy()
    unlocked_names: list[str] = []
    migrated_any = False

    for name, entry in koffer.entries.items():
        if names and name not in names:
            continue
        try:
            plaintext, migrated = _decrypt_entry_with_migration(koffer, key, entry)
            migrated_any = migrated_any or migrated
            env[entry.env_var] = plaintext
            # Add companion env vars
            for comp_var, comp_value in entry.companions.items():
                env[comp_var] = comp_value
            companion_info = f" (+{len(entry.companions)} companions)" if entry.companions else ""
            unlocked_names.append(f"{name} -> ${entry.env_var}{companion_info}")
        except (InvalidTag, ValueError):
            error_exit(f"failed to decrypt '{name}' - wrong password?")

    if migrated_any:
        save_koffer(koffer)

    if not unlocked_names:
        error_exit("no matching secrets found")

    print(f"Injecting {len(unlocked_names)} secret(s):", file=sys.stderr)
    for name_info in unlocked_names:
        print(f"  {name_info}", file=sys.stderr)

    try:
        result = _run_subprocess(command, env=env)
        sys.exit(result.returncode)
    except FileNotFoundError:
        error_exit(f"command not found: {command[0]}")
    except OSError as e:
        error_exit(f"failed to run command: {e}")


def cmd_config(args: argparse.Namespace) -> None:
    """Get or set koffer configuration."""
    koffer = load_koffer()
    if koffer is None:
        error_exit("no koffer found")

    key = args.key.upper()

    if args.value is None:
        # Get mode
        value = koffer.get_config(key)
        if value is None:
            print(f"{key} is not set (default will be used)", file=sys.stderr)
        else:
            print(f"{key}={json.dumps(value)}")
    else:
        # Set mode - parse value
        raw = args.value
        if raw.lower() == "true":
            value = True
        elif raw.lower() == "false":
            value = False
        elif raw.isdigit():
            value = int(raw)
        else:
            value = raw

        koffer.set_config(key, value)
        save_koffer(koffer)
        print(f"Set {key}={json.dumps(value)}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="koffer",
        description="Secure API key and token koffer with session-based unlock..",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    Add a secret (e.g.):
        koffer add openai
        koffer add myservice --env-var MY_SECRET --type secret

    Run a command with secrets in the environment:
        koffer run -- python my_script.py

    Unlock into your current shell (recommended):
        iex (koffer unlock)                  # PowerShell
        eval "$(koffer unlock --shell bash)"   # Bash/WSL

    Tip: unlock uses the clipboard + scrubs history by default.

Install with uv:
    uv tool install koffer
""",
    )

    sub = parser.add_subparsers(dest="subcommand", required=True)

    # add
    p = sub.add_parser("add", help="Add or update a secret")
    p.add_argument("name", help="Service name (e.g., openai, github)")
    p.add_argument("--env-var", "-e", help="Custom environment variable name")
    p.add_argument(
        "--type",
        "-t",
        choices=["key", "token", "secret"],
        help="Secret type (affects default env var naming)",
    )
    p.add_argument(
        "--companion",
        "-c",
        action="append",
        metavar="VAR=VALUE",
        help="Additional env var to set when unlocking (can be repeated)",
    )
    p.add_argument("--no-keyring", action="store_true", help="Don't use system credential manager")
    p.set_defaults(func=cmd_add)

    # remove
    p = sub.add_parser("remove", help="Remove a secret")
    p.add_argument("name", help="Service name to remove")
    p.add_argument("--no-keyring", action="store_true", help="Don't use system credential manager")
    p.set_defaults(func=cmd_remove)

    # list
    p = sub.add_parser("list", help="List stored secrets")
    p.set_defaults(func=cmd_list)

    # unlock
    p = sub.add_parser("unlock", help="Decrypt and export as env vars")
    p.add_argument("names", nargs="*", help="Specific secrets to unlock (default: all)")
    p.add_argument(
        "--shell",
        "-s",
        choices=["powershell", "bash"],
        help="Shell type (auto-detected if not specified)",
    )
    p.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of clipboard (for piping)",
    )
    p.add_argument(
        "--obfuscate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Base64-wrap unlock payload to reduce accidental exposure (default: on)",
    )
    p.add_argument(
        "--show-keys",
        "--show",
        action="store_true",
        help="Show full keys in output (implies --stdout)",
    )
    p.add_argument("--clear", action="store_true", help="Clear terminal after unlocking")
    p.add_argument(
        "--keep-history",
        action="store_true",
        help="Don't remove command from shell history (default: removes)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Proceed even if history scrubbing cannot be guaranteed",
    )
    p.add_argument("--no-keyring", action="store_true", help="Don't use system credential manager")
    p.set_defaults(func=cmd_unlock)

    # rotate
    p = sub.add_parser("rotate", help="Change master password")
    p.add_argument("--no-keyring", action="store_true", help="Don't use system credential manager")
    p.set_defaults(func=cmd_rotate)

    # purge-keyring
    p = sub.add_parser(
        "purge-keyring",
        help="Remove stored master password from system credential manager",
    )
    p.set_defaults(func=cmd_purge_keyring)

    # store-keyring
    p = sub.add_parser("store-keyring", help="Store master password in system credential manager")
    p.set_defaults(func=cmd_store_keyring)

    # export
    p = sub.add_parser("export", help="Export koffer to file (backup)")
    p.add_argument("output", help="Output file path")
    p.set_defaults(func=cmd_export)

    # import
    p = sub.add_parser("import", help="Import koffer from backup")
    p.add_argument("input", help="Input file path")
    p.add_argument("--force", "-f", action="store_true", help="Overwrite existing koffer")
    p.set_defaults(func=cmd_import)

    # run
    p = sub.add_parser("run", help="Run a command with secrets in environment")
    p.add_argument(
        "--names",
        "-n",
        nargs="*",
        metavar="NAME",
        help="Specific secrets to inject (default: all)",
    )
    p.add_argument("--no-keyring", action="store_true", help="Don't use system credential manager")
    p.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (use -- before command if it has flags)",
    )
    p.set_defaults(func=cmd_run)

    # config
    p = sub.add_parser("config", help="Get or set koffer configuration")
    p.add_argument("key", help="Config key (e.g., AUTO_BACKUP)")
    p.add_argument("value", nargs="?", help="Value to set (omit to get current value)")
    p.set_defaults(func=cmd_config)

    args = parser.parse_args()

    # Handle 'run' command requiring a command argument
    if args.subcommand == "run" and (not hasattr(args, "cmd") or not args.cmd):
        parser.error("run requires a command to execute")

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
