# Copilot Instructions for koffer

## Project Overview
A Python CLI tool for securely managing API keys and tokens. Secrets are AES-256-GCM encrypted with Argon2id key derivation and stored in `~/.koffer.enc`. The `unlock` command outputs shell `export` commands that users `eval` to inject secrets into their current session.

## Architecture

### Core Modules
- [cli.py](../src/koffer/cli.py) - Command handlers and argparse setup. Contains `DEFAULT_MAPPINGS` for 40+ known service→env var mappings
- [storage.py](../src/koffer/storage.py) - `Koffer` and `SecretEntry` dataclasses, JSON persistence with atomic writes, `KOFFER_PATH` constant
- [crypto.py](../src/koffer/crypto.py) - `derive_key()` (Argon2id), `encrypt_value()`/`decrypt_value()` (AES-256-GCM)
- [utils.py](../src/koffer/utils.py) - Shell detection, name validation, export formatting, `error_exit()` helper

### Data Flow
1. User provides master password → `derive_key(password, salt)` → 32-byte encryption key
2. Each secret encrypted independently with unique 12-byte nonce
3. Koffer serialized as JSON with base64-encoded binary fields
4. `unlock` outputs base64-wrapped shell script to avoid secrets in command history

## Development Commands

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov

# Install in editable mode
uv sync --extra dev
```

## Testing Patterns

### Key Fixtures (in [conftest.py](../tests/conftest.py))
- `temp_vault` - Redirects `KOFFER_PATH` to temp directory; **must monkeypatch both `storage.KOFFER_PATH` and `cli.KOFFER_PATH`**
- `mock_keyring` - Replaces `keyring.*` with in-memory dict to avoid OS credential manager
- `mock_getpass` - Mock password prompts; use `side_effect` for multi-prompt sequences
- `fast_kdf` - **Critical**: Replaces Argon2id with SHA256 for speed. Applied via `pytestmark = pytest.mark.usefixtures("fast_kdf")` in test modules

### Testing CLI Commands
Commands that interact with koffer require the `fast_kdf` fixture to avoid slow Argon2 operations:
```python
pytestmark = pytest.mark.usefixtures("fast_kdf")

def test_example(temp_vault, mock_keyring, mock_getpass):
    mock_getpass.side_effect = ["password", "password", "secret-value"]
    # ... test command ...
```

### Helper for Creating Test Koffers
Use `create_test_koffer()` from [test_commands.py](../tests/test_commands.py):
```python
koffer, key = create_test_koffer(
    temp_vault,
    password="test-password",
    entries={"openai": ("OPENAI_API_KEY", "key", "sk-secret123")}
)
```

## Code Conventions

### Error Handling
Use `error_exit(message)` from utils for user-facing errors—prints to stderr and exits with code 1.

### Shell Output
- User-facing messages go to `stderr` (via `file=sys.stderr`)
- Only eval-able shell commands go to `stdout`
- The `unlock` command base64-encodes output to prevent secrets appearing in shell history

### Password Flow
Check keyring first (unless `--no-keyring`), then prompt. For new koffers, require confirmation:
```python
password = get_password(confirm=True, use_keyring=False)  # New koffer
password = get_password(use_keyring=not args.no_keyring)  # Existing koffer
```

### Adding New Services
Add to `DEFAULT_MAPPINGS` dict in [cli.py](../src/koffer/cli.py):
```python
"servicename": ("SERVICE_API_KEY", "key"),  # or "token"/"secret"
```

## Security Considerations
- Never log or print decrypted secrets except through the controlled `unlock` flow
- Koffer files use 600 permissions on Unix (user read/write only)
- Atomic writes via temp file + rename to prevent corruption
- `verify_password()` decrypts first entry to validate password before operations
