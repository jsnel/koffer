<p align="center">
    <img src="https://raw.githubusercontent.com/jsnel/koffer/main/assets/koffer-logo-readme.svg" width="640" alt="koffer" />
</p>

# `koffer >_`

A CLI tool for managing API keys and tokens. Instead of scattering `.env` files across your projects, store your secrets in one encrypted file and inject them into your shell right before you need them.

Keys are AES-256-GCM encrypted with Argon2id key derivation, decrypted only when you run `koffer unlock`.

## Why "koffer"?

"Koffer" is a versatile Dutch word for trunk, briefcase or suitcase; a strangely _suitable_ name for this project.

Koffer is designed to be an easy-to-install, portable, no-subscription keystore that works across Windows, Linux (WSL2), PowerShell, and Bash. It keeps your secrets (somewhat) organized and locked away from casual prying eyes. It is not a vault however, and it doesn't pretend to be. It's just a simple container for your API keys and other CLI secrets so they don't get lost in translation or left out in half a dozen .env files. Think of it as "carry-on" security for your development workflow.

## Features

- 🔐 **Strong encryption**: AES-256-GCM with Argon2id key derivation
- 🔑 **System keyring integration**: Optional password storage in OS credential manager
- 🐚 **Shell integration**: Works with PowerShell, Bash, and Zsh
- 📦 **Zero config**: Sensible defaults for 40+ popular services
- 💾 **Portable**: Single encrypted file, easy to backup/restore

## Installation

### Using uv

```bash
# Install as a tool (globally) using uv:
uv tool install koffer
# Install the latest (unreleased) development version:
uv tool install git+https://github.com/jsnel/koffer.git
```

## Quick Start

```bash
# Add your first secret
koffer add openai
# Enter master password (first time creates the koffer)
# Enter your API key when prompted

# Recommended: run commands with secrets injected (secrets never printed)
koffer run -- python -c "import os; print('OPENAI_API_KEY' in os.environ)"

# If you really need env vars in the current shell:
# PowerShell:
Invoke-Expression (koffer unlock)

# Bash/Zsh:
eval "$(koffer unlock)"
```

## Usage

### Add secrets

```bash
# Known services get sensible defaults
koffer add openai          # -> OPENAI_API_KEY
koffer add anthropic       # -> ANTHROPIC_API_KEY
koffer add github          # -> GITHUB_TOKEN

# Custom env var or type
koffer add myservice --env-var MY_SECRET --type secret
```

### Unlock (inject into current shell)

`unlock` is meant for convenience when tools insist on reading env vars from the current shell.
For day-to-day usage, prefer `koffer run -- <command>` so secrets never need to be printed.

**PowerShell:**
```powershell
Invoke-Expression (koffer unlock)
# or (equivalent)
koffer unlock | iex
```

**Bash / Zsh / WSL:**
```bash
eval "$(koffer unlock)"
```

**Unlock specific secrets only:**
```bash
eval "$(koffer unlock openai anthropic)"
```

> **💡 Tip:** Your master password is automatically stored in your system's credential manager (Windows Credential Manager, macOS Keychain, or Linux Secret Service) after first use. Use `--no-keyring` to disable this.

By default, `unlock` base64-wraps its payload and prefers using the clipboard to reduce accidental exposure.
If you want to inspect the generated commands, use:

```bash
# Print unlock payload to stdout (still base64-wrapped)
koffer unlock --stdout

# Print commands directly (masked, but decodable)
koffer unlock --stdout --no-obfuscate

# Show plaintext secrets (least secure)
koffer unlock --show-keys
```

### Other commands

```bash
koffer list              # Show stored secrets
koffer remove <name>     # Delete a secret
koffer rotate            # Change master password
koffer export backup.enc # Backup koffer
koffer import backup.enc # Restore koffer
koffer run -- <command>  # Run a command with secrets injected (recommended)
koffer store-keyring     # Re-store password in credential manager
koffer purge-keyring     # Remove password from credential manager
```

### Shell Profile Integration

Add to your shell profile for automatic unlocking:

**PowerShell** (`$PROFILE`):
```powershell
# Unlock API keys on shell start (optional)
if (Get-Command koffer -ErrorAction SilentlyContinue) {
    Invoke-Expression (koffer unlock 2>$null)
}
```

**Bash/Zsh** (`~/.bashrc` or `~/.zshrc`):
```bash
# Unlock API keys on shell start (optional)
command -v koffer &>/dev/null && eval "$(koffer unlock 2>/dev/null)"
```

### WSL2 Integration

To share the same koffer between Windows and WSL2, create a symlink to your Windows koffer file:

```bash
cd ~
ln -s /mnt/c/Users/<username>/.koffer.enc .koffer.enc
```

Now both environments use the same encrypted secrets.

## Security Model

| Aspect | Implementation |
|--------|----------------|
| **Encryption** | AES-256-GCM with 12-byte random nonce per secret |
| **Key derivation** | Argon2id (64 MB memory, 3 iterations, 4 parallelism) |
| **Storage** | `~/.koffer.enc` with 600 permissions (Unix) |
| **Credential storage** | Optional OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service) |

### How it works

1. Your master password derives an encryption key using Argon2id
2. Each secret is encrypted with AES-256-GCM using a unique nonce
3. The `unlock` command outputs shell `export` commands
4. You `eval` the output to set environment variables in your current shell
5. Environment variables are process-local and inherited only by child processes

### What this protects against

- ✅ Secrets at rest (encrypted on disk)
- ✅ Casual shoulder surfing (secrets are masked in output)
- ✅ Other users on shared systems (file permissions)

### What this does NOT protect against

- ❌ Malware with access to your shell's memory
- ❌ Root/admin users on the same machine
- ❌ Keyloggers capturing your master password

Remember: This is a **koffer**, not a vault. It's designed for convenience and "good enough" security for development workflows, not for high-stakes production secrets.

## Supported Services

_Supported_ is a big word here, but koffer includes default environment variable mappings for some number of services (and you can easily add your own):

**AI/ML**: OpenAI, Anthropic, Google/Gemini, Groq, Mistral, Cohere, Together, Perplexity, Fireworks, DeepSeek, xAI, HuggingFace, Replicate

**DevOps**: GitHub, GitLab, Vercel, Netlify, Railway, Fly.io, Render, Ngrok

**Cloud**: AWS, DigitalOcean, Linode, Vultr

**Communication**: Discord, Slack, Telegram, Twilio

**Other**: Stripe, SendGrid, Sentry, and more...

Unknown services default to `SERVICENAME_API_KEY` (or `_TOKEN`/`_SECRET` based on `--type`).

## Development

```bash
# Clone the repository
git clone https://github.com/jsnel/koffer.git
cd koffer

# Setup env with dev dependencies
uv sync --extra dev

# Install git hooks (runs Ruff + basic hygiene checks)
uv run pre-commit install

# Run hooks against all files
uv run pre-commit run -a

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov
```

## License

MIT License - see [LICENSE](LICENSE) for details.
