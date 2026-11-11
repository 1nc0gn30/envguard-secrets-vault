<div align="center">
  <img src="assets/hero-banner.svg" alt="EnvGuard Secrets Vault Banner" width="100%" />
</div>

# EnvGuard Secrets Vault

[![Zoth Studio v2 Dossier](https://img.shields.io/badge/Zoth_Studio_v2-Dossier-D4AF37?style=flat-square)](https://zoth.nullai.tech/tools/envguard-secrets-vault)
[![Loopback Daemon](https://img.shields.io/badge/Daemon-127.0.0.1%3A8088-38BDF8?style=flat-square)](http://127.0.0.1:8088)
[![Cipher](https://img.shields.io/badge/Cipher-AES--256--CTR--HMAC--SHA256-1A73E8?style=flat-square)](#architecture)
[![MCP Server](https://img.shields.io/badge/MCP-11_Tools-9334E6?style=flat-square)](#cli--mcp-usage)
[![License: MIT](https://img.shields.io/badge/License-MIT-10B981?style=flat-square)](LICENSE)

Zero-dependency `.env` secret scanner, credential masker, authenticated AES-256-CTR-HMAC-SHA256 vault, GF(256) Shamir's Secret Sharing quorum engine, TTL secret rotation sentinel, and 11-tool Model Context Protocol (MCP) server.

## Overview

**EnvGuard Secrets Vault** (`envguard-secrets-vault`) is implemented in pure Python 3 standard library code (`src/envguard_secrets_vault/`) paired with a local loopback REST server (`127.0.0.1:8088`) and standalone Web Crypto browser studio (`public/index.html`). It integrates with **Zoth Studio v2** (`https://zoth.nullai.tech/tools/envguard-secrets-vault`) and **ZothOS v3.4.0**.

| Property | Value |
| :--- | :--- |
| **Tool ID** | `envguard-secrets-vault` |
| **Category** | `Security & Recon` |
| **Loopback Bind** | `127.0.0.1:8088` (`server.py` / `PORT=8088`) |
| **Zoth Studio v2 Dossier** | `https://zoth.nullai.tech/tools/envguard-secrets-vault` |
| **Local Studio Route** | `http://127.0.0.1:3000/tools/envguard-secrets-vault` |
| **Python Package** | `envguard_secrets_vault` (`requires-python >= 3.8`, zero external runtime deps) |
| **MCP Protocol** | JSON-RPC 2.0 over `stdio` (`envguard mcp` — 11 tools) |
| **License** | MIT (100% free and open-source) |

## Architecture

```mermaid
flowchart LR
    CLI["envguard CLI / bin/envguard.js"] --> CORE["src/envguard_secrets_vault"]
    MCP["MCP Clients (Claude / Cursor / Hermes)"] -->|stdio JSON-RPC 2.0| MCP_SRV["mcp_server.py (11 Tools)"]
    UI["public/index.html"] --> HTTP["server.py / ui_server.py (127.0.0.1:8088)"]
    MCP_SRV --> CORE
    HTTP --> CORE
    CORE --> SCAN["scanner.py + entropy_analyzer.py"]
    CORE --> VAULT["vault.py (PBKDF2 + AES-256-CTR-HMAC-SHA256)"]
    CORE --> SHAMIR["shamir_quorum.py (GF(256) k-of-n)"]
    CORE --> ROTATE["secret_rotation_sentinel.py"]
```

- **Secret Scanner & Entropy Analyzer (`scanner.py`, `entropy_analyzer.py`)**: Evaluates `.env` files and source trees against 50+ provider token signatures (OpenAI, Anthropic, AWS, Stripe, GitHub, Slack, JWTs, PEM private keys, database DSNs), framework client-bundle prefix leaks (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`), and alphabet-aware Shannon entropy thresholds.
- **Armored Vault (`vault.py`)**: Encrypts plaintext `.env` configurations into ASCII-armored `ENVGUARD ENCRYPTED VAULT` payloads using PBKDF2-HMAC-SHA256 key derivation and Encrypt-then-MAC (`AES-256-CTR` + `HMAC-SHA256`).
- **Shamir Quorum (`shamir_quorum.py`)**: Splits master keys or `.env` secrets over $GF(2^8)$ into $n$ armored shares requiring any $k$ shares for reconstruction.
- **Secret Rotation Sentinel (`secret_rotation_sentinel.py`)**: Parses `# @created`, `# @expires`, and `# @rotation_days` lifecycle comments, computes compliance scores, and rotates expired keys with provider-formatted replacement tokens and unified diffs.

## Quickstart

Clone the repository and install the package in editable mode:

```bash
git clone https://github.com/1nc0gn30/envguard-secrets-vault.git
cd envguard-secrets-vault
pip install -e .

# Verify CLI installation
envguard --version
envguard --help

# Start the loopback REST & Web Studio server on http://127.0.0.1:8088
python3 server.py
```

Open `http://127.0.0.1:8088` in a browser, or query the loopback REST API:

```bash
# Service health and diagnostics
curl -s http://127.0.0.1:8088/health | python3 -m json.tool
curl -s http://127.0.0.1:8088/api/diagnostics | python3 -m json.tool

# Scan raw .env content via REST
curl -s -X POST http://127.0.0.1:8088/api/scan \
  -H "Content-Type: application/json" \
  -d '{"content":"PORT=8080\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}' \
  | python3 -m json.tool
```

### REST API Endpoints (`127.0.0.1:8088`)

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/health`, `/api/health` | Service health check (`status`, `version`, `port`). |
| `GET` | `/api/diagnostics` | Runtime Python, OS, cipher suite, and detector diagnostics. |
| `GET`, `POST` | `/api/mcp/config` | Generates MCP client JSON configurations (`claude`, `cursor`, `cline`, `zed`). |
| `POST` | `/api/scan` | Scans `.env` text and returns `score`, `grade`, `passed`, and `findings`. |
| `POST` | `/api/mask` | Masks secret values (`partial` or `full` mode). |
| `POST` | `/api/example` | Generates a sanitized `.env.example` template. |
| `POST` | `/api/encrypt`, `/api/decrypt` | Encrypts or decrypts armored `ENVGUARD ENCRYPTED VAULT` payloads. |
| `POST` | `/api/diff` | Diffs two `.env` payloads for missing keys and type mismatches. |
| `POST` | `/api/shamir/split`, `/api/shamir/combine` | Splits or reconstructs GF(256) Shamir secret shares. |
| `POST` | `/api/rotation/audit`, `/api/rotation/execute` | Audits TTL metadata or rotates targeted secret keys. |
| `POST` | `/api/export-zip` | Bundles sanitized `.env.example`, audit report, and vault artifacts into a ZIP archive. |

## CLI & MCP Usage

### CLI Subcommands (`envguard` / `python3 -m envguard_secrets_vault`)

```bash
# Scan a .env file or directory (exit non-zero if below --min-score)
envguard scan examples/nextjs-env-audit/.env.production
envguard scan examples/nextjs-env-audit/.env.production --json --min-score 80

# CI/CD pre-commit security gate (text, github, json, markdown)
envguard check ./examples --min-score 85 --format json

# Redact sensitive values or generate .env.example
envguard mask examples/nextjs-env-audit/.env.production --mode partial
envguard example examples/nextjs-env-audit/.env.production --output /tmp/.env.example

# Encrypt and decrypt armored vault files
envguard encrypt /tmp/.env.example --password "StrongVaultPassword!99" --out /tmp/secrets.env.enc
envguard decrypt /tmp/secrets.env.enc --password "StrongVaultPassword!99"

# Compare two environment files
envguard diff examples/nextjs-env-audit/.env.production examples/nextjs-env-audit/.env.example --json

# Shamir's Secret Sharing (k-of-n threshold quorum)
envguard shamir split "MasterSigningSecret" --threshold 3 --shares 5 --json

# Audit secret lifetimes and execute rotation diff
envguard rotate examples/nextjs-env-audit/.env.production --audit-only --json
envguard rotate examples/nextjs-env-audit/.env.production --diff

# Launch HTTP server or print runtime platform specs
envguard serve --host 127.0.0.1 --port 8088
envguard platform
```

On **ZothOS v3.4.0**, the Node/Electron launcher (`./bin/envguard.js` / `envguard-secrets-vault`) and Unicode `U+2800` Braille TUI (`./bin/envguard-secrets-vault-tui --json`) are also available.

### Model Context Protocol (MCP) Server

Run `envguard mcp` (or `python3 -m envguard_secrets_vault mcp`) to expose all 11 tools over `stdio` JSON-RPC 2.0:

```json
{
  "mcpServers": {
    "envguard": {
      "command": "python3",
      "args": ["-m", "envguard_secrets_vault", "mcp"]
    }
  }
}
```

Exposed MCP tools: `env_scan_secrets`, `env_mask_variables`, `env_generate_example`, `env_vault_encrypt`, `env_vault_decrypt`, `env_diff_environments`, `env_get_diagnostics`, `env_shamir_split`, `env_shamir_combine`, `env_audit_rotation`, `env_rotate_secrets`.

### Python Library API

```python
from envguard_secrets_vault import (
    scan_secrets,
    vault_encrypt,
    vault_decrypt,
    split_secret_into_shares,
    combine_shares_to_secret,
)

report = scan_secrets("PORT=8088\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
encrypted = vault_encrypt("APP_ENV=production\n", "MasterPass!99")
decrypted = vault_decrypt(encrypted["vault_armor"], "MasterPass!99")

quorum = split_secret_into_shares("MasterPass!99", threshold=2, total_shares=3)
recovered = combine_shares_to_secret(quorum["shares"][:2])
```

## Documentation

- [Security Assumptions & Threat Model](docs/SECURITY_ASSUMPTIONS.md)
- [Secret Patterns & Detector Catalog](docs/SECRET_PATTERNS_CATALOG.md)
- [Model Context Protocol (MCP) Guide](docs/MCP_GUIDE.md)
- [Zero-Exposure Vault Specification](docs/ZERO_EXPOSURE_VAULT.md)
- [Examples & Reference Workflows](examples/README.md)

## Testing & Verification

```bash
# Run the full pytest suite
python3 -m pytest -q

# Run the built-in self-test command
envguard test
```

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 [1nc0gn30](https://1nc0gn30.si) (`@1nc0gn30`) & [NullAI](https://nullai.tech).

100% free and open-source with zero paywalls. Optional support: [Buy Us a Coffee (Stripe)](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X).
