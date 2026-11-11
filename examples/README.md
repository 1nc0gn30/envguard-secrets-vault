# EnvGuard Secrets Vault Examples & Reference Catalog

This directory contains reference examples, configuration templates, and workflows demonstrating **EnvGuard Secrets Vault** across web frameworks, CI/CD pipelines, and MCP agent clients.

## Example Catalog

| Directory | Description | Key Files |
| :--- | :--- | :--- |
| [`nextjs-env-audit/`](nextjs-env-audit/README.md) | Next.js production audit, client bundle leak remediation (`NEXT_PUBLIC_`), and `.env.example` generation. | [`.env.production`](nextjs-env-audit/.env.production), [`.env.example`](nextjs-env-audit/.env.example) |
| [`encrypted-vault-workflow/`](encrypted-vault-workflow/README.md) | End-to-end PBKDF2 + AES-256-CTR-HMAC-SHA256 vault encryption and decryption workflow. | [`sample.vault`](encrypted-vault-workflow/sample.vault) |
| [`mcp-clients/`](mcp-clients/README.md) | Model Context Protocol (MCP) configurations for Claude Desktop, Cursor, Cline, and Zed. | JSON client profiles |

## CLI Reference Commands

```bash
# 1. Scan a file or directory for secret leaks and entropy anomalies
envguard scan examples/nextjs-env-audit/.env.production --json

# 2. Mask sensitive credentials (partial or full redaction)
envguard mask examples/nextjs-env-audit/.env.production --mode partial

# 3. Generate a sanitized .env.example template
envguard example examples/nextjs-env-audit/.env.production --output .env.example

# 4. Encrypt and decrypt an armored AES-256-CTR-HMAC-SHA256 vault
envguard encrypt .env.example --password "ChangeMe!99" --out sample.env.enc
envguard decrypt sample.env.enc --password "ChangeMe!99"

# 5. Split and reconstruct master keys with GF(256) Shamir's Secret Sharing
envguard shamir split "MasterSecretKey" --threshold 3 --shares 5 --json

# 6. Audit secret rotation compliance and TTL policies
envguard rotate examples/nextjs-env-audit/.env.production --audit-only

# 7. Start the stdio JSON-RPC 2.0 MCP server
envguard mcp
```

## Web Workstation

Launch the loopback REST API and browser workstation on `http://127.0.0.1:8088`:

```bash
python3 server.py
```
