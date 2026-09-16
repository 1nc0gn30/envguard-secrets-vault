# EnvGuard Secrets Vault Examples & Reference Catalog

This directory contains production-ready examples, architectural patterns, configuration files, and workflows demonstrating how to use **EnvGuard Secrets Vault** across modern cloud frameworks, CI/CD pipelines, and AI agent environments.

---

## 📂 Example Catalog

| Directory / Example | Description | Key Deliverables |
| :--- | :--- | :--- |
| [`nextjs-env-audit/`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/nextjs-env-audit/README.md) | Next.js production audit, client bundle leak remediation (`NEXT_PUBLIC_`), and safe `.env.example` generation. | [`.env.production`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/nextjs-env-audit/.env.production), [`.env.example`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/nextjs-env-audit/.env.example) |
| [`encrypted-vault-workflow/`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/encrypted-vault-workflow/README.md) | End-to-end PBKDF2/AES-256-GCM vault encryption, verification, and zero-disk runtime injection (`envguard vault run`). | [`sample.vault`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/encrypted-vault-workflow/sample.vault) |
| [`mcp-clients/`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/mcp-clients/README.md) | Ready-to-copy Model Context Protocol (MCP) configs for Claude Desktop, Cursor, Cline, Zed, and Windsurf. | JSON configs for all major editors |

---

## ⚡ Quick CLI Cheat Sheet

```bash
# 1. Audit a directory or file for secret leaks & entropy anomalies
envguard scan .env.production
envguard audit ./src

# 2. Sanitize an existing environment file into a safe template
envguard sanitize .env.production --output .env.example

# 3. Create an AES-256-GCM encrypted vault
envguard vault create .env.production --output production.vault

# 4. View or inspect vault contents in memory
envguard vault view production.vault

# 5. Run commands with secrets injected into memory (Zero-Disk Exposure)
envguard vault run --vault production.vault -- npm run build

# 6. Convert between formats (.env, JSON, YAML, Docker Compose)
envguard convert .env.production --format json
envguard convert .env.production --format yaml
envguard convert .env.production --format docker

# 7. Start the MCP Server for AI coding assistants
envguard mcp
```

---

## 🌐 Interactive Web Studio

For an interactive browser experience with drag-and-drop auditing, multi-format transformation, and in-browser Web Crypto encryption/decryption, open [`public/index.html`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/public/index.html) in any modern web browser or serve it locally:

```bash
python3 -m http.server 8080 --directory public
```
Then navigate to `http://localhost:8080`.
