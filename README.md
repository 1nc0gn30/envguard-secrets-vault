# 🛡️ EnvGuard Secrets Vault

<p align="center">
  <strong>Zero-Exposure Environment Security, AES-256-GCM Secrets Vault, Multi-Format Transformer &amp; AI Agent MCP Server</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security_Grade-A%2B_Certified-1e8e3e?style=for-the-badge&logoColor=white" alt="Security Grade A+">
  <img src="https://img.shields.io/badge/Cipher-AES--256--GCM-1a73e8?style=for-the-badge&logo=lock&logoColor=white" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/MCP-Protocol_Ready-9334e6?style=for-the-badge&logo=anthropic&logoColor=white" alt="MCP Ready">
  <img src="https://img.shields.io/badge/Python-3.9_--_3.13-f9ab00?style=for-the-badge&logo=python&logoColor=white" alt="Python Support">
  <img src="https://img.shields.io/badge/License-Apache_2.0-202124?style=for-the-badge" alt="License">
</p>

---

## 🌟 Overview

**EnvGuard Secrets Vault** is a next-generation secrets security platform and developer toolkit designed for modern cloud architectures, CI/CD pipelines, and autonomous AI coding agents.

It replaces fragile `.env` file handling with **military-grade envelope encryption (AES-256-GCM + PBKDF2)**, scans 50+ provider token patterns, calculates Shannon entropy, identifies dangerous framework prefix leaks (e.g., Next.js `NEXT_PUBLIC_`), injects secrets into runtime processes with **zero disk writes**, and exposes a standardized **Model Context Protocol (MCP)** server for AI assistants (Claude Desktop, Cursor, Cline, Zed).

---

## 🚀 Key Highlights

- 🛡️ **Live Secret Auditor & Scanner:** 50+ detection signatures (OpenAI, Anthropic, AWS, Stripe, GitHub, Slack, DB passwords, JWTs, Private Keys) + Shannon entropy scoring.
- 🔐 **Zero-Exposure Encrypted Vault:** Authenticated AES-256-GCM payload with PBKDF2-HMAC-SHA256 key derivation.
- ⚡ **Zero-Disk Process Execution (`envguard vault run`):** Decrypts secrets directly into process RAM and child environment blocks. No plaintext touches disk.
- 🔄 **Format Transformer & Exporter:** Bidirectional conversion between `.env`, JSON, YAML, Docker Compose, and Kubernetes Secrets.
- 🤖 **Native Model Context Protocol (MCP) Server:** 6 standardized tools (`scan_env`, `audit_secrets`, `sanitize_env`, `encrypt_vault`, `decrypt_vault`, `run_with_vault`) for AI agents.
- 🌐 **EnvGuard Secrets Studio UI (`public/index.html`):** Offline-first web app (design influenced by Material 3) with Web Crypto API encryption, risk gauges, and preset inspection.

---

## 📦 Installation

```bash
# Via pip
pip install envguard-secrets-vault

# Or using uv
uv pip install envguard-secrets-vault
```

---

## ⚡ Quick Start (CLI)

### 1. Audit Environment Files for Secret Leaks
```bash
# Scan a specific environment file
envguard scan .env.production

# Deep recursive scan of workspace
envguard audit ./src
```

### 2. Generate Safe Sanitized Template (`.env.example`)
```bash
envguard sanitize .env.production --output .env.example
```

### 3. Create an Encrypted Vault File
```bash
envguard vault create .env.production --output secrets.vault
```

### 4. Zero-Disk Runtime Execution
```bash
# Run application with secrets injected directly into memory
envguard vault run --vault secrets.vault -- npm start

# Python Web Server
envguard vault run --vault secrets.vault -- uvicorn app.main:app --port 8080
```

### 5. Multi-Format Transformation
```bash
# Convert .env to JSON
envguard convert .env.production --format json

# Convert .env to Docker Compose format
envguard convert .env.production --format docker
```

---

## 🐍 Python API Reference

```python
from envguard_secrets_vault import Vault, SecretAuditor, Sanitizer

# 1. Audit an environment file
auditor = SecretAuditor()
report = auditor.scan_file(".env.production")
print(f"Security Grade: {report.grade} ({report.score}/100)")
for finding in report.findings:
    print(f"[{finding.severity}] {finding.key}: {finding.recommendation}")

# 2. Encrypt to Vault
vault = Vault.encrypt_file(
    source_path=".env.production",
    password="your-master-password"
)
vault.save("secrets.vault")

# 3. Decrypt in memory (Zero Disk Leak)
env_vars = Vault.load("secrets.vault").decrypt("your-master-password")
print(f"Loaded {len(env_vars)} variables into RAM.")
```

---

## 🤖 AI Agent & MCP Integration

EnvGuard includes a standard Model Context Protocol (MCP) server that empowers AI coding agents to manage and use secrets securely:

```json
{
  "mcpServers": {
    "envguard": {
      "command": "python3",
      "args": ["-m", "envguard.mcp"],
      "env": {
        "ENVGUARD_VAULT_PASSWORD": "${ENVGUARD_VAULT_PASSWORD}"
      }
    }
  }
}
```

See the [MCP Client Integration Guide](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/docs/MCP_GUIDE.md) for Claude Desktop, Cursor, Cline, and Zed configurations.

---

## 🌐 EnvGuard Secrets Studio Web UI (Design Influenced by Material 3)

Open [`public/index.html`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/public/index.html) in your browser or run:

```bash
python3 -m http.server 8080 --directory public
```
Navigate to `http://localhost:8080` for:
- 🛡️ Interactive Secret Auditor with 0-100 Grade Gauge.
- 🔄 Format Transformer (Dotenv, JSON, YAML, Docker Compose, Kubernetes Secret).
- 🔐 In-Browser Web Crypto AES-256-GCM Encrypted Vault.
- 🤖 AI Agent MCP Config Generator.

---

## 📚 Documentation

- [Secret Patterns & Detector Catalog](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/docs/SECRET_PATTERNS_CATALOG.md)
- [Model Context Protocol (MCP) Guide](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/docs/MCP_GUIDE.md)
- [Zero-Exposure Vault Specification](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/docs/ZERO_EXPOSURE_VAULT.md)
- [Next.js Production Audit Example](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/nextjs-env-audit/README.md)
- [Encrypted Vault Workflow Example](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/encrypted-vault-workflow/README.md)

---

## 📄 License

Apache License 2.0. Copyright (c) 2026 EnvGuard Contributors.
