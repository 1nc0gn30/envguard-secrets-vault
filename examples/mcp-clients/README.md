# EnvGuard MCP Client Configuration & AI Agent Integration Guide

This directory provides pre-configured client profiles for integrating **EnvGuard Model Context Protocol (MCP)** server with major AI coding assistants and autonomous agent runners.

---

## 🚀 Supported MCP Clients

| Client / Environment | Config File | Typical Config Location |
| :--- | :--- | :--- |
| **Claude Desktop** | [`claude_desktop_config.json`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/mcp-clients/claude_desktop_config.json) | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`<br>Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| **Cursor IDE** | [`cursor_mcp.json`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/mcp-clients/cursor_mcp.json) | `.cursor/mcp.json` (Workspace root) or Settings &gt; Features &gt; MCP |
| **Cline / Roo Code** | [`cline_mcp.json`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/mcp-clients/cline_mcp.json) | VS Code Extension MCP settings |
| **Zed Editor** | [`zed_settings.json`](file:///media/neo/f2fdda77-178b-4603-ae80-c7aa4cd97908/envguard-secrets-vault/examples/mcp-clients/zed_settings.json) | `~/.config/zed/settings.json` |

---

## 🛠️ MCP Tools Overview

When registered, the EnvGuard MCP server provides AI agents with 6 security-scoped tools:

### 1. `scan_env` (Read-Only)
- **Description:** Scans a `.env` file for secrets, leaks, and high-entropy values.
- **Parameters:** `{"file_path": string, "entropy_threshold"?: number}`
- **Response:** Summary risk score, detected providers, line numbers, and masked previews.

### 2. `audit_secrets` (Read-Only)
- **Description:** Audits the current workspace or git staging area for unencrypted credentials.
- **Parameters:** `{"target_dir"?: string, "check_git_diff"?: boolean}`
- **Response:** List of files containing potential credentials.

### 3. `sanitize_env` (Generative)
- **Description:** Creates a sanitized `.env.example` file with placeholder values while preserving comments and structure.
- **Parameters:** `{"source_file": string, "output_file"?: string}`
- **Response:** Path to generated template and count of sanitized keys.

### 4. `encrypt_vault` (Security / Write)
- **Description:** Encrypts an environment file into a portable `.vault` payload.
- **Parameters:** `{"env_file": string, "vault_file": string, "password"?: string}`
- **Response:** Metadata confirmation (`salt`, `iv`, `cipher: AES-256-GCM`).

### 5. `decrypt_vault` (Security / Read)
- **Description:** Validates authentication tag and decrypts vault keys into memory.
- **Parameters:** `{"vault_file": string, "password"?: string, "verify_only"?: boolean}`
- **Response:** Key list and validation status (raw values are masked unless explicitly requested).

### 6. `run_with_vault` (Zero-Exposure Execution)
- **Description:** Executes a subprocess with vault secrets injected directly into process memory without disk persistence.
- **Parameters:** `{"vault_file": string, "command": string[], "password"?: string}`
- **Response:** Subprocess exit code, stdout, and stderr.

---

## 🔒 Recommended Agent System Prompt Rules

To ensure AI agents never accidentally output raw secrets into chat transcripts, include the following directive in your system prompt or `.cursorrules` / `CLAUDE.md`:

```markdown
### Secrets & Environment Variable Policy
1. NEVER output unmasked secret values, database passwords, or private API keys in chat responses.
2. When managing secrets, always use EnvGuard MCP tools (`scan_env`, `sanitize_env`, `run_with_vault`).
3. To run builds, tests, or servers requiring credentials, use `run_with_vault` rather than asking the user for plaintext environment files.
4. When committing code, verify with `audit_secrets` that no `.env` files or hardcoded credentials are included in git staging.
```

---

## 💻 Quick Start Setup Example (Cursor)

1. Create `.cursor/mcp.json` in your repository:
   ```bash
   mkdir -p .cursor
   cp examples/mcp-clients/cursor_mcp.json .cursor/mcp.json
   ```
2. Restart Cursor or reload MCP servers in **Settings &gt; Features &gt; MCP**.
3. Prompt Cursor:
   > *"Run an EnvGuard scan on our environment templates and verify we have no exposed keys."*
