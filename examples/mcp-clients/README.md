# EnvGuard MCP Client Configuration & AI Agent Integration Guide

This directory provides client configuration templates for connecting the **EnvGuard Secrets Vault** stdio JSON-RPC 2.0 Model Context Protocol (MCP) server (`envguard mcp`) to AI coding assistants and agent runners.

## Supported MCP Clients

| Client / Environment | Config File | Typical Config Location |
| :--- | :--- | :--- |
| **Claude Desktop** | [`claude_desktop_config.json`](claude_desktop_config.json) | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`<br>Linux: `~/.config/Claude/claude_desktop_config.json` |
| **Cursor IDE** | [`cursor_mcp.json`](cursor_mcp.json) | `.cursor/mcp.json` (workspace root) |
| **Cline / Roo Code** | [`cline_mcp.json`](cline_mcp.json) | VS Code extension MCP settings |
| **Zed Editor** | [`zed_settings.json`](zed_settings.json) | `~/.config/zed/settings.json` |

You can also print ready-to-paste client snippets directly from the CLI:

```bash
envguard mcp --config all
```

## Registered MCP Tools (11 Tools)

1. **`env_scan_secrets`** — Scans `.env` content or files/directories against 50+ provider signatures and Shannon entropy thresholds, returning a 0-100 security score and findings list.
2. **`env_mask_variables`** — Redacts sensitive secret values using `partial` or `full` masking while preserving non-sensitive configuration keys.
3. **`env_generate_example`** — Synthesizes a sanitized `.env.example` file with typed placeholders.
4. **`env_vault_encrypt`** — Encrypts `.env` content into an armored PBKDF2-HMAC-SHA256 + AES-256-CTR-HMAC-SHA256 vault block.
5. **`env_vault_decrypt`** — Verifies the HMAC-SHA256 authentication tag and decrypts an armored vault block in memory.
6. **`env_diff_environments`** — Compares two `.env` configurations for missing keys, added keys, and inferred type mismatches.
7. **`env_get_diagnostics`** — Returns runtime Python, OS, cipher suite, and detector catalog diagnostics.
8. **`env_shamir_split`** — Splits a secret into $n$ GF(256) Shamir threshold shares requiring $k$ shares to reconstruct.
9. **`env_shamir_combine`** — Reconstructs the original secret from $k$ armored Shamir shares.
10. **`env_audit_rotation`** — Audits `# @created`, `# @expires`, and `# @rotation_days` metadata annotations for TTL compliance.
11. **`env_rotate_secrets`** — Generates provider-aware replacement tokens and unified diffs for expired or targeted keys.
