"""
Unit and integration tests for EnvGuard Secrets Vault production examples,
vault decryption, MCP client configurations, Web UI, and CI/CD workflow assets.
"""

import json
import os
import base64
import re
import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_repo_file(rel_path: str) -> str:
    path = os.path.join(REPO_ROOT, rel_path)
    assert os.path.exists(path), f"Expected file does not exist: {rel_path}"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def parse_dotenv_lines(content: str) -> dict:
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip().strip("'\"")
    return result


class TestNextJsExample:
    """Tests for examples/nextjs-env-audit/"""

    def test_production_env_structure_and_vulnerabilities(self):
        content = read_repo_file("examples/nextjs-env-audit/.env.production")
        env = parse_dotenv_lines(content)

        assert "PORT" in env
        assert "DATABASE_URL" in env
        assert "OPENAI_API_KEY" in env
        assert "NEXT_PUBLIC_STRIPE_SECRET_KEY" in env
        assert "AWS_ACCESS_KEY_ID" in env
        assert "GITHUB_PERSONAL_ACCESS_TOKEN" in env

        # Verify dangerous patterns are present in vulnerable example
        assert env["NEXT_PUBLIC_STRIPE_SECRET_KEY"].startswith(("sk_live_", "sk_test_", "sk_mock_"))
        assert env["OPENAI_API_KEY"].startswith("sk-proj-")
        assert env["GITHUB_PERSONAL_ACCESS_TOKEN"].startswith("ghp_")
        assert "postgres_admin" in env["DATABASE_URL"]

    def test_example_sanitized_template(self):
        content = read_repo_file("examples/nextjs-env-audit/.env.example")
        env = parse_dotenv_lines(content)

        assert len(env) >= 10
        # Verify no live credentials exist in sanitized template
        for k, v in env.items():
            assert not v.startswith("sk_live_"), f"Live secret found in .env.example: {k}={v}"
            assert not v.startswith("sk-proj-"), f"Live OpenAI key found in .env.example: {k}={v}"
            assert not v.startswith("ghp_"), f"Live GitHub token found in .env.example: {k}={v}"
            assert not v.startswith("sk-ant-api"), f"Live Claude token found in .env.example: {k}={v}"
            assert "UltraSecret" not in v, f"Password found in .env.example: {k}={v}"

    def test_readme_exists(self):
        content = read_repo_file("examples/nextjs-env-audit/README.md")
        assert "# Next.js Production Environment Security Audit Example" in content
        assert "NEXT_PUBLIC_" in content
        assert "envguard scan" in content


class TestEncryptedVaultWorkflow:
    """Tests for examples/encrypted-vault-workflow/ and cryptography interoperability."""

    def test_sample_vault_schema_and_integrity(self):
        content = read_repo_file("examples/encrypted-vault-workflow/sample.vault")
        assert "-----BEGIN ENVGUARD ENCRYPTED VAULT-----" in content
        assert "cipher: AES-256-CTR-HMAC-SHA256" in content
        assert "kdf: PBKDF2-HMAC-SHA256" in content
        assert "iterations: 100000" in content
        assert "salt:" in content
        assert "iv:" in content
        assert "hmac:" in content
        assert "-----END ENVGUARD ENCRYPTED VAULT-----" in content

    def test_sample_vault_decryption_with_correct_password(self):
        from envguard_secrets_vault.mcp_server import vault_decrypt
        content = read_repo_file("examples/encrypted-vault-workflow/sample.vault")
        password = "envguard-demo-password-2026!"
        res = vault_decrypt(content, password)
        assert res["cipher"] == "AES-256-CTR-HMAC-SHA256"
        decrypted_text = res["decrypted_content"]

        env = parse_dotenv_lines(decrypted_text)
        assert env["NODE_ENV"] == "production"
        assert env["PORT"] == "8080"
        assert "orders" in env["DATABASE_URL"]
        assert "DEMO" in env["OPENAI_API_KEY"]
        assert "DEMO" in env["STRIPE_SECRET_KEY"]
        assert "redis_token_demo" in env["REDIS_URL"]
        assert env["AWS_ACCESS_KEY_ID"] == "AKIAIOSFODNN7EXAMPLE"

    def test_sample_vault_decryption_fails_with_wrong_password(self):
        from envguard_secrets_vault.mcp_server import vault_decrypt
        content = read_repo_file("examples/encrypted-vault-workflow/sample.vault")
        wrong_password = "wrong-password-12345"
        with pytest.raises(ValueError, match="Authentication failed"):
            vault_decrypt(content, wrong_password)

    def test_sample_vault_decryption_fails_with_tampered_ciphertext(self):
        from envguard_secrets_vault.mcp_server import vault_decrypt
        content = read_repo_file("examples/encrypted-vault-workflow/sample.vault")
        lines = content.splitlines()
        tampered_lines = []
        for line in lines:
            if line.startswith("TCk/QYEPHI"):
                tampered_lines.append("XCk/QYEPHI" + line[10:])
            else:
                tampered_lines.append(line)
        tampered_content = "\n".join(tampered_lines)
        with pytest.raises(ValueError, match="Authentication failed"):
            vault_decrypt(tampered_content, "envguard-demo-password-2026!")

    def test_vault_readme_exists(self):
        content = read_repo_file("examples/encrypted-vault-workflow/README.md")
        assert "# Encrypted Vault Workflow Example" in content
        assert "PBKDF2-HMAC-SHA256" in content
        assert "AES-256-CTR-HMAC-SHA256" in content
        assert "envguard vault run" in content


class TestMcpClientConfigs:
    """Tests for examples/mcp-clients/ JSON configs and documentation."""

    def test_claude_desktop_config(self):
        content = read_repo_file("examples/mcp-clients/claude_desktop_config.json")
        cfg = json.loads(content)
        assert "mcpServers" in cfg
        assert "envguard" in cfg["mcpServers"]
        server = cfg["mcpServers"]["envguard"]
        assert "command" in server
        assert "args" in server

    def test_cursor_mcp_config(self):
        content = read_repo_file("examples/mcp-clients/cursor_mcp.json")
        cfg = json.loads(content)
        assert "mcpServers" in cfg
        assert "envguard-secrets" in cfg["mcpServers"]
        server = cfg["mcpServers"]["envguard-secrets"]
        assert "command" in server

    def test_cline_mcp_config(self):
        content = read_repo_file("examples/mcp-clients/cline_mcp.json")
        cfg = json.loads(content)
        assert "mcpServers" in cfg
        assert "envguard" in cfg["mcpServers"]
        assert "autoApprove" in cfg["mcpServers"]["envguard"]

    def test_zed_settings_config(self):
        content = read_repo_file("examples/mcp-clients/zed_settings.json")
        cfg = json.loads(content)
        assert "context_servers" in cfg
        assert "envguard" in cfg["context_servers"]

    def test_mcp_clients_readme(self):
        content = read_repo_file("examples/mcp-clients/README.md")
        assert "# EnvGuard MCP Client Configuration & AI Agent Integration Guide" in content
        assert "scan_env" in content
        assert "run_with_vault" in content


class TestGoogleSecretsStudioUI:
    """Tests for public/index.html UI features, branding, and integrity."""

    def test_html_structure_and_material_theme(self):
        content = read_repo_file("public/index.html")

        # HTML5 doctype & title
        assert "<!DOCTYPE html>" in content
        assert "<title>EnvGuard Secrets Studio" in content

        # Google color palette
        assert "#1a73e8" in content
        assert "#1e8e3e" in content
        assert "#d93025" in content
        assert "#f9ab00" in content
        assert "#9334e6" in content

        # Google brand dots
        assert "dot-blue" in content
        assert "dot-red" in content
        assert "dot-yellow" in content
        assert "dot-green" in content

        # 4 Interactive Workspace Tabs
        assert ("Live Secret Auditor & Scanner" in content or "Live Secret Auditor &amp; Scanner" in content)
        assert ("Format Transformer & Exporter" in content or "Format Transformer &amp; Exporter" in content)
        assert "Zero-Exposure Encrypted Vault" in content
        assert ("AI Agent & MCP" in content or "AI Agent &amp; MCP" in content)

        # Web Crypto integration
        assert "window.crypto.subtle" in content
        assert "PBKDF2" in content
        assert "AES" in content

        # Zero tracking scripts
        assert "google-analytics.com" not in content
        assert "googletagmanager.com" not in content
        assert "cdn." not in content


class TestGitHubWorkflows:
    """Tests validating GitHub Action workflow YAML files."""

    def test_ci_matrix_workflow(self):
        content = read_repo_file(".github/workflows/ci.yml")
        workflow = yaml.safe_load(content)

        assert workflow["name"] == "CI Matrix"
        jobs = workflow["jobs"]
        matrix = jobs["test-matrix"]["strategy"]["matrix"]

        os_list = matrix["os"]
        assert "ubuntu-latest" in os_list
        assert "macos-latest" in os_list
        assert "windows-latest" in os_list

        py_list = matrix["python-version"]
        assert "3.9" in py_list
        assert "3.10" in py_list
        assert "3.11" in py_list
        assert "3.12" in py_list
        assert "3.13" in py_list

        # Verify 3 OS * 5 Python = 15 Matrix Combinations
        assert len(os_list) * len(py_list) == 15

    def test_release_workflow(self):
        content = read_repo_file(".github/workflows/release.yml")
        workflow = yaml.safe_load(content)

        assert workflow["name"] == "Release & Packaging"
        assert "jobs" in workflow
        assert "build-and-release" in workflow["jobs"]

    def test_env_security_gate_workflow(self):
        content = read_repo_file(".github/workflows/env-security-gate.yml")
        workflow = yaml.safe_load(content)

        assert workflow["name"] == "EnvGuard Security Gate"
        assert "secret-scan-gate" in workflow["jobs"]


class TestDocumentation:
    """Tests validating documentation presence, size, and headings."""

    def test_secret_patterns_catalog(self):
        content = read_repo_file("docs/SECRET_PATTERNS_CATALOG.md")
        assert len(content) > 1000
        assert "# EnvGuard Secret Patterns & Detector Catalog" in content
        assert "Shannon Entropy" in content
        assert "NEXT_PUBLIC_" in content
        assert "OpenAI" in content
        assert "Anthropic" in content
        assert "Stripe" in content

    def test_mcp_guide(self):
        content = read_repo_file("docs/MCP_GUIDE.md")
        assert len(content) > 1000
        assert "# EnvGuard Model Context Protocol (MCP) Server Guide" in content
        assert "scan_env" in content
        assert "audit_secrets" in content
        assert "sanitize_env" in content
        assert "encrypt_vault" in content
        assert "decrypt_vault" in content
        assert "run_with_vault" in content

    def test_zero_exposure_vault_doc(self):
        content = read_repo_file("docs/ZERO_EXPOSURE_VAULT.md")
        assert len(content) > 1000
        assert "# EnvGuard Zero-Exposure Vault Architecture" in content
        assert "AES-256-CTR-HMAC-SHA256" in content
        assert "PBKDF2-HMAC-SHA256" in content
        assert "Zero-Disk Execution Engine" in content

    def test_root_readme(self):
        content = read_repo_file("README.md")
        assert len(content) > 1000
        assert "# 🛡️ EnvGuard Secrets Vault" in content
        assert "EnvGuard Secrets Studio" in content
        assert "Quick Start (CLI)" in content
        assert "Python API Reference" in content

    def test_examples_index_readme(self):
        content = read_repo_file("examples/README.md")
        assert len(content) > 500
        assert "# EnvGuard Secrets Vault Examples & Reference Catalog" in content
        assert "nextjs-env-audit" in content
        assert "encrypted-vault-workflow" in content
        assert "mcp-clients" in content
