"""Unit tests for EnvGuard Model Context Protocol (MCP) Server & Core Engines."""

import json
from pathlib import Path
import pytest

from envguard_secrets_vault.mcp_server import (
    MCP_PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    MCPServer,
    calculate_shannon_entropy,
    diff_environments,
    generate_env_example,
    generate_mcp_client_config,
    get_diagnostics,
    mask_env_content,
    scan_file_or_dir,
    scan_secrets,
    vault_decrypt,
    vault_encrypt,
)


@pytest.fixture
def mcp():
    return MCPServer()


# ============================================================================
# JSON-RPC Protocol Tests
# ============================================================================

def test_mcp_initialize(mcp: MCPServer):
    """Test MCP protocol initialize handshake."""
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    resp = mcp.handle_request(req)
    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == SERVER_NAME
    assert resp["result"]["serverInfo"]["version"] == SERVER_VERSION


def test_mcp_ping(mcp: MCPServer):
    """Test MCP ping."""
    req = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    resp = mcp.handle_request(req)
    assert resp is not None
    assert resp["id"] == 2
    assert resp["result"] == {}


def test_mcp_notifications(mcp: MCPServer):
    """Initialized notification should return None (no response required)."""
    req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    resp = mcp.handle_request(req)
    assert resp is None


def test_mcp_tools_list(mcp: MCPServer):
    """Test listing all registered MCP tools."""
    req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    resp = mcp.handle_request(req)
    assert resp is not None
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert len(tools) == 9
    assert "env_scan_secrets" in tool_names
    assert "env_mask_variables" in tool_names
    assert "env_generate_example" in tool_names
    assert "env_vault_encrypt" in tool_names
    assert "env_vault_decrypt" in tool_names
    assert "env_diff_environments" in tool_names
    assert "env_get_diagnostics" in tool_names
    assert "env_shamir_split" in tool_names
    assert "env_shamir_combine" in tool_names


def test_mcp_unknown_tool(mcp: MCPServer):
    """Unknown tool execution should return error."""
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "non_existent_tool", "arguments": {}},
    }
    resp = mcp.handle_request(req)
    assert resp is not None
    assert "error" in resp
    assert resp["error"]["code"] == -32601


# ============================================================================
# Tool 1: env_scan_secrets
# ============================================================================

def test_tool_env_scan_secrets(mcp: MCPServer, tmp_path: Path):
    """Test secret scanning tool with various tokens."""
    sample = (
        "PORT=8080\n"
        "OPENAI_API_KEY=sk-proj-dummyOpenAiKey00000000000000000000\n"
        "ANTHROPIC_API_KEY=sk-ant-1234567890abcdef1234567890\n"
        "DATABASE_URL=postgres://user:secret1234@localhost:5432/main\n"
    )
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "env_scan_secrets",
            "arguments": {"content": sample},
        },
    }
    resp = mcp.handle_request(req)
    assert resp is not None
    assert resp["result"]["isError"] is False
    res_data = json.loads(resp["result"]["content"][0]["text"])
    assert res_data["score"] < 50
    assert res_data["metrics"]["critical_count"] >= 3


# ============================================================================
# Tool 2: env_mask_variables
# ============================================================================

def test_tool_env_mask_variables(mcp: MCPServer):
    """Test variable masking in partial and full modes."""
    sample = (
        "# Server config\n"
        "PORT=3000\n"
        "NODE_ENV=production\n"
        "API_SECRET=supersecrettoken1234567890\n"
    )
    # Partial mask
    req_part = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "env_mask_variables",
            "arguments": {"content": sample, "mode": "partial"},
        },
    }
    resp_part = mcp.handle_request(req_part)
    res_part = json.loads(resp_part["result"]["content"][0]["text"])
    assert "PORT=3000" in res_part["masked_content"]
    assert "NODE_ENV=production" in res_part["masked_content"]
    assert "API_SECRET=supe********7890" in res_part["masked_content"]

    # Full mask
    req_full = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "env_mask_variables",
            "arguments": {"content": sample, "mode": "full"},
        },
    }
    resp_full = mcp.handle_request(req_full)
    res_full = json.loads(resp_full["result"]["content"][0]["text"])
    assert "API_SECRET=**************************" in res_full["masked_content"]


# ============================================================================
# Tool 3: env_generate_example
# ============================================================================

def test_tool_env_generate_example(mcp: MCPServer):
    """Test sanitized .env.example generator."""
    sample = (
        "PORT=8000\n"
        "OPENAI_API_KEY=sk-proj-abc123xyz456\n"
        "DATABASE_URL=postgres://app:pwd@db.host:5432/app\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    )
    req = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "env_generate_example",
            "arguments": {"content": sample},
        },
    }
    resp = mcp.handle_request(req)
    res = json.loads(resp["result"]["content"][0]["text"])
    example = res["example_content"]
    assert "PORT=8000" in example
    assert 'OPENAI_API_KEY="your-openai-api-key-here"' in example
    assert 'AWS_ACCESS_KEY_ID="your-aws-access-key-id"' in example
    assert "postgresql://user:password@localhost:5432/dbname" in example


# ============================================================================
# Tool 4 & 5: env_vault_encrypt & env_vault_decrypt
# ============================================================================

def test_tool_vault_crypto_roundtrip(mcp: MCPServer):
    """Test armored vault encryption and decryption round-trip."""
    secret_env = "DATABASE_URL=postgres://admin:TopSecret123@prod:5432/db\nSTRIPE_KEY=sk_live_123456\n"
    pwd = "CorrectMasterPassword#2026"

    # Encrypt
    enc_req = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "env_vault_encrypt",
            "arguments": {"content": secret_env, "password": pwd},
        },
    }
    enc_resp = mcp.handle_request(enc_req)
    assert enc_resp["result"]["isError"] is False
    enc_data = json.loads(enc_resp["result"]["content"][0]["text"])
    vault_armor = enc_data["vault_armor"]
    assert "-----BEGIN ENVGUARD ENCRYPTED VAULT-----" in vault_armor
    assert "iterations: 100000" in vault_armor

    # Decrypt with correct password
    dec_req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "env_vault_decrypt",
            "arguments": {"vault_armor": vault_armor, "password": pwd},
        },
    }
    dec_resp = mcp.handle_request(dec_req)
    assert dec_resp["result"]["isError"] is False
    dec_data = json.loads(dec_resp["result"]["content"][0]["text"])
    assert dec_data["decrypted_content"] == secret_env

    # Decrypt with WRONG password should return error
    bad_req = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "env_vault_decrypt",
            "arguments": {"vault_armor": vault_armor, "password": "WrongPassword!"},
        },
    }
    bad_resp = mcp.handle_request(bad_req)
    assert bad_resp["result"]["isError"] is True
    assert "Authentication failed" in bad_resp["result"]["content"][0]["text"]


# ============================================================================
# Tool 6: env_diff_environments
# ============================================================================

def test_tool_env_diff(mcp: MCPServer):
    """Test environment differ tool."""
    env_dev = "PORT=3000\nDEBUG=true\nLOG_LEVEL=debug\nSECRET_KEY=12345\n"
    env_prod = "PORT=8080\nDEBUG=false\nREDIS_URL=redis://prod:6379\nSECRET_KEY=99999\n"

    req = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "env_diff_environments",
            "arguments": {
                "env_a": env_dev,
                "env_b": env_prod,
                "name_a": "Dev",
                "name_b": "Prod",
            },
        },
    }
    resp = mcp.handle_request(req)
    res = json.loads(resp["result"]["content"][0]["text"])
    assert "LOG_LEVEL" in res["keys_only_in_a"]
    assert "REDIS_URL" in res["keys_only_in_b"]
    assert res["differences_count"] >= 3


# ============================================================================
# Tool 7: env_get_diagnostics & Client Configs
# ============================================================================

def test_tool_diagnostics_and_client_configs(mcp: MCPServer):
    """Test diagnostics retrieval and MCP client config generator."""
    req = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {"name": "env_get_diagnostics", "arguments": {}},
    }
    resp = mcp.handle_request(req)
    res = json.loads(resp["result"]["content"][0]["text"])
    assert res["app"] == SERVER_NAME
    assert res["total_detectors"] >= 15
    assert "AES-256-CTR" in res["crypto_suite"]["cipher"]

    # Client configs
    configs = generate_mcp_client_config("all")
    assert "claude_desktop" in configs
    assert "cursor" in configs
    assert "cline" in configs
    assert "zed" in configs
