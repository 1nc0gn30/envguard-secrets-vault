"""Unit tests for EnvGuard Secrets Studio UI Server & REST API Endpoints."""

import io
import json
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
import pytest

from envguard_secrets_vault.ui_server import create_server


@pytest.fixture(scope="module")
def test_server():
    """Spin up a real local ThreadingHTTPServer on an OS-assigned free port (0)."""
    server = create_server(host="127.0.0.1", port=0)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{host}:{port}"
    yield base_url
    server.shutdown()
    server.server_close()


def _request(url: str, method: str = "GET", data: dict = None, headers: dict = None):
    """Helper to perform HTTP requests using pure urllib."""
    req_headers = headers or {}
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.headers, resp.read()


# ============================================================================
# API Endpoint Tests
# ============================================================================

def test_api_health(test_server: str):
    """Test /api/health endpoint."""
    status, headers, body = _request(f"{test_server}/api/health")
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["status"] == "ok"
    assert data["app"] == "envguard-secrets-vault"
    assert "version" in data


def test_api_mcp_config(test_server: str):
    """Test /api/mcp/config endpoint."""
    status, _, body = _request(f"{test_server}/api/mcp/config?client=claude")
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert "claude_desktop" in data


def test_api_diagnostics(test_server: str):
    """Test /api/diagnostics endpoint."""
    status, _, body = _request(f"{test_server}/api/diagnostics")
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert "platform" in data
    assert "crypto_suite" in data


def test_api_scan(test_server: str):
    """Test POST /api/scan endpoint."""
    payload = {
        "content": "PORT=8080\nOPENAI_API_KEY=sk-proj-1234567890abcdef1234567890\n",
        "min_score": 80,
    }
    status, _, body = _request(f"{test_server}/api/scan", method="POST", data=payload)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["score"] < 80
    assert data["metrics"]["critical_count"] >= 1


def test_api_mask(test_server: str):
    """Test POST /api/mask endpoint."""
    payload = {
        "content": "PORT=3000\nSECRET_KEY=abcdef1234567890\n",
        "mode": "partial",
    }
    status, _, body = _request(f"{test_server}/api/mask", method="POST", data=payload)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert "PORT=3000" in data["masked_content"]
    assert "****" in data["masked_content"]


def test_api_example(test_server: str):
    """Test POST /api/example endpoint."""
    payload = {
        "content": "PORT=8080\nOPENAI_API_KEY=sk-proj-1234567890\n",
    }
    status, _, body = _request(f"{test_server}/api/example", method="POST", data=payload)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert 'OPENAI_API_KEY="your-openai-api-key-here"' in data["example_content"]


def test_api_encrypt_decrypt_roundtrip(test_server: str):
    """Test POST /api/encrypt and POST /api/decrypt endpoints."""
    raw_env = "DATABASE_URL=postgres://user:pass@localhost:5432/test\n"
    pwd = "MyMasterPassword123!"

    # Encrypt
    enc_status, _, enc_body = _request(
        f"{test_server}/api/encrypt",
        method="POST",
        data={"content": raw_env, "password": pwd},
    )
    assert enc_status == 200
    enc_data = json.loads(enc_body.decode("utf-8"))
    vault_armor = enc_data["vault_armor"]
    assert "-----BEGIN ENVGUARD ENCRYPTED VAULT-----" in vault_armor

    # Decrypt
    dec_status, _, dec_body = _request(
        f"{test_server}/api/decrypt",
        method="POST",
        data={"vault_armor": vault_armor, "password": pwd},
    )
    assert dec_status == 200
    dec_data = json.loads(dec_body.decode("utf-8"))
    assert dec_data["decrypted_content"] == raw_env


def test_api_diff(test_server: str):
    """Test POST /api/diff endpoint."""
    payload = {
        "env_a": "PORT=3000\nDEBUG=true\n",
        "env_b": "PORT=8080\nNODE_ENV=prod\n",
    }
    status, _, body = _request(f"{test_server}/api/diff", method="POST", data=payload)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["total_keys_a"] == 2
    assert "NODE_ENV" in data["keys_only_in_b"]


def test_api_export_zip(test_server: str):
    """Test POST /api/export-zip generates valid ZIP archive with all artifacts."""
    payload = {"content": "PORT=8080\nOPENAI_API_KEY=sk-proj-abc123xyz456\n"}
    status, headers, body = _request(
        f"{test_server}/api/export-zip",
        method="POST",
        data=payload,
    )
    assert status == 200
    assert "application/zip" in headers.get("Content-Type", "")

    # Parse and inspect ZIP archive in-memory
    zip_buf = io.BytesIO(body)
    with zipfile.ZipFile(zip_buf, "r") as zf:
        namelist = zf.namelist()
        assert ".env.example" in namelist
        assert ".env.masked" in namelist
        assert "audit-report.json" in namelist
        assert "mcp-configs/claude_desktop.json" in namelist
        assert "README.md" in namelist

        example_text = zf.read(".env.example").decode("utf-8")
        assert 'OPENAI_API_KEY="your-openai-api-key-here"' in example_text


def test_static_html_fallback(test_server: str):
    """Test GET / returns HTML Studio page."""
    status, headers, body = _request(f"{test_server}/")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    html = body.decode("utf-8")
    assert "EnvGuard" in html
    assert "Secrets" in html or "Vault" in html


def test_api_rotation_endpoints(test_server: str):
    """Test POST /api/rotation/audit and /api/rotation/execute."""
    sample = (
        "# @created: 2026-01-01\n"
        "# @expires: 2026-01-30\n"
        "DATABASE_URL=postgres://user:pass@localhost:5432/db\n"
    )
    # 1. Audit
    st, _, body = _request(
        f"{test_server}/api/rotation/audit",
        method="POST",
        data={"content": sample, "reference_date": "2026-09-18T00:00:00Z"},
    )
    assert st == 200
    data = json.loads(body.decode("utf-8"))
    assert data["total_secrets"] == 1
    assert data["expired_count"] == 1

    # 2. Execute
    st2, _, body2 = _request(
        f"{test_server}/api/rotation/execute",
        method="POST",
        data={"content": sample, "rotation_days": 45},
    )
    assert st2 == 200
    data2 = json.loads(body2.decode("utf-8"))
    assert data2["rotated_count"] == 1
    assert "DATABASE_URL" in data2["rotated_keys"]
    assert "@rotation_days: 45" in data2["updated_content"]

