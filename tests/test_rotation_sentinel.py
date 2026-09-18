"""Tests for Secret Rotation Sentinel, Expiration & Ephemerality Engine."""

import datetime
import io
import json
from pathlib import Path

import pytest

from envguard_secrets_vault.secret_rotation_sentinel import (
    RotationStatus,
    SecretLifecycleMeta,
    RotationAuditReport,
    RotationResult,
    parse_rotation_metadata,
    audit_rotation,
    generate_ephemeral_token,
    rotate_secrets_in_content,
)
from envguard_secrets_vault.mcp_server import MCPServer
from envguard_secrets_vault.cli import main as cli_main


SAMPLE_ENV_WITH_METADATA = """# Production secrets configuration
# @owner: security-team@example.com
# @created: 2026-01-01
# @rotation_days: 30
# @expires: 2026-01-31
DATABASE_URL=postgres://app:secret123@db.prod.internal:5432/main

# @owner: payment-eng@example.com
# @created: 2026-08-01
# @rotation_days: 90
# @expires: 2026-10-30
STRIPE_SECRET_KEY=sk_test_51MzxyzFakeStripeKey1234567890

# An unmanaged secret without lifecycle metadata
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789

# @created: 2026-09-01
# @rotation_days: 15
CACHE_REDIS_AUTH=redis_secret_pass_1234
"""


def test_parse_rotation_metadata():
    """Test parsing metadata annotations above variable definitions."""
    records = parse_rotation_metadata(SAMPLE_ENV_WITH_METADATA, filename=".env.test")
    assert len(records) == 4

    # Record 1: DATABASE_URL
    r1 = records[0]
    assert r1.key == "DATABASE_URL"
    assert r1.owner == "security-team@example.com"
    assert r1.created_at == "2026-01-01"
    assert r1.rotation_days == 30
    assert r1.expires_at == "2026-01-31"

    # Record 2: STRIPE_SECRET_KEY
    r2 = records[1]
    assert r2.key == "STRIPE_SECRET_KEY"
    assert r2.owner == "payment-eng@example.com"
    assert r2.created_at == "2026-08-01"
    assert r2.rotation_days == 90
    assert r2.expires_at == "2026-10-30"

    # Record 3: GITHUB_TOKEN
    r3 = records[2]
    assert r3.key == "GITHUB_TOKEN"
    assert r3.owner is None
    assert r3.expires_at is None
    assert r3.rotation_days is None

    # Record 4: CACHE_REDIS_AUTH
    r4 = records[3]
    assert r4.key == "CACHE_REDIS_AUTH"
    assert r4.created_at == "2026-09-01"
    assert r4.rotation_days == 15
    assert r4.expires_at == "2026-09-16"  # Derived from created_at + 15 days


def test_audit_rotation_statuses():
    """Test rotation audit classification with a fixed reference date."""
    ref_date = datetime.datetime(2026, 9, 18, tzinfo=datetime.timezone.utc)
    report = audit_rotation(SAMPLE_ENV_WITH_METADATA, filename=".env.test", reference_date=ref_date)

    assert report.total_secrets == 4
    by_key = {s.key: s for s in report.secrets}

    # DATABASE_URL expired 2026-01-31 -> Overdue/Expired
    assert by_key["DATABASE_URL"].status == RotationStatus.EXPIRED.value
    assert by_key["DATABASE_URL"].days_until_expiration < 0

    # STRIPE_SECRET_KEY expires 2026-10-30 -> Active (~42 days left)
    assert by_key["STRIPE_SECRET_KEY"].status == RotationStatus.ACTIVE.value
    assert by_key["STRIPE_SECRET_KEY"].days_until_expiration > 0

    # GITHUB_TOKEN has no metadata -> Unmanaged
    assert by_key["GITHUB_TOKEN"].status == RotationStatus.UNMANAGED.value

    # CACHE_REDIS_AUTH expired 2026-09-16 -> Expired (2 days overdue)
    assert by_key["CACHE_REDIS_AUTH"].status == RotationStatus.EXPIRED.value

    # Check compliance score is calculated and between 0 and 100
    assert 0 <= report.compliance_score <= 100
    assert report.expired_count == 2
    assert report.unmanaged_count == 1
    assert report.active_count == 1


def test_ephemeral_token_generation():
    """Test generating realistic ephemeral placeholder tokens for various secret types."""
    token_stripe = generate_ephemeral_token("STRIPE_SECRET_KEY", "sk_live_12345678901234567890")
    assert token_stripe.startswith("sk_live_")

    token_stripe_test = generate_ephemeral_token("STRIPE_TEST_KEY")
    assert token_stripe_test.startswith("sk_test_")

    token_gh = generate_ephemeral_token("GITHUB_TOKEN", "ghp_1234567890abcdef")
    assert token_gh.startswith("ghp_")

    token_slack = generate_ephemeral_token("SLACK_BOT_TOKEN", "xoxb-123-456")
    assert token_slack.startswith("xoxb-")

    token_aws_key = generate_ephemeral_token("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    assert token_aws_key.startswith("AKIA")
    assert len(token_aws_key) == 20

    token_generic = generate_ephemeral_token("CUSTOM_API_SECRET", "arbitrary_val")
    assert len(token_generic) >= 32


def test_rotate_secrets_in_content():
    """Test in-place rotation with updated content and unified diff."""
    result = rotate_secrets_in_content(
        content=SAMPLE_ENV_WITH_METADATA,
        target_keys=["DATABASE_URL", "STRIPE_SECRET_KEY"],
        rotation_days=60,
        filename=".env.prod",
    )

    assert result.rotated_count == 2
    assert "DATABASE_URL" in result.rotated_keys
    assert "STRIPE_SECRET_KEY" in result.rotated_keys
    assert result.diff != ""
    assert "--- a/.env.prod" in result.diff
    assert "+++ b/.env.prod" in result.diff

    # Verify updated content has new metadata
    assert "@rotation_days: 60" in result.updated_content

    # Verify audit on rotated content shows active status
    ref_date = datetime.datetime.now(datetime.timezone.utc)
    new_report = audit_rotation(result.updated_content, reference_date=ref_date)
    by_key = {s.key: s for s in new_report.secrets}
    assert by_key["DATABASE_URL"].status == RotationStatus.ACTIVE.value
    assert by_key["STRIPE_SECRET_KEY"].status == RotationStatus.ACTIVE.value


def test_cli_rotate_audit(capsys):
    """Test CLI `envguard rotate` in audit mode."""
    temp_env = Path("tests_temp.env")
    temp_env.write_text(SAMPLE_ENV_WITH_METADATA, encoding="utf-8")
    try:
        ret = cli_main(["rotate", str(temp_env), "--audit-only", "--json"])
        # Exit code 1 signifies that expired secrets were detected during audit
        assert ret == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total_secrets"] == 4
        assert data["expired_count"] == 2
        assert "compliance_score" in data
    finally:
        if temp_env.exists():
            temp_env.unlink()


def test_cli_rotate_execute(capsys):
    """Test CLI `envguard rotate` in execution mode with --diff."""
    temp_env = Path("tests_temp_exec.env")
    temp_env.write_text(SAMPLE_ENV_WITH_METADATA, encoding="utf-8")
    try:
        ret = cli_main(["rotate", str(temp_env), "--diff"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "--- a/" in captured.out or "DATABASE_URL" in captured.out
    finally:
        if temp_env.exists():
            temp_env.unlink()


def test_mcp_rotation_tools():
    """Test MCP protocol tools env_audit_rotation and env_rotate_secrets."""
    server = MCPServer()

    # 1. Audit Tool
    req_audit = {
        "jsonrpc": "2.0",
        "id": "test-rot-1",
        "method": "tools/call",
        "params": {
            "name": "env_audit_rotation",
            "arguments": {
                "content": SAMPLE_ENV_WITH_METADATA,
                "reference_date": "2026-09-18T00:00:00Z",
            },
        },
    }
    resp_audit = server.handle_request(req_audit)
    assert resp_audit is not None
    assert resp_audit["result"]["isError"] is False
    audit_data = json.loads(resp_audit["result"]["content"][0]["text"])
    assert audit_data["total_secrets"] == 4
    assert audit_data["expired_count"] == 2

    # 2. Rotate Tool
    req_rotate = {
        "jsonrpc": "2.0",
        "id": "test-rot-2",
        "method": "tools/call",
        "params": {
            "name": "env_rotate_secrets",
            "arguments": {
                "content": SAMPLE_ENV_WITH_METADATA,
                "target_keys": ["CACHE_REDIS_AUTH"],
                "rotation_days": 45,
            },
        },
    }
    resp_rotate = server.handle_request(req_rotate)
    assert resp_rotate is not None
    assert resp_rotate["result"]["isError"] is False
    rotate_data = json.loads(resp_rotate["result"]["content"][0]["text"])
    assert rotate_data["rotated_count"] == 1
    assert "CACHE_REDIS_AUTH" in rotate_data["rotated_keys"]
