"""Unit tests for Shamir's Secret Sharing (SSS) & Distributed Key Quorum Engine."""

import json
import pytest

from envguard_secrets_vault.shamir_quorum import (
    GF256_EXP,
    GF256_LOG,
    SecretShare,
    ShamirSecretSharing,
    combine_shares_to_secret,
    gf256_add,
    gf256_div,
    gf256_eval_poly,
    gf256_mul,
    gf256_sub,
    split_secret_into_shares,
)
from envguard_secrets_vault.mcp_server import MCPServer
from envguard_secrets_vault.cli import main as cli_main


# ============================================================================
# GF(2^8) Galois Field Arithmetic Tests
# ============================================================================

def test_gf256_basic_arithmetic():
    assert gf256_add(0x53, 0xCA) == 0x99
    assert gf256_sub(0x53, 0xCA) == 0x99
    assert gf256_add(42, 42) == 0
    assert gf256_mul(0, 100) == 0
    assert gf256_mul(100, 0) == 0
    assert gf256_mul(1, 42) == 42
    assert gf256_mul(42, 1) == 42

    # Inversion / division property: (a * b) / b == a for b != 0
    for a in [1, 7, 53, 128, 255]:
        for b in [1, 3, 19, 87, 254]:
            prod = gf256_mul(a, b)
            quot = gf256_div(prod, b)
            assert quot == a


def test_gf256_division_by_zero():
    with pytest.raises(ZeroDivisionError):
        gf256_div(42, 0)


def test_gf256_eval_poly():
    # Constant poly: P(x) = 15
    assert gf256_eval_poly([15], 0) == 15
    assert gf256_eval_poly([15], 10) == 15

    # Linear poly: P(x) = 7 + 3*x
    assert gf256_eval_poly([7, 3], 0) == 7
    expected_at_2 = gf256_add(7, gf256_mul(3, 2))
    assert gf256_eval_poly([7, 3], 2) == expected_at_2


# ============================================================================
# Core Shamir (k, n) Threshold Splitting and Reconstruction
# ============================================================================

def test_shamir_split_and_reconstruct_exact_k():
    secret = "DATABASE_URL=postgres://master:supersecret123@prod.internal:5432/db"
    k, n = 3, 5
    shares = ShamirSecretSharing.split_secret(secret, threshold=k, total_shares=n)
    assert len(shares) == n

    # Reconstruct with exact k shares: {1, 2, 3}
    rec_text = ShamirSecretSharing.reconstruct_secret_text(shares[:k])
    assert rec_text == secret

    # Reconstruct with different subset: {2, 4, 5}
    subset = [shares[1], shares[3], shares[4]]
    rec_text_subset = ShamirSecretSharing.reconstruct_secret_text(subset)
    assert rec_text_subset == secret


def test_shamir_reconstruct_all_n_shares():
    secret = "OPENAI_API_KEY=sk-proj-99887766554433221100"
    k, n = 4, 7
    shares = ShamirSecretSharing.split_secret(secret, threshold=k, total_shares=n)
    # Reconstruct with all 7 shares (should take first k)
    rec_text = ShamirSecretSharing.reconstruct_secret_text(shares)
    assert rec_text == secret


def test_shamir_quorum_threshold_unmet():
    secret = "JWT_SECRET=super_high_entropy_token"
    k, n = 3, 5
    shares = ShamirSecretSharing.split_secret(secret, threshold=k, total_shares=n)
    # Attempt reconstruction with only k-1 = 2 shares
    with pytest.raises(ValueError, match="Quorum threshold not met"):
        ShamirSecretSharing.reconstruct_secret(shares[:2])


def test_shamir_duplicate_shares_handled():
    secret = "STRIPE_SECRET_KEY=sk_live_1234567890abcdef"
    k, n = 3, 5
    shares = ShamirSecretSharing.split_secret(secret, threshold=k, total_shares=n)
    # Provide share #1 three times -> distinct count is 1 < 3
    with pytest.raises(ValueError, match="Quorum threshold not met"):
        ShamirSecretSharing.reconstruct_secret([shares[0], shares[0], shares[0]])


def test_shamir_binary_payload_roundtrip():
    secret_bytes = bytes([0x00, 0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE])
    k, n = 2, 4
    shares = ShamirSecretSharing.split_secret(secret_bytes, threshold=k, total_shares=n)
    rec_bytes = ShamirSecretSharing.reconstruct_secret([shares[0], shares[2]])
    assert rec_bytes == secret_bytes


def test_shamir_invalid_arguments():
    with pytest.raises(ValueError, match="Invalid threshold"):
        ShamirSecretSharing.split_secret("secret", threshold=1, total_shares=5)

    with pytest.raises(ValueError, match="Invalid threshold"):
        ShamirSecretSharing.split_secret("secret", threshold=6, total_shares=5)

    with pytest.raises(ValueError, match="Secret cannot be empty"):
        ShamirSecretSharing.split_secret("", threshold=3, total_shares=5)


# ============================================================================
# Armored Envelope Serialization & Deserialization
# ============================================================================

def test_share_armor_roundtrip():
    secret = "MY_VAULT_PASSWORD_2026"
    shares = ShamirSecretSharing.split_secret(secret, threshold=3, total_shares=5, label="dev-vault")
    share = shares[0]
    armor = share.to_armor()
    assert "-----BEGIN ENVGUARD SECRET SHARE-----" in armor
    assert "-----END ENVGUARD SECRET SHARE-----" in armor
    assert "Index: 1/5" in armor

    restored_share = SecretShare.from_armor(armor)
    assert restored_share.share_index == share.share_index
    assert restored_share.threshold == share.threshold
    assert restored_share.total_shares == share.total_shares
    assert restored_share.data_bytes == share.data_bytes
    assert restored_share.checksum == share.checksum


def test_combine_shares_from_armor_strings():
    secret = "POSTGRES_PASSWORD=UltraSecretPass987!"
    split_res = split_secret_into_shares(secret, threshold=3, total_shares=5)
    armored = split_res["armored_shares"]

    # Reconstruct from armored strings
    comb_res = combine_shares_to_secret([armored[0], armored[2], armored[4]])
    assert comb_res["is_text"] is True
    assert comb_res["secret_text"] == secret


# ============================================================================
# MCP Server Integration Tests
# ============================================================================

def test_mcp_env_shamir_split_and_combine():
    mcp = MCPServer()
    secret = "ANTHROPIC_API_KEY=sk-ant-api03-abcdef1234567890"

    split_resp = mcp.execute_tool(
        "env_shamir_split",
        {
            "secret": secret,
            "threshold": 3,
            "total_shares": 5,
            "label": "anthropic-key",
        },
    )
    assert split_resp["threshold"] == 3
    assert len(split_resp["shares"]) == 5
    assert len(split_resp["armored_shares"]) == 5

    # Combine back using 3 of the armored shares
    shares_subset = [split_resp["armored_shares"][1], split_resp["armored_shares"][3], split_resp["armored_shares"][4]]
    comb_resp = mcp.execute_tool("env_shamir_combine", {"shares": shares_subset})
    assert comb_resp["is_text"] is True
    assert comb_resp["secret_text"] == secret


# ============================================================================
# CLI Command Tests
# ============================================================================

def test_cli_shamir_split_and_combine_json(capsys):
    secret = "SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
    ret = cli_main(["shamir", "split", secret, "-k", "2", "-n", "3", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["threshold"] == 2
    assert len(data["armored_shares"]) == 3

    # Now combine using CLI with --share flags
    s1 = data["armored_shares"][0]
    s2 = data["armored_shares"][1]
    ret2 = cli_main(["shamir", "combine", "--share", s1, "--share", s2, "--json"])
    assert ret2 == 0
    captured2 = capsys.readouterr()
    comb_data = json.loads(captured2.out)
    assert comb_data["secret_text"] == secret
