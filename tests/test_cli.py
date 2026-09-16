"""Unit tests for EnvGuard CLI Commands."""

import json
from pathlib import Path
import pytest

from envguard_secrets_vault.cli import main, run_internal_tests


def test_cli_help(capsys):
    """Test CLI help menu display."""
    res = main([])
    assert res == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out or "usage:" in captured.err or "EnvGuard" in captured.out


def test_cli_scan_clean_and_dirty(tmp_path: Path, capsys):
    """Test scan command with clean and dirty .env files."""
    clean_env = tmp_path / ".env.clean"
    clean_env.write_text("PORT=8080\nNODE_ENV=production\n")

    dirty_env = tmp_path / ".env.dirty"
    dirty_env.write_text("OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890\n")

    # Clean scan
    res_clean = main(["scan", str(clean_env)])
    assert res_clean == 0
    out_clean = capsys.readouterr().out
    assert "[PASS]" in out_clean

    # Dirty scan
    res_dirty = main(["scan", str(dirty_env)])
    assert res_dirty == 1
    out_dirty = capsys.readouterr().out
    assert "[FAIL]" in out_dirty

    # JSON scan
    res_json = main(["scan", str(dirty_env), "--json"])
    assert res_json == 1
    out_json = capsys.readouterr().out
    parsed = json.loads(out_json)
    assert parsed["score"] < 80


def test_cli_mask(tmp_path: Path, capsys):
    """Test mask command writing to file and stdout."""
    env_file = tmp_path / ".env"
    env_file.write_text("PORT=3000\nAPI_KEY=sk-1234567890abcdef1234567890\n")
    masked_out = tmp_path / ".env.masked"

    # Write to file
    res = main(["mask", str(env_file), "-o", str(masked_out), "--mode", "partial"])
    assert res == 0
    assert masked_out.exists()
    content = masked_out.read_text(encoding="utf-8")
    assert "PORT=3000" in content
    assert "****" in content

    # Write to stdout
    res_stdout = main(["mask", str(env_file)])
    assert res_stdout == 0
    out = capsys.readouterr().out
    assert "PORT=3000" in out


def test_cli_example(tmp_path: Path, capsys):
    """Test example command writing sanitized placeholders."""
    env_file = tmp_path / ".env"
    env_file.write_text("PORT=8080\nOPENAI_API_KEY=sk-proj-abc123xyz456\n")
    example_out = tmp_path / ".env.example"

    res = main(["example", str(env_file), "-o", str(example_out)])
    assert res == 0
    assert example_out.exists()
    content = example_out.read_text(encoding="utf-8")
    assert 'OPENAI_API_KEY="your-openai-api-key-here"' in content


def test_cli_encrypt_decrypt_roundtrip(tmp_path: Path):
    """Test encrypt and decrypt subcommands round-trip."""
    orig_env = tmp_path / ".env"
    secret_text = "DATABASE_URL=postgres://admin:pwd@prod:5432/app\n"
    orig_env.write_text(secret_text)

    enc_file = tmp_path / ".env.enc"
    dec_file = tmp_path / ".env.decrypted"
    pwd = "MySecretMasterPassword!2026"

    # Encrypt
    res_enc = main(["encrypt", str(orig_env), "-p", pwd, "-o", str(enc_file)])
    assert res_enc == 0
    assert enc_file.exists()
    assert "-----BEGIN ENVGUARD ENCRYPTED VAULT-----" in enc_file.read_text()

    # Decrypt
    res_dec = main(["decrypt", str(enc_file), "-p", pwd, "-o", str(dec_file)])
    assert res_dec == 0
    assert dec_file.exists()
    assert dec_file.read_text() == secret_text


def test_cli_diff(tmp_path: Path, capsys):
    """Test diff subcommand comparing two environments."""
    env_a = tmp_path / ".env.a"
    env_b = tmp_path / ".env.b"
    env_a.write_text("PORT=3000\nDEBUG=true\n")
    env_b.write_text("PORT=8080\nNODE_ENV=prod\n")

    res = main(["diff", str(env_a), str(env_b)])
    assert res == 0
    out = capsys.readouterr().out
    assert "DEBUG" in out or "NODE_ENV" in out

    # JSON diff
    res_json = main(["diff", str(env_a), str(env_b), "--json"])
    assert res_json == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["total_keys_a"] == 2


def test_cli_check(tmp_path: Path):
    """Test check subcommand for CI gate."""
    clean = tmp_path / ".env.clean"
    clean.write_text("PORT=8080\n")
    assert main(["check", str(clean), "--min-score", "90"]) == 0

    dirty = tmp_path / ".env.dirty"
    dirty.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    assert main(["check", str(dirty), "--min-score", "90"]) == 1


def test_cli_platform(capsys):
    """Test platform diagnostics command."""
    res = main(["platform"])
    assert res == 0
    out = capsys.readouterr().out
    assert "System Runtime" in out
    assert "Crypto Capabilities" in out
    assert "AES-256-CTR" in out


def test_cli_mcp_config(capsys):
    """Test mcp --config command."""
    res = main(["mcp", "--config", "claude"])
    assert res == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "claude_desktop" in parsed


def test_cli_internal_tests():
    """Test built-in test runner."""
    res = run_internal_tests()
    assert res == 0
    res_main = main(["test"])
    assert res_main == 0


def test_cli_missing_files_error_handling(capsys):
    """Test error handling for non-existent files."""
    assert main(["mask", "non_existent_file.env"]) == 1
    assert main(["example", "non_existent_file.env"]) == 1
    assert main(["encrypt", "non_existent_file.env", "-p", "pwd"]) == 1
    assert main(["decrypt", "non_existent_file.enc", "-p", "pwd"]) == 1
    assert main(["diff", "non1.env", "non2.env"]) == 1
