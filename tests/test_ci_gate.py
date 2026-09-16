"""Unit tests for EnvGuard CI/CD Security Gate."""

import json
import os
import sys
import tempfile
from pathlib import Path
import pytest

from envguard_secrets_vault.ci_gate import main, run_security_check


def test_ci_gate_clean_pass(tmp_path: Path):
    """Clean .env with no secrets should pass with 100/100 score."""
    clean_env = tmp_path / ".env"
    clean_env.write_text(
        "PORT=8080\n"
        "NODE_ENV=production\n"
        "HOST=localhost\n"
        "DEBUG=false\n"
        "LOG_LEVEL=info\n"
    )

    passed, result, output_text = run_security_check(str(clean_env), min_score=80)
    assert passed is True
    assert result["score"] == 100
    assert result["grade"] == "A+"
    assert result["metrics"]["critical_count"] == 0
    assert "[PASS] PASSED" in output_text


def test_ci_gate_critical_secret_fails(tmp_path: Path):
    """Leaked AWS and OpenAI keys should fail the CI gate due to critical findings."""
    leaked_env = tmp_path / ".env"
    leaked_env.write_text(
        "PORT=3000\n"
        "OPENAI_API_KEY=sk-proj-dummyOpenAiKey00000000000000000000\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    )

    passed, result, output_text = run_security_check(str(leaked_env), min_score=80, fail_on_critical=True)
    assert passed is False
    assert result["score"] <= 50
    assert result["metrics"]["critical_count"] >= 2
    assert "[FAIL] FAILED" in output_text
    assert "SEC001" in output_text
    assert "SEC003" in output_text


def test_ci_gate_output_formats(tmp_path: Path):
    """Tests JSON, GitHub, and Markdown output formats."""
    env_file = tmp_path / ".env"
    env_file.write_text("STRIPE_SECRET_KEY=sk_mock_dummyStripeKey00000000000000000000\n")

    # JSON format
    passed_json, res_json, out_json = run_security_check(str(env_file), output_format="json")
    parsed = json.loads(out_json)
    assert "ci_gate" in parsed
    assert parsed["ci_gate"]["passed"] is False

    # GitHub format
    passed_gh, res_gh, out_gh = run_security_check(str(env_file), output_format="github")
    assert "::error file=" in out_gh
    assert "::notice title=EnvGuard Security Gate" in out_gh

    # Markdown format
    passed_md, res_md, out_md = run_security_check(str(env_file), output_format="markdown")
    assert "## 🛡️ EnvGuard Secrets Vault CI Gate Summary" in out_md
    assert "❌ **FAILED**" in out_md


def test_ci_gate_fail_on_critical_toggle(tmp_path: Path):
    """When fail_on_critical is False, gate depends solely on min_score."""
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890\n")  # -25 pts -> score 75

    # Should pass with min_score=70 and fail_on_critical=False
    passed, res, _ = run_security_check(str(env_file), min_score=70, fail_on_critical=False)
    assert passed is True

    # Should fail if min_score=80
    passed_fail, _, _ = run_security_check(str(env_file), min_score=80, fail_on_critical=False)
    assert passed_fail is False


def test_ci_gate_github_step_summary(tmp_path: Path, monkeypatch):
    """Verifies that markdown report is written to GITHUB_STEP_SUMMARY when set."""
    summary_file = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    env_file = tmp_path / ".env"
    env_file.write_text("PORT=8080\n")

    run_security_check(str(env_file))
    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "EnvGuard Secrets Vault CI Gate Summary" in content


def test_ci_gate_cli_main(tmp_path: Path):
    """Tests CLI entry point return codes."""
    clean_file = tmp_path / ".env.clean"
    clean_file.write_text("PORT=8080\nNODE_ENV=production\n")

    dirty_file = tmp_path / ".env.dirty"
    dirty_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")

    report_out = tmp_path / "report.txt"

    # Clean should return 0
    assert main([str(clean_file), "--output", str(report_out)]) == 0
    assert report_out.exists()

    # Dirty should return 1
    assert main([str(dirty_file)]) == 1


def test_ci_gate_nonexistent_target():
    """Nonexistent target should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        run_security_check("/path/does/not/exist/.env")
