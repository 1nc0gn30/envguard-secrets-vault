"""Comprehensive unit tests for SecretScanner and Entropy Engine (scanner.py)."""

from pathlib import Path
from typing import Any, Dict

import pytest

from envguard_secrets_vault.scanner import (
    SECRET_RULES,
    SecretScanner,
    calculate_entropy,
    is_high_entropy,
)


class TestEntropyCalculations:
    def test_empty_string_entropy(self):
        assert calculate_entropy("") == 0.0

    def test_single_character_entropy(self):
        assert calculate_entropy("a") == 0.0
        assert calculate_entropy("aaaaaaaaaaaa") == 0.0

    def test_uniform_distribution_entropy(self):
        # 2 equally likely symbols -> 1.0 bit
        assert calculate_entropy("abababab") == 1.0
        # 4 equally likely symbols -> 2.0 bits
        assert calculate_entropy("abcdabcd") == 2.0

    def test_high_entropy_random_strings(self):
        high_ent = "K8x9#mP2$vL5!qR7&wT1*yZ4"
        assert calculate_entropy(high_ent) > 4.0
        assert is_high_entropy(high_ent, threshold=3.5, min_length=16) is True

    def test_is_high_entropy_length_guard(self):
        # Short string should fail min_length guard
        assert is_high_entropy("aB3!", threshold=2.0, min_length=16) is False


class TestSecretPatternRules:
    @pytest.fixture
    def scanner(self):
        return SecretScanner()

    def test_rule_catalogue_count(self):
        assert len(SECRET_RULES) >= 40

    @pytest.mark.parametrize(
        "key,val,expected_provider,expected_sev",
        [
            ("OPENAI_KEY", "sk-proj-" + "abc123XYZ456_7890defghijklmnopqrst", "OpenAI", "CRITICAL"),
            ("OPENAI_LEGACY", "sk-" + "abcdef1234567890abcdef123456", "OpenAI", "CRITICAL"),
            ("ANTHROPIC_KEY", "sk-ant-api03-" + "abcdef1234567890_XYZabcdefghij", "Anthropic", "CRITICAL"),
            ("STRIPE_SECRET", "sk_mock_" + "dummyStripeKey00000000000000000000", "Stripe", "CRITICAL"),
            ("STRIPE_RK", "rk_mock_" + "dummyStripeRk00000000000000000000", "Stripe", "CRITICAL"),
            ("STRIPE_PK", "pk_mock_" + "51ABCDefgh12345678901234567890", "Stripe", "LOW"),
            ("AWS_ACCESS_KEY_ID", "AKIA" + "IOSFODNN7EXAMPLE", "AWS", "HIGH"),
            ("AWS_TEMP_KEY", "ASIA" + "IOSFODNN7EXAMPLE", "AWS", "HIGH"),
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS", "CRITICAL"),
            ("GITHUB_PAT", "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz", "GitHub", "CRITICAL"),
            ("GITHUB_OAUTH", "gho_" + "1234567890abcdefghijklmnopqrstuvwxyz", "GitHub", "CRITICAL"),
            ("GITHUB_FINE", "github_pat_" + "11AAAAAAA0000000000000_1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop", "GitHub", "CRITICAL"),
            ("GITHUB_APP", "ghu_" + "1234567890abcdefghijklmnopqrstuvwxyz", "GitHub", "HIGH"),
            ("GOOGLE_MAPS_KEY", "AIza" + "SyD-1234567890abcdefghijklmnopqrst", "Google", "HIGH"),
            ("SLACK_BOT_TOKEN", "xoxb-mock-" + "0000000000-0000000000-dummyTokenExample000", "Slack", "CRITICAL"),
            ("SLACK_USER_TOKEN", "xoxp-mock-" + "0000000000-0000000000-dummyTokenExample000", "Slack", "HIGH"),
            ("SLACK_WEBHOOK", "https://hooks.slack.com/services/" + "T000/B000/XXXX", "Slack", "HIGH"),
            ("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJpc3MiOiJzdXBhYmFzZSJ9.secret_signature_here", "Supabase", "CRITICAL"),
            ("SUPABASE_TOKEN", "sbp_" + "0123456789abcdef0123456789abcdef01234567", "Supabase", "MEDIUM"),
            ("NETLIFY_TOKEN", "nfp_" + "abcdef1234567890abcdef1234567890abcdef123456", "Netlify", "CRITICAL"),
            ("VERCEL_TOKEN", "abcdef1234567890abcdef12", "Vercel", "CRITICAL"),
            ("TELEGRAM_TOKEN", "123456789:" + "ABCdefGHIjklMNOpqrsTUVwxyz123456789", "Telegram", "HIGH"),
            ("SENDGRID_API_KEY", "SG." + "1234567890123456789012.1234567890123456789012345678901234567890123", "SendGrid", "CRITICAL"),
            ("TWILIO_SID", "AC" + "0123456789abcdef0123456789abcdef", "Twilio", "MEDIUM"),
            ("TWILIO_AUTH_TOKEN", "0123456789abcdef0123456789abcdef", "Twilio", "CRITICAL"),
            ("DATABASE_URL", "postgresql://dbuser:mypassword123@localhost:5432/production_db", "PostgreSQL", "CRITICAL"),
            ("MYSQL_URL", "mysql://root:secretpass@127.0.0.1:3306/ecommerce", "MySQL", "CRITICAL"),
            ("MONGO_URI", "mongodb+srv://admin:clusterpass123@cluster0.abc.mongodb.net/test", "MongoDB", "CRITICAL"),
            ("REDIS_URL", "redis://:p@ssw0rd123@cache.internal:6379", "Redis", "HIGH"),
            ("MAILGUN_KEY", "key-" + "0123456789abcdef0123456789abcdef", "Mailgun", "HIGH"),
            ("HUGGINGFACE_TOKEN", "hf_" + "abcdefghijklmnopqrstuvwxyz0123456789", "HuggingFace", "HIGH"),
            ("COHERE_API_KEY", "1234567890abcdefghijklmnopqrstuvwxyz0123", "Cohere", "HIGH"),
            ("NPM_TOKEN", "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz", "NPM", "CRITICAL"),
            ("PYPI_TOKEN", "pypi-AgEIcHlwaS5vcmcCJ" + "DEyMzQ1Njc4LTkwYWItY2RlZi0xMjM0LTU2Nzg5MGFiY2RlZgACKls", "PyPI", "CRITICAL"),
            ("DATADOG_API_KEY", "0123456789abcdef0123456789abcdef", "Datadog", "HIGH"),
            ("GITLAB_PAT", "glpat-" + "0123456789abcdefghij", "GitLab", "CRITICAL"),
            ("DISCORD_BOT_TOKEN", "OTk5OTk5OTk5OTk5OTk5OTk5." + "ABCDEF.1234567890abcdefghijklmnopqrst", "Discord", "CRITICAL"),
            ("SQUARE_TOKEN", "sq0atp-" + "1234567890abcdefghijkA", "Square", "CRITICAL"),
            ("SQUARE_SECRET", "sq0csp-" + "1234567890abcdefghijklmnopqrstuvwxyz012345", "Square", "CRITICAL"),
        ],
    )
    def test_provider_detection(
        self,
        scanner: SecretScanner,
        key: str,
        val: str,
        expected_provider: str,
        expected_sev: str,
    ):
        env_content = f"{key}={val}\n"
        result = scanner.scan_env_text(env_content)
        assert result["exposed_secret_count"] >= 1
        providers = [f["provider"] for f in result["findings"]]
        severities = [f["severity"] for f in result["findings"]]
        assert expected_provider in providers
        assert expected_sev in severities

    def test_private_key_detection(self, scanner: SecretScanner):
        rsa_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1+5kXyQ/...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        res = scanner.scan_env_text(f"SERVER_KEY=\"{rsa_key}\"\n")
        assert res["exposed_secret_count"] >= 1
        finding = res["findings"][0]
        assert finding["severity"] == "CRITICAL"
        assert "RSA Private Key" in finding["description"] or "Private Key" in finding["description"]


class TestSecurityGradingAndScoring:
    @pytest.fixture
    def scanner(self):
        return SecretScanner()

    def test_clean_env_grade_a_plus(self, scanner: SecretScanner):
        clean_content = (
            "# Clean environment configuration\n"
            "NODE_ENV=production\n"
            "PORT=8080\n"
            "HOST=0.0.0.0\n"
            "ENABLE_METRICS=true\n"
            "APP_NAME=MyApp\n"
        )
        result = scanner.scan_env_text(clean_content)
        assert result["grade"] == "A+"
        assert result["score"] == 100
        assert result["exposed_secret_count"] == 0
        assert result["total_keys"] == 5

    def test_critical_leaks_cause_f_grade(self, scanner: SecretScanner):
        leaked_content = (
            "OPENAI_API_KEY=sk-proj-dummyOpenAiKey00000000000000000000\n"
            + "STRIPE_SECRET_KEY=sk_mock_" + "dummyStripeKey00000000000000000000\n"
            + "DATABASE_URL=postgres://admin:supersecretpassword@localhost:5432/db\n"
            + "GITHUB_PAT=ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz\n"
            + "SENDGRID_API_KEY=SG." + "1234567890123456789012.1234567890123456789012345678901234567890123\n"
        )
        result = scanner.scan_env_text(leaked_content)
        assert result["grade"] == "F"
        assert result["score"] == 0
        assert result["exposed_secret_count"] >= 5
        assert result["categories"]["CRITICAL"] >= 4

    def test_export_prefix_and_quotes(self, scanner: SecretScanner):
        content = 'export OPENAI_API_KEY="sk-proj-abcdef123456789012345678"\n'
        result = scanner.scan_env_text(content)
        assert result["exposed_secret_count"] == 1
        assert result["findings"][0]["key"] == "OPENAI_API_KEY"

    def test_commented_out_secret_ignored(self, scanner: SecretScanner):
        content = "# OPENAI_KEY=sk-proj-abcdef123456789012345678\nPORT=3000\n"
        result = scanner.scan_env_text(content)
        assert result["exposed_secret_count"] == 0
        assert result["grade"] == "A+"

    def test_generic_high_entropy_secret_heuristic(self, scanner: SecretScanner):
        # A 32-char high-entropy random key under sensitive variable name
        content = "APP_SECRET_TOKEN=k9#mP2$vL5!qR7&wT1*yZ4@jK0^bN8~x\n"
        result = scanner.scan_env_text(content)
        assert result["exposed_secret_count"] >= 1
        assert any(f["key"] == "APP_SECRET_TOKEN" for f in result["findings"])

    def test_custom_rule_integration(self):
        import re
        from envguard_secrets_vault.scanner import SecretRule
        
        custom_rule = SecretRule(
            rule_id="my_corp_secret",
            name="MyCorp Internal Secret",
            provider="MyCorp",
            severity="CRITICAL",
            pattern=re.compile(r"corp_sec_[0-9a-f]{24}"),
            description="Internal corporate authentication secret",
            category="Auth",
        )
        scanner = SecretScanner(custom_rules=[custom_rule])
        res = scanner.scan_env_text("CORP_TOKEN=corp_sec_0123456789abcdef01234567\n")
        assert res["exposed_secret_count"] == 1
        assert res["findings"][0]["provider"] == "MyCorp"


class TestDirectoryScanning:
    def test_scan_directory(self, tmp_path: Path):
        scanner = SecretScanner()
        
        # Create test project tree
        (tmp_path / "src").mkdir()
        (tmp_path / ".git").mkdir()  # Should be ignored
        
        (tmp_path / ".env").write_text("PORT=3000\nNODE_ENV=dev\n")
        (tmp_path / ".env.prod").write_text("STRIPE_KEY=sk_mock_" + "dummyStripeKey00000000000000000000\n")
        (tmp_path / "src" / "app.py").write_text("API_TOKEN = 'ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz'\n")
        (tmp_path / ".git" / "config").write_text("SECRET=sk-proj-ignoremeinrepo123456\n")

        res = scanner.scan_directory(str(tmp_path))
        assert res["files_scanned"] >= 3
        assert res["total_findings"] >= 2
        # Ensure .git was skipped
        scanned_files = [r["file"] for r in res["per_file_results"]]
        assert not any(".git" in f for f in scanned_files)
