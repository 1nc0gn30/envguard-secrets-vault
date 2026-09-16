"""Comprehensive unit tests for EnvTransformer and Config Formatter (transformer.py)."""

import json

import pytest

from envguard_secrets_vault.transformer import (
    EnvTransformer,
    mask_secret,
)


class TestSecretMasking:
    def test_mask_secret_smart_prefixes(self):
        openai_key = "sk-proj-dummyOpenAiKey00000000000000000000"
        masked = mask_secret(openai_key, style="smart")
        assert masked.startswith("sk-proj-")
        assert masked.endswith("0000")
        assert "..." in masked

    def test_mask_secret_stripe(self):
        stripe_key = "sk_mock_" + "dummyStripeKey00000000000000000000"
        masked = mask_secret(stripe_key, style="smart")
        assert masked.startswith("sk_mock_")
        assert masked.endswith("0000")

    def test_mask_secret_github(self):
        ghp_key = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        masked = mask_secret(ghp_key, style="smart")
        assert masked.startswith("ghp_")
        assert masked.endswith("wxyz")

    def test_mask_secret_short_string(self):
        short = "secret"
        assert mask_secret(short, style="smart") == "••••••••"

    def test_mask_secret_styles(self):
        val = "my_super_secret_value_12345"
        assert mask_secret(val, style="empty") == ""
        assert mask_secret(val, style="dummy") == "your_secret_here"
        assert "•" in mask_secret(val, style="bullets")
        assert mask_secret(val, style="partial") == "my****45"


class TestEnvExampleGeneration:
    def test_generate_env_example_preserves_structure(self):
        env_content = (
            "# App Configuration\n"
            "NODE_ENV=production\n"
            "PORT=8080\n"
            "DEBUG=true\n"
            "\n"
            "# Secrets\n"
            "OPENAI_API_KEY=sk-proj-abcdef1234567890 # required for AI\n"
            "DATABASE_URL=postgresql://user:secret123@db.prod:5432/appdb\n"
            "CUSTOM_API_SECRET=mycustomsecretvalue\n"
        )
        
        example = EnvTransformer.generate_env_example(env_content)
        assert "# App Configuration" in example
        assert "# Secrets" in example
        assert "NODE_ENV=development" in example
        assert "PORT=8080" in example
        assert "DEBUG=false" in example
        assert "OPENAI_API_KEY=sk-proj-your_openai_api_key_here # required for AI" in example
        assert "DATABASE_URL=postgresql://postgres:password@localhost:5432/mydb" in example
        assert "CUSTOM_API_SECRET=your_custom_api_secret_here" in example
        assert "sk-proj-abcdef" not in example
        assert "secret123" not in example

    def test_custom_placeholders_override(self):
        env_content = "STRIPE_SECRET=sk_mock_123456\n"
        custom = {"STRIPE_SECRET": "sk_mock_placeholder_key"}
        example = EnvTransformer.generate_env_example(env_content, custom_placeholders=custom)
        assert "STRIPE_SECRET=sk_mock_placeholder_key" in example


class TestFormatConverters:
    def test_env_to_dict_and_dict_to_env(self):
        env_text = (
            "# Comment\n"
            'APP_NAME="My Great App"\n'
            "PORT=3000\n"
            "IS_ACTIVE=true\n"
        )
        d = EnvTransformer.env_to_dict(env_text)
        assert d == {"APP_NAME": "My Great App", "PORT": "3000", "IS_ACTIVE": "true"}

        back_to_env = EnvTransformer.dict_to_env(d)
        assert 'APP_NAME="My Great App"' in back_to_env
        assert "PORT=3000" in back_to_env

    def test_env_to_json_and_json_to_env(self):
        env_text = "KEY1=value1\nKEY2=value2\n"
        json_out = EnvTransformer.env_to_json(env_text)
        parsed = json.loads(json_out)
        assert parsed == {"KEY1": "value1", "KEY2": "value2"}

        reconstructed_env = EnvTransformer.json_to_env(json_out)
        d = EnvTransformer.env_to_dict(reconstructed_env)
        assert d == {"KEY1": "value1", "KEY2": "value2"}

    def test_env_to_yaml_and_yaml_to_env(self):
        env_text = "PORT=8080\nHOST=localhost\nDEBUG=true\n"
        yaml_out = EnvTransformer.env_to_yaml(env_text)
        assert "PORT: 8080" in yaml_out
        assert "DEBUG: true" in yaml_out

        env_back = EnvTransformer.yaml_to_env(yaml_out)
        d = EnvTransformer.env_to_dict(env_back)
        assert d["PORT"] == "8080"
        assert d["HOST"] == "localhost"
        assert d["DEBUG"] == "true"

    def test_env_to_docker_compose_map_style_and_back(self):
        env_text = "DATABASE_URL=postgres://localhost/db\nPORT=3000\n"
        compose = EnvTransformer.env_to_docker_compose(env_text, service_name="api", style="map")
        assert "services:" in compose
        assert "api:" in compose
        assert "environment:" in compose
        assert "PORT: 3000" in compose or 'PORT: "3000"' in compose

        env_reconstructed = EnvTransformer.docker_compose_to_env(compose)
        d = EnvTransformer.env_to_dict(env_reconstructed)
        assert d["DATABASE_URL"] == "postgres://localhost/db"
        assert d["PORT"] == "3000"

    def test_json_to_env_invalid_json_type(self):
        with pytest.raises(ValueError):
            EnvTransformer.json_to_env('["not", "a", "dict"]')

    def test_multiline_value_in_env(self):
        env_text = (
            'CERTIFICATE="-----BEGIN CERTIFICATE-----\n'
            "MIIDdzCCAl+gAwIBAgIEAgAAAzANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJV\n"
            '-----END CERTIFICATE-----"\n'
            "PORT=443\n"
        )
        d = EnvTransformer.env_to_dict(env_text)
        assert d["PORT"] == "443"
        assert "-----BEGIN CERTIFICATE-----" in d["CERTIFICATE"]
        assert "-----END CERTIFICATE-----" in d["CERTIFICATE"]


class TestDeduplicationAndDiff:
    def test_deduplicate_and_sort_keep_last(self):
        env_text = (
            "PORT=3000\n"
            "APP=first\n"
            "PORT=8080\n"
            "APP=second\n"
            "AAA_KEY=val\n"
        )
        deduped = EnvTransformer.deduplicate_and_sort(env_text, sort_keys=True, keep_last=True)
        lines = [line.strip() for line in deduped.splitlines() if line.strip()]
        assert lines == ["AAA_KEY=val", "APP=second", "PORT=8080"]

    def test_diff_env(self):
        env_a = (
            "PORT=3000\n"
            "HOST=localhost\n"
            "OLD_KEY=deprecated\n"
        )
        env_b = (
            "PORT=8080\n"
            "HOST=localhost\n"
            "NEW_KEY=introduced\n"
        )
        diff = EnvTransformer.diff_env(env_a, env_b)
        assert diff["has_changes"] is True
        assert "NEW_KEY" in diff["added"]
        assert "OLD_KEY" in diff["removed"]
        assert "PORT" in diff["modified"]
        assert diff["modified"]["PORT"] == {"before": "3000", "after": "8080"}
        assert diff["unchanged"] == ["HOST"]
