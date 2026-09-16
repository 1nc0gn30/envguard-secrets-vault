"""Secret Scanner and Shannon Entropy Engine for EnvGuard Secrets Vault.

Provides 40+ pre-compiled provider patterns, Shannon entropy analysis,
line-aware finding detection, security scoring, and multi-file directory auditing.
Zero external runtime dependencies - pure Python stdlib.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple

from envguard_secrets_vault.compat import safe_read_text


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (bits per character).

    Formula: H = - sum(p_i * log2(p_i))
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_high_entropy(text: str, threshold: float = 3.5, min_length: int = 16) -> bool:
    """Return True if text exceeds the entropy threshold and minimum length."""
    if len(text) < min_length:
        return False
    return calculate_entropy(text) >= threshold


@dataclass(frozen=True)
class SecretRule:
    """Definition of a secret detection rule."""

    rule_id: str
    name: str
    provider: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    pattern: Pattern[str]
    description: str
    category: str  # AI, Cloud, Payment, VCS, Database, Auth, Communication, Generic
    min_entropy: Optional[float] = None
    min_length: Optional[int] = None


@dataclass
class SecretFinding:
    """Represents an identified secret in scanned content."""

    line_number: int
    key: str
    secret_type: str
    provider: str
    severity: str
    entropy: float
    description: str
    masked_value: str
    raw_preview: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _mask_value_preview(val: str) -> str:
    """Return a safe masked preview of a secret value."""
    if not val:
        return ""
    if len(val) <= 8:
        return "••••••••"
    if len(val) <= 16:
        return f"{val[:2]}••••{val[-2:]}"
    return f"{val[:6]}••••••••{val[-4:]}"


# Pre-compiled catalogue of 40+ secret detection rules
SECRET_RULES: List[SecretRule] = [
    # 1. OpenAI Project API Key
    SecretRule(
        rule_id="openai_project_key",
        name="OpenAI Project API Key",
        provider="OpenAI",
        severity="CRITICAL",
        pattern=re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}"),
        description="OpenAI Project-scoped API secret key",
        category="AI",
    ),
    # 2. OpenAI Legacy / Standard API Key
    SecretRule(
        rule_id="openai_standard_key",
        name="OpenAI API Key",
        provider="OpenAI",
        severity="CRITICAL",
        pattern=re.compile(r"\bsk-(?!proj-|ant-)[A-Za-z0-9]{20,48}\b"),
        description="Standard OpenAI API secret key",
        category="AI",
    ),
    # 3. Anthropic Claude API Key
    SecretRule(
        rule_id="anthropic_api_key",
        name="Anthropic API Key",
        provider="Anthropic",
        severity="CRITICAL",
        pattern=re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{20,}"),
        description="Anthropic Claude API authorization secret",
        category="AI",
    ),
    # 4. Stripe Secret Key (Live or Test or Mock)
    SecretRule(
        rule_id="stripe_secret_key",
        name="Stripe Secret Key",
        provider="Stripe",
        severity="CRITICAL",
        pattern=re.compile(r"\bsk_(?:live|test|mock)_[0-9a-zA-Z]{20,}\b"),
        description="Stripe secret API key",
        category="Payment",
    ),
    # 5. Stripe Restricted Key (Live or Test or Mock)
    SecretRule(
        rule_id="stripe_restricted_key",
        name="Stripe Restricted Key",
        provider="Stripe",
        severity="CRITICAL",
        pattern=re.compile(r"\brk_(?:live|test|mock)_[0-9a-zA-Z]{20,}\b"),
        description="Stripe restricted API key",
        category="Payment",
    ),
    # 6. Stripe Publishable Key (Live or Test or Mock)
    SecretRule(
        rule_id="stripe_publishable_key",
        name="Stripe Publishable Key",
        provider="Stripe",
        severity="LOW",
        pattern=re.compile(r"\bpk_(?:live|test|mock)_[0-9a-zA-Z]{20,}\b"),
        description="Stripe public client-side key",
        category="Payment",
    ),
    # 7. AWS Access Key ID
    SecretRule(
        rule_id="aws_access_key_id",
        name="AWS Access Key ID",
        provider="AWS",
        severity="HIGH",
        pattern=re.compile(r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b"),
        description="Amazon Web Services access key identifier",
        category="Cloud",
    ),
    # 8. AWS Secret Access Key
    SecretRule(
        rule_id="aws_secret_key",
        name="AWS Secret Access Key",
        provider="AWS",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        description="Amazon Web Services secret access key",
        category="Cloud",
    ),
    # 9. GitHub Personal Access Token (Classic)
    SecretRule(
        rule_id="github_pat_classic",
        name="GitHub Personal Access Token (Classic)",
        provider="GitHub",
        severity="CRITICAL",
        pattern=re.compile(r"\bghp_[A-Za-z0-9]{30,45}\b"),
        description="GitHub classic personal access token",
        category="VCS",
    ),
    # 10. GitHub OAuth Access Token
    SecretRule(
        rule_id="github_oauth_token",
        name="GitHub OAuth Token",
        provider="GitHub",
        severity="CRITICAL",
        pattern=re.compile(r"\bgho_[A-Za-z0-9]{30,45}\b"),
        description="GitHub OAuth user authorization token",
        category="VCS",
    ),
    # 11. GitHub Fine-Grained Personal Access Token
    SecretRule(
        rule_id="github_fine_grained_pat",
        name="GitHub Fine-Grained PAT",
        provider="GitHub",
        severity="CRITICAL",
        pattern=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,120}\b"),
        description="GitHub fine-grained granular permissions token",
        category="VCS",
    ),
    # 12. GitHub App Token
    SecretRule(
        rule_id="github_app_token",
        name="GitHub App Token",
        provider="GitHub",
        severity="HIGH",
        pattern=re.compile(r"\b(?:ghu|ghs|ghr)_[A-Za-z0-9]{30,45}\b"),
        description="GitHub App server-to-server or refresh token",
        category="VCS",
    ),
    # 13. Google Cloud API Key
    SecretRule(
        rule_id="google_api_key",
        name="Google Cloud API Key",
        provider="Google",
        severity="HIGH",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b"),
        description="Google Cloud Platform / Firebase / Maps API key",
        category="Cloud",
    ),
    # 14. Slack Bot Token
    SecretRule(
        rule_id="slack_bot_token",
        name="Slack Bot Token",
        provider="Slack",
        severity="CRITICAL",
        pattern=re.compile(r"\bxoxb-(?:mock-)?[0-9a-zA-Z\-]{20,}\b"),
        description="Slack bot integration token",
        category="Communication",
    ),
    # 15. Slack User Token
    SecretRule(
        rule_id="slack_user_token",
        name="Slack User Token",
        provider="Slack",
        severity="HIGH",
        pattern=re.compile(r"\bxoxp-(?:mock-)?[0-9a-zA-Z\-]{20,}\b"),
        description="Slack user API authorization token",
        category="Communication",
    ),
    # 16. Slack Webhook URL
    SecretRule(
        rule_id="slack_webhook",
        name="Slack Incoming Webhook",
        provider="Slack",
        severity="HIGH",
        pattern=re.compile(r"https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+"),
        description="Slack incoming webhook trigger URL",
        category="Communication",
    ),
    # 17. Supabase Service Role Key
    SecretRule(
        rule_id="supabase_service_role_key",
        name="Supabase Service Role Key",
        provider="Supabase",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?i)(?:supabase.*(?:service_role|service_key|secret_key))"
        ),
        description="Supabase superuser service-role bypass key",
        category="Database",
    ),
    # 18. Supabase Anon Access Key / Token
    SecretRule(
        rule_id="supabase_anon_token",
        name="Supabase Access Token",
        provider="Supabase",
        severity="MEDIUM",
        pattern=re.compile(r"\bsbp_[a-f0-9]{40}\b"),
        description="Supabase personal access token",
        category="Database",
    ),
    # 19. Netlify Personal Access Token
    SecretRule(
        rule_id="netlify_token",
        name="Netlify Personal Access Token",
        provider="Netlify",
        severity="CRITICAL",
        pattern=re.compile(r"\bnfp_[a-zA-Z0-9]{40,64}\b"),
        description="Netlify deployment and account access token",
        category="Cloud",
    ),
    # 20. Vercel Access Token
    SecretRule(
        rule_id="vercel_token",
        name="Vercel Access Token",
        provider="Vercel",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?i)(?:VERCEL_TOKEN|VERCEL_ACCESS_TOKEN)"
        ),
        description="Vercel CLI & API management token",
        category="Cloud",
    ),
    # 21. Telegram Bot Token
    SecretRule(
        rule_id="telegram_bot_token",
        name="Telegram Bot Token",
        provider="Telegram",
        severity="HIGH",
        pattern=re.compile(r"\b[0-9]{8,12}:[A-Za-z0-9_-]{30,45}\b"),
        description="Telegram bot authorization secret token",
        category="Communication",
    ),
    # 22. SendGrid API Key
    SecretRule(
        rule_id="sendgrid_api_key",
        name="SendGrid API Key",
        provider="SendGrid",
        severity="CRITICAL",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,30}\.[A-Za-z0-9_\-]{35,50}\b"),
        description="SendGrid email delivery API key",
        category="Communication",
    ),
    # 23. Twilio Account SID
    SecretRule(
        rule_id="twilio_account_sid",
        name="Twilio Account SID",
        provider="Twilio",
        severity="MEDIUM",
        pattern=re.compile(r"\bAC[a-f0-9]{32}\b"),
        description="Twilio account identifier",
        category="Communication",
    ),
    # 24. Twilio Auth Token
    SecretRule(
        rule_id="twilio_auth_token",
        name="Twilio Auth Token",
        provider="Twilio",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?i)(?:TWILIO_AUTH_TOKEN|TWILIO_SECRET)"
        ),
        description="Twilio secret authentication token",
        category="Communication",
    ),
    # 25. JSON Web Token (JWT)
    SecretRule(
        rule_id="jwt_token",
        name="JSON Web Token (JWT)",
        provider="Auth",
        severity="MEDIUM",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_\-\+/=]{8,}\b"
        ),
        description="Signed JSON Web Token",
        category="Auth",
    ),
    # 26. RSA Private Key
    SecretRule(
        rule_id="rsa_private_key",
        name="RSA Private Key",
        provider="PKI",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        description="Unencrypted RSA private key block",
        category="Auth",
    ),
    # 27. OpenSSH Private Key
    SecretRule(
        rule_id="openssh_private_key",
        name="OpenSSH Private Key",
        provider="OpenSSH",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        description="OpenSSH cryptographic private key",
        category="Auth",
    ),
    # 28. EC Private Key
    SecretRule(
        rule_id="ec_private_key",
        name="EC Private Key",
        provider="PKI",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        description="Elliptic Curve private key block",
        category="Auth",
    ),
    # 29. PGP Private Key Block
    SecretRule(
        rule_id="pgp_private_key",
        name="PGP Private Key",
        provider="PGP",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        description="PGP/GPG cryptographic private key block",
        category="Auth",
    ),
    # 30. Generic Private Key
    SecretRule(
        rule_id="generic_private_key",
        name="Generic Private Key",
        provider="PKI",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9_\- ]+)?PRIVATE KEY-----"),
        description="Generic SSL/TLS private key header",
        category="Auth",
    ),
    # 31. PostgreSQL Connection URI
    SecretRule(
        rule_id="postgres_connection_uri",
        name="PostgreSQL Connection URI",
        provider="PostgreSQL",
        severity="CRITICAL",
        pattern=re.compile(
            r"postgres(?:ql)?:\/\/[a-zA-Z0-9_\-\.%]+:[^@\s]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-\.%]+"
        ),
        description="PostgreSQL connection string with plaintext credentials",
        category="Database",
    ),
    # 32. MySQL Connection URI
    SecretRule(
        rule_id="mysql_connection_uri",
        name="MySQL Connection URI",
        provider="MySQL",
        severity="CRITICAL",
        pattern=re.compile(
            r"mysql:\/\/[a-zA-Z0-9_\-\.%]+:[^@\s]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-\.%]+"
        ),
        description="MySQL connection string with plaintext credentials",
        category="Database",
    ),
    # 33. MongoDB Connection URI
    SecretRule(
        rule_id="mongodb_connection_uri",
        name="MongoDB Connection URI",
        provider="MongoDB",
        severity="CRITICAL",
        pattern=re.compile(
            r"mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_\-\.%]+:[^@\s]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-\.%]+"
        ),
        description="MongoDB connection string with credentials",
        category="Database",
    ),
    # 34. Redis Connection URI with Auth
    SecretRule(
        rule_id="redis_connection_uri",
        name="Redis Connection URI",
        provider="Redis",
        severity="HIGH",
        pattern=re.compile(
            r"redis(?:s)?:\/\/(?:[a-zA-Z0-9_\-\.%]+:)?([^@\s]+)@[a-zA-Z0-9_\-\.]+(?::\d+)?"
        ),
        description="Redis connection string with authentication secret",
        category="Database",
    ),
    # 35. Mailgun API Key
    SecretRule(
        rule_id="mailgun_api_key",
        name="Mailgun API Key",
        provider="Mailgun",
        severity="HIGH",
        pattern=re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        description="Mailgun email delivery private key",
        category="Communication",
    ),
    # 36. Hugging Face User Token
    SecretRule(
        rule_id="huggingface_token",
        name="Hugging Face Access Token",
        provider="HuggingFace",
        severity="HIGH",
        pattern=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        description="Hugging Face model hub access token",
        category="AI",
    ),
    # 37. Cohere API Key
    SecretRule(
        rule_id="cohere_api_key",
        name="Cohere API Key",
        provider="Cohere",
        severity="HIGH",
        pattern=re.compile(
            r"(?i)(?:COHERE_API_KEY|CO_API_KEY)\s*[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?"
        ),
        description="Cohere LLM inference platform key",
        category="AI",
    ),
    # 38. NPM Access Token
    SecretRule(
        rule_id="npm_token",
        name="NPM Access Token",
        provider="NPM",
        severity="CRITICAL",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        description="Node Package Manager publishing access token",
        category="VCS",
    ),
    # 39. PyPI API Token
    SecretRule(
        rule_id="pypi_token",
        name="PyPI API Token",
        provider="PyPI",
        severity="CRITICAL",
        pattern=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b"),
        description="Python Package Index package publishing token",
        category="VCS",
    ),
    # 40. Datadog API Key
    SecretRule(
        rule_id="datadog_api_key",
        name="Datadog API Key",
        provider="Datadog",
        severity="HIGH",
        pattern=re.compile(
            r"(?i)(?:DD_API_KEY|DATADOG_API_KEY)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"
        ),
        description="Datadog monitoring and telemetry API key",
        category="Cloud",
    ),
    # 41. GitLab Personal Access Token
    SecretRule(
        rule_id="gitlab_pat",
        name="GitLab Personal Access Token",
        provider="GitLab",
        severity="CRITICAL",
        pattern=re.compile(r"\bglpat-[0-9a-zA-Z\-]{20,}\b"),
        description="GitLab personal access or deploy token",
        category="VCS",
    ),
    # 42. Discord Bot Token
    SecretRule(
        rule_id="discord_bot_token",
        name="Discord Bot Token",
        provider="Discord",
        severity="CRITICAL",
        pattern=re.compile(r"\b(?:N|M|O)[A-Za-z0-9]{23,25}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}\b"),
        description="Discord bot authorization authentication token",
        category="Communication",
    ),
    # 43. Square Access Token
    SecretRule(
        rule_id="square_access_token",
        name="Square Access Token",
        provider="Square",
        severity="CRITICAL",
        pattern=re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{20,32}\b"),
        description="Square payment merchant access token",
        category="Payment",
    ),
    # 44. Square OAuth Secret
    SecretRule(
        rule_id="square_oauth_secret",
        name="Square OAuth Secret",
        provider="Square",
        severity="CRITICAL",
        pattern=re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{38,55}\b"),
        description="Square OAuth client application secret",
        category="Payment",
    ),
    # 45. Generic High-Entropy Password / Secret Assignment
    SecretRule(
        rule_id="generic_credential_assignment",
        name="Generic Credential Assignment",
        provider="Generic",
        severity="HIGH",
        pattern=re.compile(
            r"(?i)(?:(?:db_|database_|app_|master_)?(?:password|passwd|pwd)|(?:api|auth|secret)_?(?:key|token|secret))\s*[:=]\s*['\"]?([^\s'\"#]{12,})['\"]?"
        ),
        description="Named secret, password, or key assignment with high entropy",
        category="Generic",
        min_entropy=3.2,
        min_length=12,
    ),
]


class SecretScanner:
    """High-entropy secret scanner and security posture evaluator."""

    def __init__(self, custom_rules: Optional[List[SecretRule]] = None) -> None:
        self.rules: List[SecretRule] = list(custom_rules or SECRET_RULES)

    def scan_env_text(self, content: str) -> Dict[str, Any]:
        """Scan .env text or configuration content and return security grade and findings."""
        lines = content.splitlines()
        findings: List[SecretFinding] = []
        parsed_keys: List[Tuple[int, str, str]] = []  # (line_no, key, value)
        seen_detections: Set[Tuple[int, str, str]] = set()  # (line_no, key, rule_id)

        # Parse key-value lines
        multiline_key: Optional[str] = None
        multiline_lines: List[str] = []
        multiline_start_line = 0

        for line_idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()

            # Handle multiline continuation
            if multiline_key is not None:
                multiline_lines.append(raw_line)
                if stripped.endswith('"') or stripped.endswith("'") or "-----END" in stripped:
                    full_val = "\n".join(multiline_lines).strip("'\"")
                    parsed_keys.append((multiline_start_line, multiline_key, full_val))
                    multiline_key = None
                    multiline_lines = []
                continue

            if not stripped or stripped.startswith("#"):
                continue

            # Check if line starts a multiline quoted value or private key
            kv_match = re.match(r"^(?:export\s+)?([A-Za-z0-9_.\-]+)\s*=\s*(.*)$", stripped)
            if kv_match:
                key, val = kv_match.group(1), kv_match.group(2)
                # Check for start of multiline
                if (val.startswith('"') and not val.endswith('"') and len(val) > 1) or (
                    val.startswith("'") and not val.endswith("'") and len(val) > 1
                ):
                    multiline_key = key
                    multiline_lines = [val]
                    multiline_start_line = line_idx
                    continue
                else:
                    # Strip inline comments if unquoted or after quote
                    clean_val = self._extract_clean_value(val)
                    parsed_keys.append((line_idx, key, clean_val))
            else:
                # Direct assignment like YAML or plain format
                kv_colon = re.match(r"^([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", stripped)
                if kv_colon:
                    key, val = kv_colon.group(1), kv_colon.group(2)
                    clean_val = self._extract_clean_value(val)
                    parsed_keys.append((line_idx, key, clean_val))

        # Check whole content for block private keys and certificates
        self._scan_multiline_blocks(content, findings, seen_detections)

        # Scan parsed key-value entries against rules and entropy
        for line_no, key, val in parsed_keys:
            val_entropy = calculate_entropy(val)

            for rule in self.rules:
                if (line_no, key, rule.rule_id) in seen_detections:
                    continue

                # If specific provider rule already matched this key/line, skip generic rules
                if (rule.category == "Generic" or rule.provider == "Generic" or rule.rule_id == "jwt_token") and any(
                    f.line_number == line_no and f.key == key for f in findings
                ):
                    continue

                # Test pattern against key=val or val
                match = rule.pattern.search(val) or rule.pattern.search(f"{key}={val}")
                if match:
                    # If rule requires min_entropy or min_length
                    if rule.min_entropy is not None and val_entropy < rule.min_entropy:
                        continue
                    if rule.min_length is not None and len(val) < rule.min_length:
                        continue

                    finding = SecretFinding(
                        line_number=line_no,
                        key=key,
                        secret_type=rule.rule_id,
                        provider=rule.provider,
                        severity=rule.severity,
                        entropy=val_entropy,
                        description=rule.description,
                        masked_value=_mask_value_preview(val),
                        raw_preview=val[:12] + "..." if len(val) > 12 else val,
                    )
                    findings.append(finding)
                    seen_detections.add((line_no, key, rule.rule_id))

            # Additional high-entropy generic heuristic check for suspect key names
            if val and len(val) >= 16 and val_entropy >= 3.6:
                suspect_keywords = ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "KEY", "CREDENTIAL", "AUTH", "PRIVATE")
                if any(kw in key.upper() for kw in suspect_keywords):
                    if not any(f.line_number == line_no and f.key == key for f in findings):
                        finding = SecretFinding(
                            line_number=line_no,
                            key=key,
                            secret_type="high_entropy_secret",
                            provider="Generic",
                            severity="HIGH",
                            entropy=val_entropy,
                            description=f"High-entropy secret ({val_entropy:.2f} bits) in sensitive key {key}",
                            masked_value=_mask_value_preview(val),
                            raw_preview=val[:12] + "..." if len(val) > 12 else val,
                        )
                        findings.append(finding)
                        seen_detections.add((line_no, key, "high_entropy_secret"))

        # Calculate statistics, categories, score, grade
        categories = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            categories[f.severity] = categories.get(f.severity, 0) + 1

        all_entropies = [calculate_entropy(val) for _, _, val in parsed_keys if val]
        avg_entropy = round(sum(all_entropies) / len(all_entropies), 4) if all_entropies else 0.0
        max_entropy = max(all_entropies) if all_entropies else 0.0
        high_entropy_count = sum(1 for e in all_entropies if e >= 3.5)

        # Compute Security Score (0 - 100)
        # Base: 100, Deduct: CRITICAL -25, HIGH -15, MEDIUM -8, LOW -3
        deductions = (
            categories["CRITICAL"] * 25
            + categories["HIGH"] * 15
            + categories["MEDIUM"] * 8
            + categories["LOW"] * 3
        )
        score = max(0, 100 - deductions)

        # Determine Security Grade
        grade = self._score_to_grade(score, len(findings))

        summary = (
            f"Security Grade: {grade} (Score: {score}/100). "
            f"Total Keys: {len(parsed_keys)}, Exposed Secrets: {len(findings)} "
            f"(CRITICAL: {categories['CRITICAL']}, HIGH: {categories['HIGH']}, "
            f"MEDIUM: {categories['MEDIUM']}, LOW: {categories['LOW']})."
        )

        return {
            "grade": grade,
            "score": score,
            "total_keys": len(parsed_keys),
            "exposed_secret_count": len(findings),
            "categories": categories,
            "entropy_ratings": {
                "average_entropy": avg_entropy,
                "max_entropy": max_entropy,
                "high_entropy_count": high_entropy_count,
            },
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
        }

    def _extract_clean_value(self, raw_val: str) -> str:
        """Extract clean value stripping quotes or inline comments."""
        val = raw_val.strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            return val[1:-1]
        # If unquoted and contains inline comment preceded by whitespace, split
        match = re.search(r"\s+#", val)
        if match:
            val = val[: match.start()].strip()
        return val

    def _scan_multiline_blocks(
        self,
        content: str,
        findings: List[SecretFinding],
        seen: Set[Tuple[int, str, str]],
    ) -> None:
        """Detect multiline private keys and certs directly from content."""
        private_key_patterns = [
            ("rsa_private_key", "RSA Private Key", "PKI", "CRITICAL", re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----")),
            ("openssh_private_key", "OpenSSH Private Key", "OpenSSH", "CRITICAL", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----")),
            ("ec_private_key", "EC Private Key", "PKI", "CRITICAL", re.compile(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----")),
            ("pgp_private_key", "PGP Private Key", "PGP", "CRITICAL", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----")),
            ("generic_private_key", "Private Key Block", "PKI", "CRITICAL", re.compile(r"-----BEGIN [A-Z0-9_\- ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\- ]+PRIVATE KEY-----")),
        ]
        lines = content.splitlines()
        for rule_id, name, provider, sev, pat in private_key_patterns:
            for match in pat.finditer(content):
                start_pos = match.start()
                # Compute line number
                line_no = content[:start_pos].count("\n") + 1
                key_name = "PRIVATE_KEY"
                # Check line before or current line for KEY=
                line_text = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                if "=" in line_text:
                    key_name = line_text.split("=")[0].strip().replace("export ", "")

                if (line_no, key_name, rule_id) not in seen:
                    matched_text = match.group(0)
                    findings.append(
                        SecretFinding(
                            line_number=line_no,
                            key=key_name,
                            secret_type=rule_id,
                            provider=provider,
                            severity=sev,
                            entropy=calculate_entropy(matched_text),
                            description=f"Exposed {name} block",
                            masked_value="-----BEGIN PRIVATE KEY-----••••[REDACTED]••••-----END PRIVATE KEY-----",
                            raw_preview=matched_text[:28] + "...",
                        )
                    )
                    seen.add((line_no, key_name, rule_id))

    def _score_to_grade(self, score: int, finding_count: int) -> str:
        """Convert a 0-100 numerical score into a letter grade."""
        if finding_count == 0:
            return "A+"
        if score >= 95:
            return "A+"
        if score >= 85:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def scan_directory(self, path: str, max_files: int = 100) -> Dict[str, Any]:
        """Scan a directory for secret leaks across .env, json, yaml, py, js, and ts files."""
        root_path = Path(path).resolve()
        if not root_path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        ignored_dirs = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".pytest_cache",
            ".idea",
            ".vscode",
            ".mypy_cache",
        }

        target_extensions = {
            ".env",
            ".json",
            ".yaml",
            ".yml",
            ".py",
            ".js",
            ".ts",
            ".mjs",
            ".cjs",
            ".toml",
            ".ini",
            ".cfg",
            ".sh",
            ".bash",
        }

        files_scanned = 0
        per_file_results: List[Dict[str, Any]] = []
        total_findings_count = 0
        all_categories = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]

            for file_name in files:
                if files_scanned >= max_files:
                    break

                file_path = Path(root) / file_name
                is_env = file_name == ".env" or file_name.startswith(".env.")
                has_target_ext = file_path.suffix.lower() in target_extensions

                if not (is_env or has_target_ext):
                    continue

                try:
                    content = safe_read_text(file_path)
                    res = self.scan_env_text(content)
                    files_scanned += 1
                    rel_path = str(file_path.relative_to(root_path))
                    res["file"] = rel_path
                    res["file_path"] = str(file_path)
                    per_file_results.append(res)
                    total_findings_count += res["exposed_secret_count"]
                    for k, v in res["categories"].items():
                        all_categories[k] += v
                except Exception as exc:
                    # Record error for file
                    per_file_results.append({
                        "file": str(file_path.relative_to(root_path)),
                        "file_path": str(file_path),
                        "error": str(exc),
                        "exposed_secret_count": 0,
                        "grade": "N/A",
                        "score": 0,
                    })

            if files_scanned >= max_files:
                break

        overall_deductions = (
            all_categories["CRITICAL"] * 25
            + all_categories["HIGH"] * 15
            + all_categories["MEDIUM"] * 8
            + all_categories["LOW"] * 3
        )
        overall_score = max(0, 100 - overall_deductions) if files_scanned > 0 else 100
        overall_grade = self._score_to_grade(overall_score, total_findings_count)

        return {
            "root_path": str(root_path),
            "files_scanned": files_scanned,
            "total_findings": total_findings_count,
            "categories": all_categories,
            "overall_score": overall_score,
            "overall_grade": overall_grade,
            "per_file_results": per_file_results,
        }
