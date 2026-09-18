"""
Secret Rotation, Expiration & Cryptographic Ephemerality Sentinel.
Monitors secret lifetimes, TTL deadlines, and generates provider-formatted ephemeral replacement tokens.
Zero external runtime dependencies (100% Python Standard Library).
"""

from __future__ import annotations

import datetime
import difflib
import json
import re
import secrets
import string
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class SecretStatus(str, Enum):
    """Lifecycle status of a managed secret."""
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    OVERDUE = "overdue"
    UNTRACKED = "untracked"
    UNMANAGED = "unmanaged"


RotationStatus = SecretStatus


# Known provider token prefixes and heuristic matching
PROVIDER_PREFIXES: Dict[str, str] = {
    "sk_live_": "stripe_live",
    "sk_test_": "stripe_test",
    "ghp_": "github_pat",
    "github_pat_": "github_pat_fine",
    "sk-proj-": "openai",
    "sk-ant-": "anthropic",
    "AKIA": "aws_access_key",
    "xoxb-": "slack_bot",
    "xoxp-": "slack_user",
    "SG.": "sendgrid",
    "pypi-": "pypi",
    "npm_": "npm",
    "glpat-": "gitlab",
    "hf_": "huggingface",
}


def detect_secret_provider(key_name: str, value: str = "") -> str:
    """Infer the credential provider from value prefix or variable key name."""
    val_clean = value.strip("\"'") if value else ""
    for prefix, prov in PROVIDER_PREFIXES.items():
        if val_clean.startswith(prefix):
            return prov

    key_upper = key_name.upper()
    if "STRIPE" in key_upper:
        return "stripe_live" if "LIVE" in key_upper else "stripe_test"
    if "OPENAI" in key_upper:
        return "openai"
    if "ANTHROPIC" in key_upper or "CLAUDE" in key_upper:
        return "anthropic"
    if "GITHUB" in key_upper or "GH_" in key_upper:
        return "github_pat"
    if "AWS" in key_upper and "KEY" in key_upper:
        return "aws_access_key"
    if "AWS" in key_upper and "SECRET" in key_upper:
        return "aws_secret"
    if "SLACK" in key_upper:
        return "slack_bot"
    if "SENDGRID" in key_upper:
        return "sendgrid"
    if "DATABASE" in key_upper or "DB_URL" in key_upper or "POSTGRES" in key_upper:
        return "database_url"
    if "JWT" in key_upper or "SECRET_KEY" in key_upper or "SESSION" in key_upper:
        return "jwt_secret"
    return "generic"


def generate_ephemeral_token(provider_or_key: str, current_value: str = "") -> str:
    """Generate a cryptographically secure ephemeral token formatted for the given provider or key name."""
    known_providers = (
        "stripe_live", "stripe_test", "github_pat", "github_pat_fine",
        "openai", "anthropic", "aws_access_key", "aws_secret",
        "slack_bot", "slack_user", "sendgrid", "pypi", "npm",
        "gitlab", "huggingface", "database_url", "jwt_secret", "generic"
    )
    if provider_or_key in known_providers and not current_value:
        provider = provider_or_key
    else:
        provider = detect_secret_provider(provider_or_key, current_value)

    chars_alnum = string.ascii_letters + string.digits
    chars_upper = string.ascii_uppercase + string.digits

    if provider == "stripe_live":
        return "sk_live_" + "".join(secrets.choice(chars_alnum) for _ in range(24))
    elif provider == "stripe_test":
        return "sk_test_" + "".join(secrets.choice(chars_alnum) for _ in range(24))
    elif provider in ("github_pat", "github_pat_fine"):
        return "ghp_" + "".join(secrets.choice(chars_alnum) for _ in range(36))
    elif provider == "openai":
        return "sk-proj-" + "".join(secrets.choice(chars_alnum) for _ in range(48))
    elif provider == "anthropic":
        return "sk-ant-api03-" + "".join(secrets.choice(chars_alnum) for _ in range(42))
    elif provider == "aws_access_key":
        return "AKIA" + "".join(secrets.choice(chars_upper) for _ in range(16))
    elif provider == "aws_secret":
        raw = secrets.token_bytes(30)
        import base64
        return base64.b64encode(raw).decode("ascii")[:40]
    elif provider == "slack_bot":
        p1 = "".join(secrets.choice(string.digits) for _ in range(12))
        p2 = "".join(secrets.choice(string.digits) for _ in range(12))
        p3 = "".join(secrets.choice(chars_alnum) for _ in range(24))
        return f"xoxb-{p1}-{p2}-{p3}"
    elif provider == "sendgrid":
        p1 = "".join(secrets.choice(chars_alnum) for _ in range(22))
        p2 = "".join(secrets.choice(chars_alnum) for _ in range(43))
        return f"SG.{p1}.{p2}"
    elif provider == "database_url":
        user = "app_" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(5))
        pwd = "".join(secrets.choice(chars_alnum) for _ in range(20))
        return f"postgresql://{user}:{pwd}@localhost:5432/production_db"
    elif provider == "jwt_secret":
        return secrets.token_hex(32)
    else:
        # Generic high-entropy secret (32 bytes = 256 bits)
        return secrets.token_urlsafe(32)


@dataclass
class SecretLifecycleItem:
    """Metadata and lifecycle health tracking for an individual secret."""
    key: str
    masked_value: str
    provider: str
    status: str
    created_date: Optional[str]
    expires_date: Optional[str]
    rotation_policy_days: int
    age_days: Optional[int]
    days_until_expiration: Optional[int]
    owner: Optional[str]
    is_ephemeral: bool
    recommendation: str

    @property
    def created_at(self) -> Optional[str]:
        return self.created_date

    @property
    def expires_at(self) -> Optional[str]:
        return self.expires_date

    @property
    def rotation_days(self) -> Optional[int]:
        return self.rotation_policy_days

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["created_at"] = self.created_date
        d["expires_at"] = self.expires_date
        d["rotation_days"] = self.rotation_policy_days
        return d


SecretLifecycleMeta = SecretLifecycleItem


@dataclass
class SecretRotationAuditReport:
    """Comprehensive audit report evaluating secret ages, expirations, and rotation policies."""
    total_secrets: int
    tracked_secrets_count: int
    untracked_secrets_count: int
    active_count: int
    expiring_soon_count: int
    expired_count: int
    overdue_count: int
    compliance_score: float
    grade: str
    secrets: List[SecretLifecycleItem]
    actionable_recommendations: List[str]

    @property
    def unmanaged_count(self) -> int:
        return self.untracked_secrets_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_secrets": self.total_secrets,
            "tracked_secrets_count": self.tracked_secrets_count,
            "untracked_secrets_count": self.untracked_secrets_count,
            "unmanaged_count": self.untracked_secrets_count,
            "active_count": self.active_count,
            "expiring_soon_count": self.expiring_soon_count,
            "expired_count": self.expired_count,
            "overdue_count": self.overdue_count,
            "compliance_score": round(self.compliance_score, 2),
            "grade": self.grade,
            "secrets": [s.to_dict() for s in self.secrets],
            "actionable_recommendations": self.actionable_recommendations,
        }

    def to_markdown(self) -> str:
        """Render markdown audit summary."""
        lines = [
            "# 🔄 Secret Rotation & Ephemerality Lifecycle Audit",
            "",
            f"**Rotation Compliance Score**: `{self.compliance_score:.1f}/100` (Grade: **{self.grade}**)",
            f"- **Total Secrets Analyzed**: `{self.total_secrets}`",
            f"- **Tracked with Lifecycle Metadata**: `{self.tracked_secrets_count}`",
            f"- **Active & Healthy**: `{self.active_count}`",
            f"- **Expiring Soon (≤14d)**: `{self.expiring_soon_count}`",
            f"- **Expired**: `{self.expired_count}`",
            f"- **Overdue Rotation Policy**: `{self.overdue_count}`",
            "",
            "| Key | Provider | Status | Age | TTL | Policy | Owner |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for s in self.secrets:
            age_str = f"{s.age_days}d" if s.age_days is not None else "—"
            ttl_str = f"{s.days_until_expiration}d" if s.days_until_expiration is not None else "—"
            owner_str = s.owner or "—"
            lines.append(f"| `{s.key}` | `{s.provider}` | **{s.status.upper()}** | {age_str} | {ttl_str} | {s.rotation_policy_days}d | {owner_str} |")

        if self.actionable_recommendations:
            lines.extend([
                "",
                "## 💡 Recommended Remediation Actions",
                "",
            ])
            for rec in self.actionable_recommendations:
                lines.append(f"- {rec}")

        return "\n".join(lines)


RotationAuditReport = SecretRotationAuditReport


# Regex helpers for inline metadata tags in comments
RE_TAG_EXPIRES = re.compile(r"@expires:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)
RE_TAG_CREATED = re.compile(r"@created:\s*(\d{4}-\d{2}-\d{2})", re.IGNORECASE)
RE_TAG_POLICY = re.compile(r"@rotation_days:\s*(\d+)", re.IGNORECASE)
RE_TAG_OWNER = re.compile(r"@owner:\s*([^\s,;]+)", re.IGNORECASE)
RE_TAG_EPHEMERAL = re.compile(r"@ephemeral:\s*(true|false|1|0)", re.IGNORECASE)


def audit_secret_rotation(
    env_content: str,
    default_policy_days: int = 90,
    grace_period_days: int = 14,
    reference_date: Optional[Union[datetime.date, datetime.datetime]] = None,
    filename: str = ".env",
) -> SecretRotationAuditReport:
    """
    Audit .env content for secret age, expiration deadlines, and rotation policy compliance.
    """
    if isinstance(reference_date, datetime.datetime):
        today = reference_date.date()
    elif isinstance(reference_date, datetime.date):
        today = reference_date
    else:
        today = datetime.date.today()

    lines = env_content.splitlines()

    items: List[SecretLifecycleItem] = []
    pending_comments: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            pending_comments = []
            continue

        if stripped.startswith("#"):
            pending_comments.append(stripped)
            continue

        # Check for KEY=VALUE
        if "=" in stripped and not stripped.startswith("export "):
            k, _, v = stripped.partition("=")
        elif "=" in stripped and stripped.startswith("export "):
            k, _, v = stripped[7:].partition("=")
        else:
            pending_comments = []
            continue

        k = k.strip()
        v = v.strip()
        val_unquoted = v.strip("\"'")

        # Join pending comments and any inline comment
        comment_block = " ".join(pending_comments)
        pending_comments = []

        # Parse tags
        m_exp = RE_TAG_EXPIRES.search(comment_block)
        m_cre = RE_TAG_CREATED.search(comment_block)
        m_pol = RE_TAG_POLICY.search(comment_block)
        m_own = RE_TAG_OWNER.search(comment_block)
        m_eph = RE_TAG_EPHEMERAL.search(comment_block)

        created_str = m_cre.group(1) if m_cre else None
        expires_str = m_exp.group(1) if m_exp else None
        policy_days = int(m_pol.group(1)) if m_pol else default_policy_days
        owner_str = m_own.group(1) if m_own else None
        is_eph = m_eph.group(1).lower() in ("true", "1") if m_eph else False

        # If created_str is known but expires_str is not, derive it from policy_days
        if not expires_str and created_str:
            try:
                c_d = datetime.date.fromisoformat(created_str)
                expires_str = (c_d + datetime.timedelta(days=policy_days)).isoformat()
            except ValueError:
                pass

        provider = detect_secret_provider(k, val_unquoted)

        # Compute age and TTL
        age_days: Optional[int] = None
        if created_str:
            try:
                c_date = datetime.date.fromisoformat(created_str)
                age_days = (today - c_date).days
            except ValueError:
                pass

        ttl_days: Optional[int] = None
        if expires_str:
            try:
                e_date = datetime.date.fromisoformat(expires_str)
                ttl_days = (e_date - today).days
            except ValueError:
                pass

        # Determine status
        if expires_str and ttl_days is not None:
            if ttl_days < 0:
                status = SecretStatus.EXPIRED.value
                rec = f"Secret expired {abs(ttl_days)} days ago! Rotate immediately."
            elif ttl_days <= grace_period_days:
                status = SecretStatus.EXPIRING_SOON.value
                rec = f"Secret expires in {ttl_days} days. Plan rotation."
            elif age_days is not None and age_days > policy_days:
                status = SecretStatus.OVERDUE.value
                rec = f"Secret age ({age_days}d) exceeds rotation policy ({policy_days}d)."
            else:
                status = SecretStatus.ACTIVE.value
                rec = "Secret is active and within healthy rotation window."
        elif age_days is not None:
            if age_days > policy_days:
                status = SecretStatus.OVERDUE.value
                rec = f"Secret age ({age_days}d) exceeds {policy_days}-day rotation policy."
            else:
                status = SecretStatus.ACTIVE.value
                rec = f"Secret age is {age_days} days (healthy)."
        else:
            status = SecretStatus.UNMANAGED.value
            rec = "Untracked secret. Add `# @created: YYYY-MM-DD` and `# @expires: YYYY-MM-DD`."

        # Masked value
        if len(val_unquoted) <= 8:
            masked = "***"
        else:
            masked = val_unquoted[:4] + "..." + val_unquoted[-3:]

        items.append(SecretLifecycleItem(
            key=k,
            masked_value=masked,
            provider=provider,
            status=status,
            created_date=created_str,
            expires_date=expires_str,
            rotation_policy_days=policy_days if (m_pol or created_str or expires_str) else None,
            age_days=age_days,
            days_until_expiration=ttl_days,
            owner=owner_str,
            is_ephemeral=is_eph,
            recommendation=rec
        ))

    total = len(items)
    tracked = sum(1 for s in items if s.status not in (SecretStatus.UNTRACKED.value, SecretStatus.UNMANAGED.value))
    untracked = total - tracked
    active = sum(1 for s in items if s.status == SecretStatus.ACTIVE.value)
    expiring = sum(1 for s in items if s.status == SecretStatus.EXPIRING_SOON.value)
    expired = sum(1 for s in items if s.status == SecretStatus.EXPIRED.value)
    overdue = sum(1 for s in items if s.status == SecretStatus.OVERDUE.value)

    # Compliance score calculation
    if total == 0:
        score = 100.0
    else:
        # Base 100 minus penalties
        penalty = (expired * 40.0) + (overdue * 20.0) + (expiring * 10.0) + (untracked * 5.0)
        score = max(0.0, min(100.0, 100.0 - (penalty / total)))

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Actionable suggestions
    recs: List[str] = []
    if expired > 0:
        recs.append(f"URGENT: {expired} secret(s) have passed their expiration deadline. Revoke and replace immediately.")
    if overdue > 0:
        recs.append(f"{overdue} secret(s) exceed maximum rotation policy age ({default_policy_days} days). Schedule credential rotation.")
    if expiring > 0:
        recs.append(f"{expiring} secret(s) expire within {grace_period_days} days. Pre-generate replacement tokens.")
    if untracked > 0:
        recs.append(f"{untracked} secret(s) lack metadata tags. Add `# @created: YYYY-MM-DD` and `# @rotation_days: 90` to automate tracking.")
    if not recs:
        recs.append("All secrets are tracked, active, and fully compliant with rotation policies.")

    return SecretRotationAuditReport(
        total_secrets=total,
        tracked_secrets_count=tracked,
        untracked_secrets_count=untracked,
        active_count=active,
        expiring_soon_count=expiring,
        expired_count=expired,
        overdue_count=overdue,
        compliance_score=score,
        grade=grade,
        secrets=items,
        actionable_recommendations=recs
    )


audit_rotation = audit_secret_rotation


def parse_rotation_metadata(env_content: str, filename: str = ".env") -> List[SecretLifecycleItem]:
    """Parse all secret lifecycle metadata records from .env text."""
    report = audit_secret_rotation(env_content, filename=filename)
    return report.secrets


@dataclass
class RotationResult:
    """Result of an executed secret rotation operation."""
    updated_content: str
    diff: str
    rotated_count: int
    rotated_keys: List[str]
    rotation_date: str
    expiration_date: str
    rotation_policy_days: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def execute_secret_rotation(
    env_content: str,
    target_keys: Optional[List[str]] = None,
    rotation_days: int = 90,
    reference_date: Optional[Union[datetime.date, datetime.datetime]] = None,
    filename: str = ".env",
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Rotate expired, overdue, or specified secrets by injecting fresh ephemeral tokens
    and updating lifecycle timestamp annotations.
    """
    if isinstance(reference_date, datetime.datetime):
        today = reference_date.date()
    elif isinstance(reference_date, datetime.date):
        today = reference_date
    else:
        today = datetime.date.today()

    expiry_date = today + datetime.timedelta(days=rotation_days)

    lines = env_content.splitlines()
    rotated_lines: List[str] = []
    rotated_keys: List[str] = []

    i = 0
    pending_comments: List[str] = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("#"):
            pending_comments.append(line)
            i += 1
            continue

        if not stripped:
            if pending_comments:
                rotated_lines.extend(pending_comments)
                pending_comments = []
            rotated_lines.append(line)
            i += 1
            continue

        if "=" in stripped:
            prefix = "export " if stripped.startswith("export ") else ""
            raw_kv = stripped[len(prefix):]
            k, _, v = raw_kv.partition("=")
            k_clean = k.strip()
            v_clean = v.strip().strip("\"'")

            # Check if this key should be rotated
            should_rotate = False
            if target_keys is not None:
                should_rotate = k_clean in target_keys
            else:
                prov = detect_secret_provider(k_clean, v_clean)
                should_rotate = prov != "generic" or any(s in k_clean.upper() for s in ("SECRET", "KEY", "TOKEN", "PWD", "PASSWORD"))

            if should_rotate:
                provider = detect_secret_provider(k_clean, v_clean)
                new_token = generate_ephemeral_token(provider)

                # Filter out old @created, @expires, @rotation_days annotations from pending_comments
                preserved_comments = [
                    c for c in pending_comments
                    if not any(tag in c for tag in ("@created:", "@expires:", "@rotation_days:", "@provider:"))
                ]
                rotated_lines.extend(preserved_comments)
                pending_comments = []

                # Add new metadata comments
                rotated_lines.append(f"# @created: {today.isoformat()}")
                rotated_lines.append(f"# @rotation_days: {rotation_days}")
                rotated_lines.append(f"# @expires: {expiry_date.isoformat()}")
                rotated_lines.append(f"{prefix}{k_clean}={new_token}")
                rotated_keys.append(k_clean)
            else:
                if pending_comments:
                    rotated_lines.extend(pending_comments)
                    pending_comments = []
                rotated_lines.append(line)
        else:
            if pending_comments:
                rotated_lines.extend(pending_comments)
                pending_comments = []
            rotated_lines.append(line)
        i += 1

    if pending_comments:
        rotated_lines.extend(pending_comments)

    new_env_text = "\n".join(rotated_lines) + ("\n" if env_content.endswith("\n") else "")

    # Compute diff
    diff_lines = difflib.unified_diff(
        env_content.splitlines(keepends=True),
        new_env_text.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}"
    )
    diff_text = "".join(diff_lines)

    summary = {
        "status": "success",
        "rotated_keys_count": len(rotated_keys),
        "rotated_keys": rotated_keys,
        "rotation_date": today.isoformat(),
        "expiration_date": expiry_date.isoformat(),
        "rotation_policy_days": rotation_days
    }

    return new_env_text, diff_text, summary


def rotate_secrets_in_content(
    content: str,
    target_keys: Optional[List[str]] = None,
    rotation_days: int = 90,
    reference_date: Optional[Union[datetime.date, datetime.datetime]] = None,
    filename: str = ".env",
) -> RotationResult:
    """High-level function to rotate secrets in .env text and return structured RotationResult."""
    new_text, diff_text, summary = execute_secret_rotation(
        env_content=content,
        target_keys=target_keys,
        rotation_days=rotation_days,
        reference_date=reference_date,
        filename=filename,
    )
    return RotationResult(
        updated_content=new_text,
        diff=diff_text,
        rotated_count=summary["rotated_keys_count"],
        rotated_keys=summary["rotated_keys"],
        rotation_date=summary["rotation_date"],
        expiration_date=summary["expiration_date"],
        rotation_policy_days=summary["rotation_policy_days"],
    )
