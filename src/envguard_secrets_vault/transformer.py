"""Environment Transformer and Configuration Formatter for EnvGuard.

Provides secret masking, .env.example scaffolding, bidirectional format conversion
(.env <-> JSON <-> YAML <-> Docker Compose), deduplication, sorting, and diffing.
Zero external runtime dependencies - pure Python stdlib.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple


def mask_secret(val: str, style: str = "smart") -> str:
    """Mask a sensitive secret value according to the specified style.

    Styles:
    - 'smart': Preserves known prefix and last 4 characters with redaction in between.
    - 'bullets': Replaces entire string with bullet characters (••••••••).
    - 'partial': Retains first 2 and last 2 characters (e.g. 'ab***yz').
    - 'empty': Returns empty string.
    - 'dummy': Returns placeholder string.
    """
    if not val:
        return ""

    if style == "empty":
        return ""

    if style == "bullets":
        return "•" * min(max(len(val), 8), 24)

    if style == "dummy":
        return "your_secret_here"

    if style == "partial":
        if len(val) <= 4:
            return "****"
        return f"{val[:2]}****{val[-2:]}"

    # Default: 'smart'
    if len(val) <= 8:
        return "••••••••"

    # Detect known prefixes
    prefixes = [
        "sk-proj-",
        "sk-ant-api03-",
        "sk-ant-admin01-",
        "sk-ant-",
        "sk-",
        "sk_live_",
        "sk_test_",
        "sk_mock_",
        "rk_live_",
        "rk_test_",
        "rk_mock_",
        "pk_live_",
        "pk_test_",
        "pk_mock_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "nfp_",
        "sbp_",
        "hf_",
        "npm_",
        "pypi-",
        "AKIA",
        "ASIA",
        "AIza",
    ]
    matched_prefix = ""
    for p in prefixes:
        if val.startswith(p):
            matched_prefix = p
            break

    if matched_prefix:
        remainder = val[len(matched_prefix) :]
        if len(remainder) <= 6:
            return f"{matched_prefix}••••"
        return f"{matched_prefix}{remainder[:2]}...{remainder[-4:]}"

    return f"{val[:4]}...{val[-4:]}"


class EnvTransformer:
    """Transformation engine for environment files and configurations."""

    @staticmethod
    def parse_env_lines(env_text: str) -> List[Dict[str, Any]]:
        """Parse raw .env text into structured records preserving line order and comments."""
        records: List[Dict[str, Any]] = []
        lines = env_text.splitlines()

        multiline_key: Optional[str] = None
        multiline_quote: Optional[str] = None
        multiline_lines: List[str] = []

        for line in lines:
            # Handle multiline continuation
            if multiline_key is not None and multiline_quote is not None:
                multiline_lines.append(line)
                if line.rstrip().endswith(multiline_quote):
                    full_val = "\n".join(multiline_lines)
                    # Strip outer quotes
                    cleaned_val = full_val.strip()
                    if cleaned_val.startswith(multiline_quote) and cleaned_val.endswith(multiline_quote):
                        cleaned_val = cleaned_val[1:-1]
                    records.append({
                        "type": "kv",
                        "key": multiline_key,
                        "value": cleaned_val,
                        "raw": full_val,
                    })
                    multiline_key = None
                    multiline_quote = None
                    multiline_lines = []
                continue

            stripped = line.strip()
            if not stripped:
                records.append({"type": "blank", "raw": line})
                continue

            if stripped.startswith("#"):
                records.append({"type": "comment", "raw": line})
                continue

            # Key-Value match
            kv_match = re.match(r"^(?:export\s+)?([A-Za-z0-9_.\-]+)\s*=\s*(.*)$", line)
            if kv_match:
                key = kv_match.group(1)
                val_raw = kv_match.group(2).strip()

                # Check multiline start
                if (val_raw.startswith('"') and not val_raw.endswith('"') and len(val_raw) > 1) or (
                    val_raw.startswith("'") and not val_raw.endswith("'") and len(val_raw) > 1
                ):
                    multiline_key = key
                    multiline_quote = val_raw[0]
                    multiline_lines = [val_raw]
                    continue

                # Single line value parsing
                val = val_raw
                inline_comment = ""
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                else:
                    cmt_match = re.search(r"\s+#", val)
                    if cmt_match:
                        inline_comment = val[cmt_match.start() :].strip()
                        val = val[: cmt_match.start()].strip()

                records.append({
                    "type": "kv",
                    "key": key,
                    "value": val,
                    "inline_comment": inline_comment,
                    "raw": line,
                })
            else:
                records.append({"type": "raw", "raw": line})

        return records

    @classmethod
    def env_to_dict(cls, env_text: str) -> Dict[str, str]:
        """Convert .env text into a dictionary of key-value pairs."""
        records = cls.parse_env_lines(env_text)
        result: Dict[str, str] = {}
        for r in records:
            if r["type"] == "kv":
                result[r["key"]] = r["value"]
        return result

    @classmethod
    def dict_to_env(cls, env_dict: Dict[str, str]) -> str:
        """Convert a dictionary to a standard formatted .env string."""
        lines: List[str] = []
        for key, val in env_dict.items():
            safe_val = str(val)
            if "\n" in safe_val:
                lines.append(f'{key}="{safe_val}"')
            elif any(c in safe_val for c in [" ", "#", "=", '"', "'", "\t"]):
                # Quote if contains special characters
                escaped = safe_val.replace('"', '\\"')
                lines.append(f'{key}="{escaped}"')
            else:
                lines.append(f"{key}={safe_val}")
        return "\n".join(lines) + ("\n" if lines else "")

    @classmethod
    def generate_env_example(
        cls,
        env_text: str,
        custom_placeholders: Optional[Dict[str, str]] = None,
    ) -> str:
        """Generate a clean sanitized .env.example with descriptive placeholders.

        Preserves comments, section spacing, and key names while removing all secrets.
        """
        placeholders = custom_placeholders or {}
        records = cls.parse_env_lines(env_text)
        out_lines: List[str] = []

        for r in records:
            if r["type"] in ("blank", "comment"):
                out_lines.append(r["raw"])
            elif r["type"] == "kv":
                key = r["key"]
                val = r.get("value", "")
                inline_cmt = r.get("inline_comment", "")

                placeholder = placeholders.get(key) or cls._infer_placeholder(key, val)
                line = f"{key}={placeholder}"
                if inline_cmt:
                    line = f"{line} {inline_cmt}"
                out_lines.append(line)
            else:
                out_lines.append(r["raw"])

        return "\n".join(out_lines) + ("\n" if out_lines else "")

    @staticmethod
    def _infer_placeholder(key: str, value: str) -> str:
        """Infer an appropriate dummy placeholder based on key name and value semantics."""
        k_upper = key.upper()

        # Database URLs
        if "DATABASE_URL" in k_upper or "DB_URI" in k_upper or "POSTGRES" in k_upper:
            return "postgresql://postgres:password@localhost:5432/mydb"
        if "MONGODB_URI" in k_upper or "MONGO_URL" in k_upper:
            return "mongodb://localhost:27017/mydb"
        if "REDIS_URL" in k_upper:
            return "redis://localhost:6379"

        # AI / LLM Providers
        if "OPENAI" in k_upper:
            return "sk-proj-your_openai_api_key_here"
        if "ANTHROPIC" in k_upper or "CLAUDE" in k_upper:
            return "sk-ant-your_anthropic_api_key_here"
        if "HUGGINGFACE" in k_upper or "HF_TOKEN" in k_upper:
            return "hf_your_huggingface_token_here"
        if "COHERE" in k_upper:
            return "your_cohere_api_key_here"

        # Cloud & Payments
        if "STRIPE_SECRET" in k_upper or "STRIPE_KEY" in k_upper:
            return "sk_live_your_stripe_secret_key_here"
        if "STRIPE_PUBLISHABLE" in k_upper or "STRIPE_PK" in k_upper:
            return "pk_live_your_stripe_publishable_key_here"
        if "AWS_ACCESS_KEY" in k_upper:
            return "AKIAIOSFODNN7EXAMPLE"
        if "AWS_SECRET" in k_upper:
            return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        if "GITHUB_TOKEN" in k_upper or "GH_PAT" in k_upper:
            return "ghp_your_github_token_here"
        if "VERCEL" in k_upper:
            return "your_vercel_token_here"
        if "NETLIFY" in k_upper:
            return "nfp_your_netlify_token_here"
        if "SUPABASE_URL" in k_upper:
            return "https://your-project.supabase.co"
        if "SUPABASE" in k_upper and ("KEY" in k_upper or "TOKEN" in k_upper):
            return "your_supabase_api_key_here"

        # Environment & Network
        if k_upper in ("NODE_ENV", "APP_ENV", "ENVIRONMENT", "ENV"):
            return "development"
        if "PORT" in k_upper:
            return value if value.isdigit() else "3000"
        if "HOST" in k_upper:
            return "localhost"
        if "DEBUG" in k_upper or k_upper.startswith("ENABLE_") or k_upper.startswith("USE_"):
            return "false"
        if "EMAIL" in k_upper or "MAIL_FROM" in k_upper:
            return "user@example.com"
        if "URL" in k_upper or "DOMAIN" in k_upper:
            return "https://example.com"

        # Generic secret / key / password
        if any(w in k_upper for w in ("SECRET", "PASSWORD", "PASSWD", "PWD", "TOKEN", "KEY", "AUTH")):
            return f"your_{key.lower()}_here"

        # Fallback default
        return f"your_{key.lower()}_here"

    @classmethod
    def env_to_json(cls, env_text: str, indent: int = 2) -> str:
        """Convert .env text to JSON format string."""
        d = cls.env_to_dict(env_text)
        return json.dumps(d, indent=indent, ensure_ascii=False) + "\n"

    @classmethod
    def json_to_env(cls, json_text: str) -> str:
        """Convert JSON text to standard .env format string."""
        data = json.loads(json_text)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object with key-value pairs.")
        flat_dict: Dict[str, str] = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                flat_dict[str(k)] = json.dumps(v)
            else:
                flat_dict[str(k)] = str(v)
        return cls.dict_to_env(flat_dict)

    @classmethod
    def env_to_yaml(cls, env_text: str) -> str:
        """Convert .env text to YAML format using stdlib emitter."""
        d = cls.env_to_dict(env_text)
        lines: List[str] = []
        for key, val in d.items():
            # Clean scalar quoting
            if "\n" in val:
                lines.append(f"{key}: |")
                for sub in val.splitlines():
                    lines.append(f"  {sub}")
            elif val.lower() in ("true", "false", "yes", "no") or val.isdigit():
                lines.append(f"{key}: {val}")
            else:
                escaped = val.replace('"', '\\"')
                lines.append(f'{key}: "{escaped}"')
        return "\n".join(lines) + ("\n" if lines else "")

    @classmethod
    def yaml_to_env(cls, yaml_text: str) -> str:
        """Parse flat or simple YAML into .env format using stdlib parser."""
        lines = yaml_text.splitlines()
        result: Dict[str, str] = {}
        current_multiline_key: Optional[str] = None
        current_multiline_lines: List[str] = []

        for line in lines:
            if current_multiline_key is not None:
                if line.startswith("  ") or line.startswith("\t"):
                    current_multiline_lines.append(line.lstrip())
                    continue
                else:
                    result[current_multiline_key] = "\n".join(current_multiline_lines)
                    current_multiline_key = None
                    current_multiline_lines = []

            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", stripped)
            if match:
                key, val = match.group(1), match.group(2).strip()
                if val == "|":
                    current_multiline_key = key
                    current_multiline_lines = []
                else:
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    result[key] = val

        if current_multiline_key is not None:
            result[current_multiline_key] = "\n".join(current_multiline_lines)

        return cls.dict_to_env(result)

    @classmethod
    def env_to_docker_compose(
        cls,
        env_text: str,
        service_name: str = "app",
        style: str = "list",
    ) -> str:
        """Convert .env text to Docker Compose environment block."""
        d = cls.env_to_dict(env_text)
        lines = [
            "services:",
            f"  {service_name}:",
            "    environment:",
        ]
        if style == "list":
            for k, v in d.items():
                if "\n" in v or '"' in v:
                    escaped = v.replace('"', '\\"')
                    lines.append(f'      - {k}="{escaped}"')
                else:
                    lines.append(f"      - {k}={v}")
        else:  # map / dict style
            for k, v in d.items():
                if "\n" in v or '"' in v or " " in v:
                    escaped = v.replace('"', '\\"')
                    lines.append(f'      {k}: "{escaped}"')
                else:
                    lines.append(f"      {k}: {v}")
        return "\n".join(lines) + "\n"

    @classmethod
    def docker_compose_to_env(cls, compose_text: str) -> str:
        """Parse Docker Compose environment block into .env format."""
        lines = compose_text.splitlines()
        result: Dict[str, str] = {}
        in_env_block = False
        env_indent = 0

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped == "environment:":
                in_env_block = True
                env_indent = len(line) - len(line.lstrip())
                continue

            if in_env_block:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= env_indent and not stripped.startswith("-"):
                    in_env_block = False
                    continue

                # List item format: - KEY=VAL
                if stripped.startswith("-"):
                    entry = stripped.lstrip("-").strip()
                    if "=" in entry:
                        k, v = entry.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        result[k] = v
                # Mapping format: KEY: VAL or KEY: "VAL"
                elif ":" in stripped:
                    parts = stripped.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip().strip("'\"")
                    result[k] = v

        return cls.dict_to_env(result)

    @classmethod
    def deduplicate_and_sort(
        cls,
        env_text: str,
        sort_keys: bool = True,
        keep_last: bool = True,
    ) -> str:
        """Deduplicate keys and optionally sort alphabetically."""
        records = cls.parse_env_lines(env_text)
        kv_pairs: Dict[str, str] = {}

        for r in records:
            if r["type"] == "kv":
                k = r["key"]
                v = r["value"]
                if keep_last or k not in kv_pairs:
                    kv_pairs[k] = v

        keys = sorted(kv_pairs.keys()) if sort_keys else list(kv_pairs.keys())
        sorted_dict = {k: kv_pairs[k] for k in keys}
        return cls.dict_to_env(sorted_dict)

    @classmethod
    def diff_env(cls, env_text_a: str, env_text_b: str) -> Dict[str, Any]:
        """Compute the difference between two environment file configurations."""
        dict_a = cls.env_to_dict(env_text_a)
        dict_b = cls.env_to_dict(env_text_b)

        keys_a = set(dict_a.keys())
        keys_b = set(dict_b.keys())

        added_keys = sorted(list(keys_b - keys_a))
        removed_keys = sorted(list(keys_a - keys_b))
        common_keys = keys_a & keys_b

        modified: Dict[str, Dict[str, str]] = {}
        unchanged: List[str] = []

        for k in sorted(common_keys):
            if dict_a[k] != dict_b[k]:
                modified[k] = {"before": dict_a[k], "after": dict_b[k]}
            else:
                unchanged.append(k)

        return {
            "added": {k: dict_b[k] for k in added_keys},
            "removed": {k: dict_a[k] for k in removed_keys},
            "modified": modified,
            "unchanged": unchanged,
            "total_a": len(dict_a),
            "total_b": len(dict_b),
            "has_changes": bool(added_keys or removed_keys or modified),
        }
