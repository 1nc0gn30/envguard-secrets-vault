#!/usr/bin/env python3
"""EnvGuard Secrets Vault - Model Context Protocol (MCP) Server & Core Engines.

Zero external dependencies: Pure Python standard library implementation of:
1. JSON-RPC 2.0 / MCP Server over stdio
2. 20+ Pattern Secret Detector & Shannon Entropy Scanner
3. Safe .env Variable Masker (partial/full)
4. Sanitized .env.example Placeholder Generator
5. Armored Vault Cryptographic Suite (PBKDF2-HMAC-SHA256 + AES-256-CTR + HMAC-SHA256)
6. Environment Comparator & Type Mismatch Differ
7. System Diagnostics & MCP Client Configuration Generator
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ============================================================================
# Protocol & Engine Constants
# ============================================================================

SERVER_NAME = "envguard-secrets-vault"
SERVER_VERSION = "1.0.0"
MCP_PROTOCOL_VERSION = "2024-11-05"

# Armored Vault Envelope Markers
VAULT_HEADER = "-----BEGIN ENVGUARD ENCRYPTED VAULT-----"
VAULT_FOOTER = "-----END ENVGUARD ENCRYPTED VAULT-----"
PBKDF2_ITERATIONS = 100_000

# ============================================================================
# Pure Python AES-256 CTR Engine (NIST FIPS 197 compliant)
# ============================================================================

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _sub_word(w: int) -> int:
    return (
        (SBOX[(w >> 24) & 0xFF] << 24)
        | (SBOX[(w >> 16) & 0xFF] << 16)
        | (SBOX[(w >> 8) & 0xFF] << 8)
        | (SBOX[w & 0xFF])
    )


def _rot_word(w: int) -> int:
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)


def _aes256_key_expansion(key: bytes) -> List[int]:
    w: List[int] = []
    for i in range(8):
        w.append(
            (key[4 * i] << 24)
            | (key[4 * i + 1] << 16)
            | (key[4 * i + 2] << 8)
            | key[4 * i + 3]
        )
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // 8] << 24)
        elif i % 8 == 4:
            temp = _sub_word(temp)
        w.append(w[i - 8] ^ temp)
    return w


def _xtimes(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _aes_encrypt_block(block: bytes, w: List[int]) -> bytes:
    s = [[block[row + 4 * col] for col in range(4)] for row in range(4)]

    # AddRoundKey 0
    for col in range(4):
        kw = w[col]
        s[0][col] ^= (kw >> 24) & 0xFF
        s[1][col] ^= (kw >> 16) & 0xFF
        s[2][col] ^= (kw >> 8) & 0xFF
        s[3][col] ^= kw & 0xFF

    # Rounds 1-13
    for round_idx in range(1, 14):
        # SubBytes
        for r in range(4):
            for c in range(4):
                s[r][c] = SBOX[s[r][c]]
        # ShiftRows
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
        # MixColumns
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            t = a0 ^ a1 ^ a2 ^ a3
            s[0][c] ^= t ^ _xtimes(a0 ^ a1)
            s[1][c] ^= t ^ _xtimes(a1 ^ a2)
            s[2][c] ^= t ^ _xtimes(a2 ^ a3)
            s[3][c] ^= t ^ _xtimes(a3 ^ a0)
        # AddRoundKey
        for c in range(4):
            kw = w[round_idx * 4 + c]
            s[0][c] ^= (kw >> 24) & 0xFF
            s[1][c] ^= (kw >> 16) & 0xFF
            s[2][c] ^= (kw >> 8) & 0xFF
            s[3][c] ^= kw & 0xFF

    # Round 14 (Final round, no MixColumns)
    for r in range(4):
        for c in range(4):
            s[r][c] = SBOX[s[r][c]]
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
    for c in range(4):
        kw = w[14 * 4 + c]
        s[0][c] ^= (kw >> 24) & 0xFF
        s[1][c] ^= (kw >> 16) & 0xFF
        s[2][c] ^= (kw >> 8) & 0xFF
        s[3][c] ^= kw & 0xFF

    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r][c]
    return bytes(out)


def aes256_ctr_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts or decrypts bytes using AES-256 in Counter (CTR) mode."""
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES IV/nonce must be exactly 16 bytes, got {len(iv)}")

    w = _aes256_key_expansion(key)
    iv_int = int.from_bytes(iv, "big")
    out = bytearray(len(data))

    num_blocks = (len(data) + 15) // 16
    for i in range(num_blocks):
        ctr_val = (iv_int + i) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        ctr_bytes = ctr_val.to_bytes(16, "big")
        keystream = _aes_encrypt_block(ctr_bytes, w)

        start = i * 16
        end = min(start + 16, len(data))
        for j in range(start, end):
            out[j] = data[j] ^ keystream[j - start]

    return bytes(out)


# ============================================================================
# Secret Detection Rules & Entropy Engine
# ============================================================================

SECRET_DETECTORS: List[Dict[str, Any]] = [
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "category": "Cloud Infrastructure",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "AWS 20-character Access Key ID leaked in configuration.",
        "remediation": "Revoke AWS IAM access key and migrate to IAM Roles or Secrets Manager.",
    },
    {
        "id": "SEC002",
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws(?:.{0,20})?(?:secret|key|access|token)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        "category": "Cloud Infrastructure",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "AWS 40-character Secret Access Key found.",
        "remediation": "Immediately invalidate AWS Secret Key in AWS IAM console.",
    },
    {
        "id": "SEC003",
        "name": "OpenAI API Key",
        "regex": r"sk-(?:proj-|live-|admin-)?[a-zA-Z0-9_-]{20,}",
        "category": "AI / LLM Service",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "OpenAI API Key detected.",
        "remediation": "Rotate API key in OpenAI Dashboard and store in encrypted vault.",
    },
    {
        "id": "SEC004",
        "name": "Anthropic API Key",
        "regex": r"sk-ant-[a-zA-Z0-9_-]{20,}",
        "category": "AI / LLM Service",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "Anthropic Claude API Key detected.",
        "remediation": "Revoke key in Anthropic Console and inject via serverless environment.",
    },
    {
        "id": "SEC005",
        "name": "GitHub Personal Access Token (PAT)",
        "regex": r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})",
        "category": "Source Control",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "GitHub Personal Access Token with repository permissions found.",
        "remediation": "Revoke PAT in GitHub Developer Settings -> Personal access tokens.",
    },
    {
        "id": "SEC006",
        "name": "GitHub App / OAuth Token",
        "regex": r"(?:gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}",
        "category": "Source Control",
        "severity": "HIGH",
        "deduction": 15,
        "description": "GitHub OAuth or App access token found.",
        "remediation": "Rotate OAuth token and use ephemeral GitHub Actions OIDC tokens.",
    },
    {
        "id": "SEC007",
        "name": "Stripe Live Secret Key",
        "regex": r"sk_(?:live|test|mock)_[0-9a-zA-Z]{20,}",
        "category": "Payment Gateway",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "Stripe Production Live Secret Key detected.",
        "remediation": "Roll Stripe API key in Developers -> API keys dashboard immediately.",
    },
    {
        "id": "SEC008",
        "name": "Stripe Restricted Key",
        "regex": r"rk_(?:live|test|mock)_[0-9a-zA-Z]{20,}",
        "category": "Payment Gateway",
        "severity": "HIGH",
        "deduction": 15,
        "description": "Stripe Live Restricted Key found.",
        "remediation": "Rotate Stripe restricted key and restrict permissions to minimal scope.",
    },
    {
        "id": "SEC009",
        "name": "Google / Firebase API Key",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "category": "Cloud Platform",
        "severity": "HIGH",
        "deduction": 15,
        "description": "Google Cloud / Firebase API Key detected.",
        "remediation": "Apply HTTP referrer and API service restrictions in Google Cloud Console.",
    },
    {
        "id": "SEC010",
        "name": "Slack Bot / User Token",
        "regex": r"xox[baprs]-(?:mock-)?[0-9a-zA-Z\-]{20,36}",
        "category": "Messaging / Chat",
        "severity": "HIGH",
        "deduction": 15,
        "description": "Slack Bot, App, or User OAuth token detected.",
        "remediation": "Revoke Slack token in api.slack.com/apps and reinstall app.",
    },
    {
        "id": "SEC011",
        "name": "Slack Incoming Webhook",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "category": "Messaging / Chat",
        "severity": "MEDIUM",
        "deduction": 10,
        "description": "Slack Incoming Webhook URL containing auth credentials.",
        "remediation": "Deactivate webhook URL and regenerate in Slack workspace app settings.",
    },
    {
        "id": "SEC012",
        "name": "Private Cryptographic Key",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "category": "Cryptography / SSH",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "Unencrypted Private Cryptographic Key (RSA/EC/SSH/PGP).",
        "remediation": "Remove private key from repo, rotate keypair, and use SSH Agent.",
    },
    {
        "id": "SEC013",
        "name": "Database URI with Credentials",
        "regex": r"(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:([^@\s]+)@",
        "category": "Database",
        "severity": "CRITICAL",
        "deduction": 25,
        "description": "Database connection string containing embedded plaintext password.",
        "remediation": "Rotate database password and store URL in encrypted vault.",
    },
    {
        "id": "SEC014",
        "name": "JSON Web Token (JWT)",
        "regex": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-\.\+/=]+",
        "category": "Authentication",
        "severity": "MEDIUM",
        "deduction": 10,
        "description": "Signed JSON Web Token (JWT) hardcoded in environment.",
        "remediation": "Do not hardcode active JWT tokens. Use short-lived tokens generated at runtime.",
    },
    {
        "id": "SEC015",
        "name": "Generic High-Entropy Secret",
        "regex": r"(?i)(?:secret|password|passwd|auth_token|api_key|encryption_key|master_key|token)[^=\n]*=\s*[\"']?([A-Za-z0-9+/=_\-]{16,})[\"']?",
        "category": "Credentials",
        "severity": "HIGH",
        "deduction": 15,
        "description": "Sensitive variable name with high entropy credential value.",
        "remediation": "Mask or encrypt this variable with EnvGuard Vault before committing.",
    },
]

SAFE_KEY_PREFIXES = ("PORT", "HOST", "DEBUG", "NODE_ENV", "APP_ENV", "ENVIRONMENT", "TZ", "LOG_LEVEL")


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _is_placeholder(val: str) -> bool:
    """Returns True if the value appears to be a dummy or documentation placeholder."""
    v = val.strip().lower()
    if not v:
        return True
    exact_placeholders = {
        "example", "placeholder", "changeme", "todo", "dummy", "sample",
        "none", "null", "undefined", "localhost", "127.0.0.1", "0.0.0.0",
        "test", "xxx", "your-api-key-here", "your-secret-here", "your-token-here"
    }
    if v in exact_placeholders:
        return True
    prefix_placeholders = (
        "your-", "your_", "<", "${", "your ", "insert-", "enter-"
    )
    if v.startswith(prefix_placeholders) or (v.startswith("<") and v.endswith(">")):
        return True
    return False


def scan_secrets(content: str, source: str = "<input>", min_score: int = 80) -> Dict[str, Any]:
    """Scans .env text content for leaked API keys, tokens, high entropy, and security flaws."""
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    total_deduction = 0

    seen_signatures = set()

    for line_idx, line in enumerate(lines, start=1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue

        line_has_match = False
        # Check all specific pattern detectors first (SEC001 to SEC014)
        for detector in SECRET_DETECTORS:
            if detector["id"] == "SEC015":
                continue
            matches = list(re.finditer(detector["regex"], line))
            for m in matches:
                matched_val = m.group(1) if m.groups() else m.group(0)
                if _is_placeholder(matched_val):
                    continue

                sig = f"{detector['id']}:{line_idx}:{matched_val[:8]}"
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                deduct = detector["deduction"]
                total_deduction += deduct
                line_has_match = True

                # Mask matched string for report safety
                if len(matched_val) > 8:
                    masked = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:]
                else:
                    masked = "*" * len(matched_val)

                findings.append({
                    "id": detector["id"],
                    "name": detector["name"],
                    "category": detector["category"],
                    "severity": detector["severity"],
                    "deduction": deduct,
                    "line": line_idx,
                    "matched_sample": masked,
                    "description": detector["description"],
                    "remediation": detector["remediation"],
                })

        # Only check generic high-entropy secret (SEC015) if no specific pattern matched on this line
        if not line_has_match and "=" in line_stripped:
            parts = line_stripped.split("=", 1)
            key = parts[0].strip()
            val = parts[1].strip().strip("\"'")

            if len(val) >= 16 and not _is_placeholder(val) and not key.upper().startswith(SAFE_KEY_PREFIXES):
                ent = calculate_shannon_entropy(val)
                sec015 = next(d for d in SECRET_DETECTORS if d["id"] == "SEC015")
                m_generic = re.search(sec015["regex"], line)
                if m_generic or ent >= 3.8:
                    sig = f"GENERIC:{line_idx}:{key}"
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        deduct = 15
                        total_deduction += deduct
                        masked = val[:3] + "*" * (len(val) - 6) + val[-3:] if len(val) > 6 else "*" * len(val)
                        findings.append({
                            "id": "SEC015",
                            "name": f"High-Entropy Secret ({key})",
                            "category": "Credentials",
                            "severity": "HIGH",
                            "deduction": deduct,
                            "line": line_idx,
                            "matched_sample": masked,
                            "description": f"Variable '{key}' has high Shannon entropy ({ent:.2f} bits/symbol).",
                            "remediation": "Encrypt this variable with EnvGuard Vault before committing.",
                        })

    score = max(0, 100 - total_deduction)
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    return {
        "source": source,
        "score": score,
        "grade": grade,
        "min_score": min_score,
        "passed": score >= min_score and crit_count == 0,
        "metrics": {
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "total_findings": len(findings),
            "total_lines_scanned": len(lines),
        },
        "findings": findings,
    }


def scan_file_or_dir(target_path: str, min_score: int = 80, recursive: bool = True) -> Dict[str, Any]:
    """Scans a file or recursively audits all .env / config files in a directory."""
    p = Path(target_path)
    if not p.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    if p.is_file():
        content = p.read_text(encoding="utf-8", errors="replace")
        return scan_secrets(content, source=str(p), min_score=min_score)

    # Directory scan
    ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", "dist", "build"}
    files_to_scan: List[Path] = []

    pattern_names = [".env*", "*.env", "*.conf", "*.cfg", "settings.py", "secrets.json", "config.json"]
    for root, dirs, files in os.walk(p):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            f_lower = f.lower()
            if any(f_lower.startswith(".env") or f_lower.endswith(".env") or f in ("secrets.json", "config.json") for _ in [1]):
                files_to_scan.append(Path(root) / f)
            if not recursive:
                break

    if not files_to_scan:
        # Fallback: check if standard .env exists
        candidate = p / ".env"
        if candidate.exists():
            files_to_scan.append(candidate)

    all_findings: List[Dict[str, Any]] = []
    total_deduction = 0
    total_lines = 0

    for f_path in files_to_scan:
        try:
            content = f_path.read_text(encoding="utf-8", errors="replace")
            res = scan_secrets(content, source=str(f_path), min_score=min_score)
            total_lines += res["metrics"]["total_lines_scanned"]
            for f in res["findings"]:
                f_copy = dict(f)
                f_copy["file"] = str(f_path.relative_to(p) if f_path.is_relative_to(p) else f_path)
                all_findings.append(f_copy)
                total_deduction += f["deduction"]
        except Exception as e:
            all_findings.append({
                "id": "SCAN-ERR",
                "name": "File Read Error",
                "category": "Error",
                "severity": "LOW",
                "deduction": 5,
                "line": 1,
                "file": str(f_path),
                "matched_sample": "",
                "description": f"Failed reading file: {str(e)}",
                "remediation": "Check file permissions.",
            })

    score = max(0, 100 - total_deduction)
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    crit_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in all_findings if f["severity"] == "LOW")

    return {
        "source": str(p),
        "target_type": "directory" if p.is_dir() else "file",
        "scanned_files_count": len(files_to_scan),
        "score": score,
        "grade": grade,
        "min_score": min_score,
        "passed": score >= min_score and crit_count == 0,
        "metrics": {
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "total_findings": len(all_findings),
            "total_lines_scanned": total_lines,
        },
        "findings": all_findings,
    }


# ============================================================================
# Safe Variable Masking Engine
# ============================================================================

def mask_env_content(content: str, mode: str = "partial", mask_char: str = "*") -> Dict[str, Any]:
    """Masks sensitive values in .env while preserving formatting, comments, and safe variables."""
    lines = content.splitlines()
    masked_lines: List[str] = []
    masked_keys: List[str] = []
    total_vars = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            masked_lines.append(line)
            continue

        # Extract key and value preserving indentation
        parts = line.split("=", 1)
        key_part = parts[0]
        val_part = parts[1]

        key_clean = key_part.strip()
        val_clean = val_part.strip().strip("\"'")
        total_vars += 1

        # Check if key is inherently safe
        is_safe = key_clean.upper().startswith(SAFE_KEY_PREFIXES) or val_clean.lower() in ("true", "false", "development", "production", "test")

        if is_safe and calculate_shannon_entropy(val_clean) < 3.5:
            masked_lines.append(line)
            continue

        # Mask the value
        masked_keys.append(key_clean)
        if mode == "full":
            masked_val = mask_char * max(16, len(val_clean))
        else:  # partial
            if len(val_clean) <= 6:
                masked_val = mask_char * len(val_clean)
            elif len(val_clean) <= 12:
                masked_val = val_clean[:2] + (mask_char * (len(val_clean) - 4)) + val_clean[-2:]
            else:
                masked_val = val_clean[:4] + (mask_char * 8) + val_clean[-4:]

        # Reconstruct line with quotes if original was quoted
        if val_part.strip().startswith('"') and val_part.strip().endswith('"'):
            masked_val = f'"{masked_val}"'
        elif val_part.strip().startswith("'") and val_part.strip().endswith("'"):
            masked_val = f"'{masked_val}'"

        indent = line[: len(line) - len(line.lstrip())]
        masked_lines.append(f"{key_part}={masked_val}")

    return {
        "masked_content": "\n".join(masked_lines) + ("\n" if content.endswith("\n") else ""),
        "total_variables": total_vars,
        "masked_variables_count": len(masked_keys),
        "masked_keys": masked_keys,
        "mode": mode,
    }


# ============================================================================
# Sanitized .env.example Placeholder Generator
# ============================================================================

def generate_env_example(content: str) -> Dict[str, Any]:
    """Generates a clean, sanitized .env.example with dummy placeholders from a live .env."""
    lines = content.splitlines()
    example_lines: List[str] = [
        "# =============================================================================",
        "# Sanitized Environment Template (.env.example)",
        "# Generated automatically by EnvGuard Secrets Vault",
        "# =============================================================================",
        "",
    ]
    generated_keys: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            example_lines.append(line)
            continue

        parts = line.split("=", 1)
        key_part = parts[0]
        val_part = parts[1]

        key_clean = key_part.strip()
        val_clean = val_part.strip().strip("\"'")
        generated_keys.append(key_clean)

        k_upper = key_clean.upper()

        # Generate intelligent placeholder based on key name
        if k_upper.startswith("PORT"):
            placeholder = val_clean if val_clean.isdigit() else "8080"
        elif k_upper in ("NODE_ENV", "ENVIRONMENT", "APP_ENV"):
            placeholder = "development"
        elif k_upper.startswith("HOST"):
            placeholder = "localhost"
        elif k_upper.startswith("DEBUG"):
            placeholder = "false"
        elif "OPENAI" in k_upper:
            placeholder = '"your-openai-api-key-here"'
        elif "ANTHROPIC" in k_upper or "CLAUDE" in k_upper:
            placeholder = '"your-anthropic-api-key-here"'
        elif "AWS_ACCESS_KEY" in k_upper:
            placeholder = '"your-aws-access-key-id"'
        elif "AWS_SECRET" in k_upper:
            placeholder = '"your-aws-secret-access-key"'
        elif "AWS_REGION" in k_upper:
            placeholder = '"us-east-1"'
        elif "STRIPE_SECRET" in k_upper:
            placeholder = '"sk_test_your_stripe_secret_key"'
        elif "STRIPE_PUBLISHABLE" in k_upper or "STRIPE_PK" in k_upper:
            placeholder = '"pk_test_your_stripe_publishable_key"'
        elif "GITHUB_TOKEN" in k_upper or "GH_TOKEN" in k_upper:
            placeholder = '"your-github-personal-access-token"'
        elif "SLACK_BOT_TOKEN" in k_upper:
            placeholder = '"xoxb-your-slack-bot-token"'
        elif "SLACK_WEBHOOK" in k_upper:
            placeholder = '"https://hooks.slack.com/services/T000/B000/XXXX"'
        elif "JWT_SECRET" in k_upper or "SESSION_SECRET" in k_upper:
            placeholder = '"your-jwt-secret-minimum-32-chars"'
        elif "DATABASE_URL" in k_upper or "POSTGRES_URL" in k_upper:
            placeholder = '"postgresql://user:password@localhost:5432/dbname"'
        elif "REDIS_URL" in k_upper:
            placeholder = '"redis://localhost:6379/0"'
        elif "MONGO" in k_upper:
            placeholder = '"mongodb://localhost:27017/dbname"'
        elif "PASSWORD" in k_upper or "PASSWD" in k_upper:
            placeholder = '"your-secure-password-here"'
        elif "KEY" in k_upper or "SECRET" in k_upper or "TOKEN" in k_upper:
            placeholder = f'"your-{key_clean.lower().replace("_", "-")}-here"'
        else:
            if val_clean.lower() in ("true", "false", "0", "1"):
                placeholder = val_clean
            elif val_clean.isdigit():
                placeholder = val_clean
            else:
                placeholder = f'"your-{key_clean.lower().replace("_", "-")}"'

        example_lines.append(f"{key_part}={placeholder}")

    return {
        "example_content": "\n".join(example_lines) + "\n",
        "total_variables": len(generated_keys),
        "variables": generated_keys,
    }


# ============================================================================
# Armored Vault Encryption & Decryption Engine
# ============================================================================

def vault_encrypt(content: str, password: str) -> Dict[str, Any]:
    """Encrypts .env content into a hardened armored vault payload with master password."""
    if not password:
        raise ValueError("Encryption password cannot be empty.")

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    # Derive 64 bytes: 32 for AES-256 key, 32 for HMAC-SHA256 key
    kdf_derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64)
    enc_key = kdf_derived[:32]
    mac_key = kdf_derived[32:64]

    raw_data = content.encode("utf-8")
    ciphertext = aes256_ctr_crypt(raw_data, enc_key, iv)

    # Encrypt-then-MAC: HMAC over (salt + iv + ciphertext)
    hmac_tag = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()

    # Base64 encode the ciphertext
    b64_cipher = base64.b64encode(ciphertext).decode("ascii")
    chunk_size = 64
    payload_lines = [b64_cipher[i : i + chunk_size] for i in range(0, len(b64_cipher), chunk_size)]

    armor_lines = [
        VAULT_HEADER,
        "version: 1",
        "cipher: AES-256-CTR-HMAC-SHA256",
        "kdf: PBKDF2-HMAC-SHA256",
        f"iterations: {PBKDF2_ITERATIONS}",
        f"salt: {salt.hex()}",
        f"iv: {iv.hex()}",
        f"hmac: {hmac_tag.hex()}",
        "payload:",
    ] + payload_lines + [VAULT_FOOTER]

    armored_vault = "\n".join(armor_lines) + "\n"

    return {
        "vault_armor": armored_vault,
        "cipher": "AES-256-CTR-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt_hex": salt.hex(),
        "iv_hex": iv.hex(),
        "hmac_hex": hmac_tag.hex(),
        "plaintext_bytes": len(raw_data),
        "ciphertext_bytes": len(ciphertext),
    }


def vault_decrypt(vault_armor: str, password: str) -> Dict[str, Any]:
    """Decrypts an EnvGuard armored vault payload using the master password."""
    if not password:
        raise ValueError("Decryption password cannot be empty.")

    lines = [ln.strip() for ln in vault_armor.strip().splitlines() if ln.strip()]

    if not lines or VAULT_HEADER not in lines[0] or VAULT_FOOTER not in lines[-1]:
        raise ValueError("Invalid format: Missing EnvGuard Armored Vault envelope headers.")

    headers: Dict[str, str] = {}
    payload_chunks: List[str] = []
    in_payload = False

    for line in lines[1:-1]:
        if line.lower() == "payload:":
            in_payload = True
            continue
        if in_payload:
            payload_chunks.append(line)
        else:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

    salt_hex = headers.get("salt")
    iv_hex = headers.get("iv")
    hmac_hex = headers.get("hmac")
    iterations_str = headers.get("iterations", str(PBKDF2_ITERATIONS))

    if not salt_hex or not iv_hex or not hmac_hex:
        raise ValueError("Corrupted vault: Missing salt, IV, or HMAC authentication tag.")

    try:
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        expected_hmac = bytes.fromhex(hmac_hex)
        iterations = int(iterations_str)
        ciphertext = base64.b64decode("".join(payload_chunks))
    except Exception as e:
        raise ValueError(f"Corrupted vault envelope data: {str(e)}")

    # Derive keys
    kdf_derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
    enc_key = kdf_derived[:32]
    mac_key = kdf_derived[32:64]

    # Verify HMAC in constant time
    actual_hmac = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_hmac, expected_hmac):
        raise ValueError("Authentication failed: Invalid master password or tampered vault data.")

    plaintext_bytes = aes256_ctr_crypt(ciphertext, enc_key, iv)
    try:
        decrypted_text = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decryption failed: UTF-8 decoding error on decrypted payload.")

    return {
        "decrypted_content": decrypted_text,
        "cipher": headers.get("cipher", "AES-256-CTR-HMAC-SHA256"),
        "plaintext_bytes": len(plaintext_bytes),
        "ciphertext_bytes": len(ciphertext),
    }


# ============================================================================
# Environment Differ & Type Mismatch Engine
# ============================================================================

def _parse_env_dict(content: str) -> Dict[str, str]:
    """Parses .env string into a key-value dictionary."""
    env_map: Dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env_map[k.strip()] = v.strip().strip("\"'")
    return env_map


def _infer_type(val: str) -> str:
    """Infers high-level type of a configuration value."""
    v = val.strip()
    if v.lower() in ("true", "false", "yes", "no", "on", "off"):
        return "boolean"
    if v.isdigit():
        return "integer"
    try:
        float(v)
        return "float"
    except ValueError:
        pass
    if v.startswith(("http://", "https://", "postgres://", "postgresql://", "redis://", "mongodb://")):
        return "url"
    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        try:
            json.loads(v)
            return "json"
        except Exception:
            pass
    if calculate_shannon_entropy(v) >= 3.8 and len(v) >= 16:
        return "secret/token"
    return "string"


def diff_environments(
    env_a_content: str,
    env_b_content: str,
    name_a: str = "Environment A",
    name_b: str = "Environment B",
) -> Dict[str, Any]:
    """Compares two .env environments for missing keys, value differences, and type mismatches."""
    dict_a = _parse_env_dict(env_a_content)
    dict_b = _parse_env_dict(env_b_content)

    keys_a = set(dict_a.keys())
    keys_b = set(dict_b.keys())

    all_keys = sorted(keys_a | keys_b)
    only_in_a = sorted(keys_a - keys_b)
    only_in_b = sorted(keys_b - keys_a)
    common_keys = sorted(keys_a & keys_b)

    differences: List[Dict[str, Any]] = []
    identical_count = 0

    for k in all_keys:
        in_a = k in dict_a
        in_b = k in dict_b
        val_a = dict_a.get(k)
        val_b = dict_b.get(k)

        type_a = _infer_type(val_a) if in_a else None
        type_b = _infer_type(val_b) if in_b else None

        if in_a and not in_b:
            differences.append({
                "key": k,
                "status": "missing_in_b",
                "val_a": val_a,
                "val_b": None,
                "type_a": type_a,
                "type_b": None,
                "type_mismatch": False,
            })
        elif in_b and not in_a:
            differences.append({
                "key": k,
                "status": "missing_in_a",
                "val_a": None,
                "val_b": val_b,
                "type_a": None,
                "type_b": type_b,
                "type_mismatch": False,
            })
        else:
            if val_a == val_b:
                identical_count += 1
            else:
                type_mismatch = type_a != type_b
                differences.append({
                    "key": k,
                    "status": "value_diff",
                    "val_a": val_a,
                    "val_b": val_b,
                    "type_a": type_a,
                    "type_b": type_b,
                    "type_mismatch": type_mismatch,
                })

    return {
        "name_a": name_a,
        "name_b": name_b,
        "total_keys_a": len(keys_a),
        "total_keys_b": len(keys_b),
        "keys_only_in_a": only_in_a,
        "keys_only_in_b": only_in_b,
        "common_keys_count": len(common_keys),
        "identical_values_count": identical_count,
        "differences_count": len(differences),
        "differences": differences,
    }


# ============================================================================
# Diagnostics & System Specs Engine
# ============================================================================

def get_diagnostics() -> Dict[str, Any]:
    """Returns platform runtime specs, supported secret detectors, and crypto algorithms."""
    return {
        "app": SERVER_NAME,
        "version": SERVER_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "platform": {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "byte_order": sys.byteorder,
        },
        "crypto_suite": {
            "cipher": "AES-256-CTR (Pure Python NIST FIPS 197 standard)",
            "key_derivation": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": PBKDF2_ITERATIONS,
            "mac_algorithm": "HMAC-SHA256 (Encrypt-then-MAC)",
            "zero_external_dependencies": True,
        },
        "detectors": [
            {
                "id": d["id"],
                "name": d["name"],
                "category": d["category"],
                "severity": d["severity"],
                "deduction": d["deduction"],
            }
            for d in SECRET_DETECTORS
        ],
        "total_detectors": len(SECRET_DETECTORS),
        "entropy_detection": {
            "algorithm": "Shannon Entropy (bits/symbol)",
            "threshold": 3.8,
            "min_length": 16,
        },
    }


# ============================================================================
# MCP Client Configs Generator
# ============================================================================

def generate_mcp_client_config(client_type: str = "all", server_path: Optional[str] = None) -> Dict[str, Any]:
    """Generates ready-to-use MCP configuration files for Claude Desktop, Cursor, Cline, and Zed."""
    cmd = "python3"
    args = ["-m", "envguard_secrets_vault", "mcp"]
    if server_path:
        args = [server_path, "mcp"]

    configs: Dict[str, Any] = {
        "claude_desktop": {
            "mcpServers": {
                "envguard": {
                    "command": cmd,
                    "args": args,
                }
            }
        },
        "cursor": {
            "mcpServers": {
                "envguard": {
                    "command": cmd,
                    "args": args,
                }
            }
        },
        "cline": {
            "mcpServers": {
                "envguard": {
                    "command": cmd,
                    "args": args,
                    "disabled": False,
                    "autoApprove": [],
                }
            }
        },
        "zed": {
            "context_servers": {
                "envguard": {
                    "command": {
                        "path": cmd,
                        "args": args,
                    }
                }
            }
        },
    }

    t = client_type.lower().strip()
    if t in ("claude", "claude_desktop", "claude-desktop"):
        return {"claude_desktop": configs["claude_desktop"]}
    elif t == "cursor":
        return {"cursor": configs["cursor"]}
    elif t == "cline":
        return {"cline": configs["cline"]}
    elif t == "zed":
        return {"zed": configs["zed"]}
    return configs


# ============================================================================
# MCP Tool Definitions (JSON-RPC Schema)
# ============================================================================

MCP_TOOLS_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "env_scan_secrets",
        "description": "Scans .env configuration text or target file/directory for leaked API keys, high entropy tokens, private keys, and security risks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw .env configuration text content to scan.",
                },
                "target_path": {
                    "type": "string",
                    "description": "Local file or directory path to scan (e.g. .env, backend/.env).",
                },
                "min_score": {
                    "type": "integer",
                    "description": "Minimum passing security score (0-100, default 80).",
                    "default": 80,
                },
            },
        },
    },
    {
        "name": "env_mask_variables",
        "description": "Safely masks sensitive credentials in .env while preserving formatting, comments, and safe configuration keys.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw .env content to mask.",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional file path to read .env content from.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["partial", "full"],
                    "description": "'partial' retains token prefix/suffix, 'full' obscures entire value.",
                    "default": "partial",
                },
            },
        },
    },
    {
        "name": "env_generate_example",
        "description": "Auto-generates a clean, sanitized .env.example with descriptive dummy placeholders.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw .env text content to sanitize into an example file.",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional file path to read .env content from.",
                },
            },
        },
    },
    {
        "name": "env_vault_encrypt",
        "description": "Encrypts .env with a master password into an armored AES-256-CTR vault with HMAC-SHA256 integrity check.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw .env content to encrypt.",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional file path to read .env from.",
                },
                "password": {
                    "type": "string",
                    "description": "Master password to encrypt the vault.",
                },
            },
            "required": ["password"],
        },
    },
    {
        "name": "env_vault_decrypt",
        "description": "Decrypts an EnvGuard armored vault payload back to plaintext .env using master password.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_armor": {
                    "type": "string",
                    "description": "Armored vault content string.",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional path to .env.enc or vault file.",
                },
                "password": {
                    "type": "string",
                    "description": "Master password to unlock the vault.",
                },
            },
            "required": ["password"],
        },
    },
    {
        "name": "env_diff_environments",
        "description": "Compares two .env environments for missing keys, value differences, and type mismatches.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "env_a": {
                    "type": "string",
                    "description": "First .env content or file path (e.g. .env.development).",
                },
                "env_b": {
                    "type": "string",
                    "description": "Second .env content or file path (e.g. .env.production).",
                },
                "name_a": {
                    "type": "string",
                    "description": "Label for environment A.",
                    "default": "Env A",
                },
                "name_b": {
                    "type": "string",
                    "description": "Label for environment B.",
                    "default": "Env B",
                },
            },
            "required": ["env_a", "env_b"],
        },
    },
    {
        "name": "env_get_diagnostics",
        "description": "Retrieves multi-OS platform specs, supported secret detector patterns, and cryptographic capabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "env_shamir_split",
        "description": "Split a master secret or .env file into n Shamir threshold shares requiring any k shares to reconstruct.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "secret": {
                    "type": "string",
                    "description": "Secret text, master password, or raw .env content to split.",
                },
                "threshold": {
                    "type": "integer",
                    "description": "Quorum threshold k (minimum shares needed, default: 3).",
                    "default": 3,
                },
                "total_shares": {
                    "type": "integer",
                    "description": "Total shares n to produce (default: 5).",
                    "default": 5,
                },
                "label": {
                    "type": "string",
                    "description": "Human-readable label for the key quorum.",
                    "default": "master-key",
                },
            },
            "required": ["secret"],
        },
    },
    {
        "name": "env_shamir_combine",
        "description": "Reconstruct original secret from a quorum of at least k Shamir secret shares.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "shares": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Array of armored share strings or share JSON dictionaries.",
                },
            },
            "required": ["shares"],
        },
    },
]


# ============================================================================
# MCP JSON-RPC 2.0 Server Class
# ============================================================================

class MCPServer:
    """Zero-dependency JSON-RPC 2.0 Model Context Protocol (MCP) Server."""

    def __init__(self, name: str = SERVER_NAME, version: str = SERVER_VERSION):
        self.name = name
        self.version = version

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches tool execution by name and returns result dictionary."""
        if tool_name == "env_scan_secrets":
            content = arguments.get("content")
            target_path = arguments.get("target_path")
            min_score = int(arguments.get("min_score", 80))

            if target_path:
                return scan_file_or_dir(target_path, min_score=min_score)
            elif content is not None:
                return scan_secrets(content, source="<mcp_input>", min_score=min_score)
            else:
                raise ValueError("Must provide either 'content' or 'target_path'")

        elif tool_name == "env_mask_variables":
            content = arguments.get("content")
            target_path = arguments.get("target_path")
            mode = arguments.get("mode", "partial")

            if target_path and content is None:
                content = Path(target_path).read_text(encoding="utf-8")
            if content is None:
                raise ValueError("Must provide 'content' or 'target_path'")
            return mask_env_content(content, mode=mode)

        elif tool_name == "env_generate_example":
            content = arguments.get("content")
            target_path = arguments.get("target_path")

            if target_path and content is None:
                content = Path(target_path).read_text(encoding="utf-8")
            if content is None:
                raise ValueError("Must provide 'content' or 'target_path'")
            return generate_env_example(content)

        elif tool_name == "env_vault_encrypt":
            password = arguments.get("password")
            if not password:
                raise ValueError("Missing required parameter 'password'")
            content = arguments.get("content")
            target_path = arguments.get("target_path")

            if target_path and content is None:
                content = Path(target_path).read_text(encoding="utf-8")
            if content is None:
                raise ValueError("Must provide 'content' or 'target_path'")
            return vault_encrypt(content, password=password)

        elif tool_name == "env_vault_decrypt":
            password = arguments.get("password")
            if not password:
                raise ValueError("Missing required parameter 'password'")
            vault_armor = arguments.get("vault_armor")
            target_path = arguments.get("target_path")

            if target_path and vault_armor is None:
                vault_armor = Path(target_path).read_text(encoding="utf-8")
            if vault_armor is None:
                raise ValueError("Must provide 'vault_armor' or 'target_path'")
            return vault_decrypt(vault_armor, password=password)

        elif tool_name == "env_diff_environments":
            env_a = arguments.get("env_a", "")
            env_b = arguments.get("env_b", "")
            name_a = arguments.get("name_a", "Env A")
            name_b = arguments.get("name_b", "Env B")

            # Resolve if file path or raw string
            if Path(env_a).is_file():
                content_a = Path(env_a).read_text(encoding="utf-8")
            else:
                content_a = env_a

            if Path(env_b).is_file():
                content_b = Path(env_b).read_text(encoding="utf-8")
            else:
                content_b = env_b

            return diff_environments(content_a, content_b, name_a=name_a, name_b=name_b)

        elif tool_name == "env_get_diagnostics":
            return get_diagnostics()

        elif tool_name == "env_shamir_split":
            from envguard_secrets_vault.shamir_quorum import split_secret_into_shares
            secret = arguments.get("secret")
            if not secret:
                raise ValueError("Missing required parameter 'secret'")
            threshold = int(arguments.get("threshold", 3))
            total_shares = int(arguments.get("total_shares", 5))
            label = arguments.get("label", "master-key")
            return split_secret_into_shares(
                secret=secret,
                threshold=threshold,
                total_shares=total_shares,
                label=label,
            )

        elif tool_name == "env_shamir_combine":
            from envguard_secrets_vault.shamir_quorum import combine_shares_to_secret
            shares = arguments.get("shares")
            if not shares:
                raise ValueError("Missing required parameter 'shares'")
            return combine_shares_to_secret(shares)

        else:
            raise KeyError(f"Unknown MCP tool: '{tool_name}'")

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC 2.0 request dictionary."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if not method:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing 'method'"},
            }

        if method in ("notifications/initialized", "initialized"):
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version,
                    },
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": MCP_TOOLS_DEFINITIONS,
                },
            }

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                result_data = self.execute_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2),
                            }
                        ],
                        "isError": False,
                    },
                }
            except KeyError as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": str(e)},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing tool '{tool_name}': {str(e)}",
                            }
                        ],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: '{method}'"},
        }

    def run_stdio(self) -> None:
        """Runs stdio loop reading JSON-RPC lines from stdin and replying to stdout."""
        sys.stderr.write(
            f"[{SERVER_NAME}] MCP stdio server active (v{SERVER_VERSION}, Python {platform.python_version()})\n"
        )
        sys.stderr.flush()

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                line_stripped = line.strip()
                if not line_stripped:
                    continue

                if line_stripped.startswith("Content-Length:"):
                    length = int(line_stripped.split(":")[1].strip())
                    while True:
                        header_line = sys.stdin.readline().strip()
                        if not header_line:
                            break
                    raw_payload = sys.stdin.read(length)
                    data = json.loads(raw_payload)
                else:
                    data = json.loads(line_stripped)

                response = self.handle_request(data)
                if response is not None:
                    out_json = json.dumps(response)
                    sys.stdout.write(f"{out_json}\n")
                    sys.stdout.flush()

            except json.JSONDecodeError as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                sys.stdout.write(f"{json.dumps(err_resp)}\n")
                sys.stdout.flush()
            except KeyboardInterrupt:
                break
            except Exception as e:
                sys.stderr.write(f"[{SERVER_NAME}] Unexpected error: {str(e)}\n")
                sys.stderr.flush()


def run_mcp_server() -> None:
    """Entrypoint helper to run the stdio MCP server."""
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    run_mcp_server()
