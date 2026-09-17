"""Normalized Shannon entropy analysis and custom secret rule compiler.

Calculates alphabet-aware normalized entropy H(X) / log2(|Sigma|) to accurately
flag high-randomness tokens across Hex, Base64, Base58, and Alphanumeric strings.
Provides custom rule compilation with regex validation and false-positive allowlisting.

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set


class AlphabetType(str, Enum):
    HEX = "hex"
    BASE64 = "base64"
    BASE58 = "base58"
    ALPHANUMERIC = "alphanumeric"
    PRINTABLE_ASCII = "printable_ascii"


HEX_CHARS = set("0123456789abcdefABCDEF")
BASE58_CHARS = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=")
ALPHANUMERIC_CHARS = set(string.ascii_letters + string.digits)


def detect_alphabet(text: str) -> AlphabetType:
    """Detect the minimal alphabet category spanning the characters in text."""
    if not text:
        return AlphabetType.PRINTABLE_ASCII
    chars = set(text)
    if chars.issubset(HEX_CHARS):
        return AlphabetType.HEX
    if chars.issubset(BASE58_CHARS):
        return AlphabetType.BASE58
    if chars.issubset(ALPHANUMERIC_CHARS):
        return AlphabetType.ALPHANUMERIC
    if chars.issubset(BASE64_CHARS):
        return AlphabetType.BASE64
    return AlphabetType.PRINTABLE_ASCII


def get_alphabet_size(alphabet: AlphabetType) -> int:
    """Return theoretical cardinality of the alphabet."""
    if alphabet == AlphabetType.HEX:
        return 16
    if alphabet == AlphabetType.BASE58:
        return 58
    if alphabet == AlphabetType.BASE64:
        return 64
    if alphabet == AlphabetType.ALPHANUMERIC:
        return 62
    return 95


@dataclass
class EntropyProfile:
    """Detailed entropy evaluation across alphabet dimensions."""

    text_length: int
    raw_entropy: float
    alphabet: AlphabetType
    alphabet_size: int
    max_possible_entropy: float
    normalized_entropy: float  # 0.0 to 1.0 (relative to alphabet theoretical max)
    is_likely_secret: bool
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text_length": self.text_length,
            "raw_entropy": self.raw_entropy,
            "alphabet": self.alphabet.value,
            "alphabet_size": self.alphabet_size,
            "max_possible_entropy": self.max_possible_entropy,
            "normalized_entropy": self.normalized_entropy,
            "is_likely_secret": self.is_likely_secret,
            "confidence": self.confidence,
        }


def analyze_entropy_profile(text: str) -> EntropyProfile:
    """Analyze character distribution and calculate normalized entropy.

    Formula: Normalized H = - sum(p_i * log2(p_i)) / log2(|Alphabet|)
    """
    if not text:
        return EntropyProfile(
            text_length=0,
            raw_entropy=0.0,
            alphabet=AlphabetType.PRINTABLE_ASCII,
            alphabet_size=95,
            max_possible_entropy=math.log2(95),
            normalized_entropy=0.0,
            is_likely_secret=False,
            confidence=0.0,
        )

    length = len(text)
    counts = Counter(text)
    raw_entropy = 0.0
    for count in counts.values():
        p = count / length
        raw_entropy -= p * math.log2(p)

    alphabet = detect_alphabet(text)
    sigma = get_alphabet_size(alphabet)
    max_entropy = math.log2(sigma)

    normalized = raw_entropy / max_entropy if max_entropy > 0 else 0.0
    normalized = min(1.0, max(0.0, round(normalized, 4)))

    # Secrets heuristic: >= 16 chars with normalized entropy > 0.70
    is_secret = length >= 16 and normalized >= 0.72
    confidence = min(1.0, round(normalized * min(1.0, length / 24.0), 2))

    return EntropyProfile(
        text_length=length,
        raw_entropy=round(raw_entropy, 4),
        alphabet=alphabet,
        alphabet_size=sigma,
        max_possible_entropy=round(max_entropy, 4),
        normalized_entropy=normalized,
        is_likely_secret=is_secret,
        confidence=confidence,
    )


@dataclass
class CompiledCustomRule:
    """Compiled custom secret rule."""

    rule_id: str
    name: str
    pattern: re.Pattern
    severity: str
    min_normalized_entropy: float = 0.0
    allowlist: Set[str] = field(default_factory=set)


def compile_custom_rules(rule_dicts: Sequence[Dict[str, Any]]) -> List[CompiledCustomRule]:
    """Compile custom dictionary-based rules into regex matching objects.

    Args:
        rule_dicts: List of dicts containing 'rule_id', 'name', 'regex' or 'pattern',
                    optional 'severity', 'min_entropy', 'allowlist'.

    Returns:
        List of CompiledCustomRule instances.
    """
    compiled: List[CompiledCustomRule] = []
    for r in rule_dicts:
        rule_id = str(r.get("rule_id", r.get("id", "custom-rule")))
        name = str(r.get("name", rule_id))
        raw_pattern = str(r.get("pattern", r.get("regex", "")))
        if not raw_pattern:
            continue

        try:
            pattern = re.compile(raw_pattern)
        except re.error:
            continue

        severity = str(r.get("severity", "HIGH")).upper()
        min_ent = float(r.get("min_normalized_entropy", r.get("min_entropy", 0.0)))
        allowlist = set(r.get("allowlist", []))

        compiled.append(
            CompiledCustomRule(
                rule_id=rule_id,
                name=name,
                pattern=pattern,
                severity=severity,
                min_normalized_entropy=min_ent,
                allowlist=allowlist,
            )
        )
    return compiled


def scan_with_custom_rules(
    text: str,
    rules: Sequence[CompiledCustomRule],
) -> List[Dict[str, Any]]:
    """Execute compiled custom rules against raw text or env file content."""
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()

    for line_num, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue

        for rule in rules:
            for match in rule.pattern.finditer(line):
                matched_str = match.group(0)
                if matched_str in rule.allowlist:
                    continue

                if rule.min_normalized_entropy > 0.0:
                    profile = analyze_entropy_profile(matched_str)
                    if profile.normalized_entropy < rule.min_normalized_entropy:
                        continue

                findings.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "line_number": line_num,
                    "matched_snippet": matched_str[:4] + "..." + matched_str[-4:] if len(matched_str) > 8 else "***",
                    "length": len(matched_str),
                })
    return findings
