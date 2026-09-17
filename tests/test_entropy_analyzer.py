"""Tests for normalized Shannon entropy analysis and custom rule compiler."""

from envguard_secrets_vault.entropy_analyzer import (
    AlphabetType,
    EntropyProfile,
    analyze_entropy_profile,
    compile_custom_rules,
    detect_alphabet,
    scan_with_custom_rules,
)


def test_detect_alphabet():
    assert detect_alphabet("0123456789abcdefABCDEF") == AlphabetType.HEX
    assert detect_alphabet("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == AlphabetType.BASE58
    assert detect_alphabet("Abc0123lOxyz") == AlphabetType.ALPHANUMERIC
    assert detect_alphabet("aGVsbG8gd29ybGQ=") == AlphabetType.BASE64
    assert detect_alphabet("hello world! @#$") == AlphabetType.PRINTABLE_ASCII


def test_analyze_entropy_profile_empty():
    profile = analyze_entropy_profile("")
    assert isinstance(profile, EntropyProfile)
    assert profile.text_length == 0
    assert profile.raw_entropy == 0.0
    assert not profile.is_likely_secret


def test_analyze_entropy_high_randomness():
    # 32-character random hex token
    high_rand_hex = "4f7a9c2b8e1d5a3f0e8b6c4a2d1f9e7a"
    profile = analyze_entropy_profile(high_rand_hex)
    assert profile.alphabet == AlphabetType.HEX
    assert profile.alphabet_size == 16
    assert profile.normalized_entropy >= 0.85
    assert profile.is_likely_secret
    assert profile.confidence > 0.80

    # Low randomness repeated string
    repeated = "aaaaaaaaaaaaaaaa"
    profile_low = analyze_entropy_profile(repeated)
    assert profile_low.raw_entropy == 0.0
    assert profile_low.normalized_entropy == 0.0
    assert not profile_low.is_likely_secret


def test_custom_rule_compiler_and_scanner():
    rules_def = [
        {
            "rule_id": "INTERNAL_CORP_TOKEN",
            "name": "Internal Corp Access Key",
            "regex": r"corp_[A-Za-z0-9]{16,}",
            "severity": "CRITICAL",
            "min_normalized_entropy": 0.60,
            "allowlist": ["corp_EXAMPLE_DUMMY_KEY_0000"],
        }
    ]
    compiled = compile_custom_rules(rules_def)
    assert len(compiled) == 1
    assert compiled[0].rule_id == "INTERNAL_CORP_TOKEN"

    # Test scanning text
    text = """
    # Sample env
    CORP_KEY=corp_9fa8b7c6d5e4f3a2b1
    DUMMY_KEY=corp_EXAMPLE_DUMMY_KEY_0000
    SAFE_VAL=hello_world
    """
    findings = scan_with_custom_rules(text, compiled)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "INTERNAL_CORP_TOKEN"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["line_number"] == 3
