#!/usr/bin/env python3
"""EnvGuard Secrets Vault - Command-Line Interface (CLI).

Subcommands:
  serve      - Start Secrets Studio UI Server (Default port: 8087)
  scan       - Audit a .env file or directory for leaked API keys, tokens & high entropy
  mask       - Redact sensitive credentials in .env (partial or full masking)
  example    - Auto-generate sanitized .env.example with descriptive placeholders
  encrypt    - Hardened vault encryption with PBKDF2-HMAC-SHA256 & AES-256-CTR
  decrypt    - Restore plaintext .env from armored vault using master password
  diff       - Compare two .env files for missing keys, type mismatches & value diffs
  check      - CI/CD security gate with configurable score threshold and exit codes
  mcp        - Start stdio JSON-RPC 2.0 MCP server or display client configs
  platform   - Display multi-OS system info, crypto specs, and detector patterns
  test       - Run built-in engine verification test suite
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from envguard_secrets_vault.ci_gate import run_security_check
from envguard_secrets_vault.mcp_server import (
    SERVER_NAME,
    SERVER_VERSION,
    calculate_shannon_entropy,
    diff_environments,
    generate_env_example,
    generate_mcp_client_config,
    get_diagnostics,
    mask_env_content,
    run_mcp_server,
    scan_file_or_dir,
    scan_secrets,
    vault_decrypt,
    vault_encrypt,
)
from envguard_secrets_vault.ui_server import start_server

# ============================================================================
# ANSI Color Helpers
# ============================================================================

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def bold(text: str) -> str:
    return _c(text, "1")


def cyan(text: str) -> str:
    return _c(text, "36")


def green(text: str) -> str:
    return _c(text, "32")


def yellow(text: str) -> str:
    return _c(text, "33")


def red(text: str) -> str:
    return _c(text, "31")


def magenta(text: str) -> str:
    return _c(text, "35")


def gray(text: str) -> str:
    return _c(text, "90")


def print_banner() -> None:
    """Prints the EnvGuard CLI header banner."""
    print(cyan(bold(f"🛡️  EnvGuard Secrets Vault v{SERVER_VERSION}")) + gray(" | Zero-Dependency SecOps & MCP Server"))
    print(gray("─" * 78))


# ============================================================================
# Internal Engine Test Suite (envguard test)
# ============================================================================

def run_internal_tests() -> int:
    """Executes the built-in test verification suite."""
    print_banner()
    print(bold("🧪 Running EnvGuard Secrets Vault Built-In Verification Suite...\n"))
    passes = 0
    failures = 0

    def test(name: str, fn) -> None:
        nonlocal passes, failures
        try:
            fn()
            print(f"  {green('✔ PASS')} {name}")
            passes += 1
        except Exception as e:
            print(f"  {red('✖ FAIL')} {name}: {str(e)}")
            failures += 1

    # 1. Shannon Entropy
    def test_entropy():
        low = calculate_shannon_entropy("localhost")
        high = calculate_shannon_entropy("8f9a2b1c4e5d6f7a0b1c2d3e4f5a6b7c")
        assert low < 3.2, f"Expected low entropy, got {low}"
        assert high >= 3.8, f"Expected high entropy, got {high}"

    test("Shannon Entropy Calculation", test_entropy)

    # 2. Secret Scanner
    def test_scanner():
        sample = (
            "PORT=3000\n"
            "OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        res = scan_secrets(sample)
        assert res["score"] < 80
        assert res["metrics"]["critical_count"] >= 2

    test("Secret Scanner Detection (OpenAI & AWS Keys)", test_scanner)

    # 3. Masker
    def test_masker():
        sample = "PORT=3000\nOPENAI_KEY=sk-1234567890abcdef1234567890\n"
        res = mask_env_content(sample, mode="partial")
        assert "PORT=3000" in res["masked_content"]
        assert "****" in res["masked_content"]

    test("Safe Variable Masking", test_masker)

    # 4. Example Generator
    def test_example_gen():
        sample = "PORT=8080\nDATABASE_URL=postgres://user:pass@localhost:5432/app\n"
        res = generate_env_example(sample)
        assert "your-jwt" not in res["example_content"]
        assert "postgresql://user:password" in res["example_content"]

    test("Sanitized .env.example Generation", test_example_gen)

    # 5. Vault Encrypt & Decrypt Round-Trip
    def test_crypto():
        raw = "SUPER_SECRET_TOKEN=xyz9876543210\n"
        pwd = "TestMasterPassword!99"
        enc = vault_encrypt(raw, pwd)
        assert "-----BEGIN ENVGUARD ENCRYPTED VAULT-----" in enc["vault_armor"]
        dec = vault_decrypt(enc["vault_armor"], pwd)
        assert dec["decrypted_content"] == raw

    test("Pure Python AES-256-CTR Vault Cryptography", test_crypto)

    # 6. Environment Differ
    def test_differ():
        env1 = "PORT=3000\nDEBUG=true\n"
        env2 = "PORT=8080\nNODE_ENV=production\n"
        res = diff_environments(env1, env2)
        assert res["total_keys_a"] == 2
        assert res["total_keys_b"] == 2
        assert "NODE_ENV" in res["keys_only_in_b"]

    test("Environment Differ & Type Inference", test_differ)

    print("\n" + gray("─" * 78))
    print(f"Summary: {green(f'{passes} passed')}, {red(f'{failures} failed') if failures else '0 failed'}")
    return 0 if failures == 0 else 1


# ============================================================================
# CLI Command Implementations
# ============================================================================

def cmd_scan(args: argparse.Namespace) -> int:
    """Audits secrets in target file or directory."""
    target = args.target
    min_score = args.min_score
    try:
        res = scan_file_or_dir(target, min_score=min_score)
    except Exception as e:
        print(red(f"Scan Error: {str(e)}"))
        return 1

    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res["passed"] else 1

    print_banner()
    score = res["score"]
    grade = res["grade"]
    score_color = green if score >= 80 else (yellow if score >= 60 else red)
    passed_badge = green("[PASS]") if res["passed"] else red("[FAIL]")

    print(f"Target:       {bold(res['source'])}")
    print(f"Audit Score:  {score_color(bold(f'{score}/100'))} (Grade: {score_color(grade)})")
    print(f"Status:       {passed_badge} (Minimum required: {min_score})")
    print(f"Findings:     {res['metrics']['critical_count']} Critical, {res['metrics']['high_count']} High, {res['metrics']['medium_count']} Medium, {res['metrics']['low_count']} Low")
    print(gray("─" * 78))

    findings = res["findings"]
    if not findings:
        print(green("  ✔ No secrets or high-entropy credentials detected. 100% clean!"))
    else:
        print(f" {'ID':<10} | {'SEVERITY':<10} | {'DEDUCT':<6} | {'LINE':<5} | {'SECRET TYPE':<24} | {'SAMPLE'}")
        print(gray("─" * 78))
        for f in findings:
            sev = f["severity"]
            sev_c = red if sev in ("CRITICAL", "HIGH") else (yellow if sev == "MEDIUM" else cyan)
            name_t = f["name"][:24]
            sample_t = f.get("matched_sample", "")[:18]
            print(f" {f['id']:<10} | {sev_c(f'{sev:<10}')} | -{f['deduction']:<5} | {f.get('line', 1):<5} | {name_t:<24} | {sample_t}")

    print(gray("─" * 78))
    return 0 if res["passed"] else 1


def cmd_mask(args: argparse.Namespace) -> int:
    """Masks sensitive credentials in .env file."""
    p = Path(args.file)
    if not p.is_file():
        print(red(f"Error: File not found: {args.file}"))
        return 1

    content = p.read_text(encoding="utf-8")
    mode = getattr(args, "mode", "partial")
    res = mask_env_content(content, mode=mode)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(res["masked_content"], encoding="utf-8")
        print(green(f"✔ Masked configuration written to: {args.output} ({res['masked_variables_count']} variables redacted)"))
    else:
        print(res["masked_content"])
    return 0


def cmd_example(args: argparse.Namespace) -> int:
    """Generates sanitized .env.example template from live .env."""
    p = Path(args.file)
    if not p.is_file():
        print(red(f"Error: File not found: {args.file}"))
        return 1

    content = p.read_text(encoding="utf-8")
    res = generate_env_example(content)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(res["example_content"], encoding="utf-8")
        print(green(f"✔ Sanitized example template written to: {args.output} ({res['total_variables']} variables)"))
    else:
        print(res["example_content"])
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypts .env into an armored vault envelope."""
    p = Path(args.file)
    if not p.is_file():
        print(red(f"Error: File not found: {args.file}"))
        return 1

    content = p.read_text(encoding="utf-8")
    password = args.password
    if not password:
        password = getpass.getpass("Enter master encryption password: ")
        confirm = getpass.getpass("Confirm master encryption password: ")
        if password != confirm:
            print(red("Error: Passwords do not match."))
            return 1

    try:
        res = vault_encrypt(content, password)
    except Exception as e:
        print(red(f"Encryption failed: {str(e)}"))
        return 1

    out_file = args.out or f"{args.file}.enc"
    Path(out_file).write_text(res["vault_armor"], encoding="utf-8")
    print(green(f"✔ Vault successfully encrypted to: {out_file} (PBKDF2-HMAC-SHA256 + AES-256-CTR)"))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypts armored vault envelope back to plaintext .env."""
    p = Path(args.file)
    if not p.is_file():
        print(red(f"Error: Vault file not found: {args.file}"))
        return 1

    vault_armor = p.read_text(encoding="utf-8")
    password = args.password
    if not password:
        password = getpass.getpass("Enter master decryption password: ")

    try:
        res = vault_decrypt(vault_armor, password)
    except Exception as e:
        print(red(f"Decryption failed: {str(e)}"))
        return 1

    if args.out:
        Path(args.out).write_text(res["decrypted_content"], encoding="utf-8")
        print(green(f"✔ Decrypted plaintext .env written to: {args.out}"))
    else:
        print(res["decrypted_content"])
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Compares two .env files."""
    p_a = Path(args.file_a)
    p_b = Path(args.file_b)

    if not p_a.is_file() or not p_b.is_file():
        print(red("Error: Both input files must exist."))
        return 1

    content_a = p_a.read_text(encoding="utf-8")
    content_b = p_b.read_text(encoding="utf-8")

    res = diff_environments(content_a, content_b, name_a=str(p_a), name_b=str(p_b))

    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
        return 0

    print_banner()
    print(f"Comparing: {bold(res['name_a'])} vs {bold(res['name_b'])}")
    print(f"Total Keys: Env A: {res['total_keys_a']} | Env B: {res['total_keys_b']} | Identical: {res['identical_values_count']}")
    print(gray("─" * 78))

    for d in res["differences"]:
        status = d["status"]
        k = d["key"]
        if status == "missing_in_b":
            print(f"  {red('-')} {bold(k)}: only in Env A ({d['type_a']})")
        elif status == "missing_in_a":
            print(f"  {green('+')} {bold(k)}: only in Env B ({d['type_b']})")
        else:
            mismatch_tag = yellow("[TYPE MISMATCH]") if d.get("type_mismatch") else ""
            print(f"  {yellow('~')} {bold(k)} {mismatch_tag}")
            print(f"      Env A ({d['type_a']}): {d['val_a']}")
            print(f"      Env B ({d['type_b']}): {d['val_b']}")

    print(gray("─" * 78))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Runs CI/CD pre-commit security check."""
    passed, result_dict, output_str = run_security_check(
        target_path=args.path,
        min_score=args.min_score,
        fail_on_critical=getattr(args, "fail_on_critical", True),
        output_format=getattr(args, "format", "text"),
    )
    print(output_str)
    return 0 if passed else 1


def cmd_mcp(args: argparse.Namespace) -> int:
    """Runs MCP stdio server or prints client config."""
    config_type = getattr(args, "config", None)
    if config_type:
        configs = generate_mcp_client_config(config_type)
        print(json.dumps(configs, indent=2))
        return 0

    run_mcp_server()
    return 0


def cmd_platform(args: argparse.Namespace) -> int:
    """Displays multi-OS diagnostics."""
    print_banner()
    diag = get_diagnostics()
    print(bold("System Runtime:"))
    for k, v in diag["platform"].items():
        print(f"  {cyan(k)}: {v}")

    print(bold("\nCrypto Capabilities:"))
    for k, v in diag["crypto_suite"].items():
        print(f"  {cyan(k)}: {v}")

    print(bold(f"\nSupported Secret Detectors ({diag['total_detectors']}):"))
    for d in diag["detectors"]:
        print(f"  [{d['id']}] {d['name']} ({d['severity']}) - {d['category']}")

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Starts Secrets Studio (design influenced by Material 3)."""
    port = getattr(args, "port", 8087)
    host = getattr(args, "host", "0.0.0.0")
    print_banner()
    start_server(host=host, port=port)
    return 0


# ============================================================================
# Main Entry Point & Argument Parsing
# ============================================================================

def main(args: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="EnvGuard Secrets Vault - Zero-Trust .env Auditor, Encryptor & MCP Server",
    )
    parser.add_argument("--version", "-v", action="version", version=f"envguard {SERVER_VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start Secrets Studio Web UI (design influenced by Material 3)")
    p_serve.add_argument("--port", type=int, default=8087, help="HTTP port (default: 8087)")
    p_serve.add_argument("--host", type=str, default="0.0.0.0", help="HTTP host (default: 0.0.0.0)")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan .env file or directory for secrets")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--json", action="store_true", help="Output JSON report")
    p_scan.add_argument("--min-score", type=int, default=80, help="Minimum passing score (default: 80)")

    # mask
    p_mask = subparsers.add_parser("mask", help="Mask sensitive variables in .env")
    p_mask.add_argument("file", help="Input .env file")
    p_mask.add_argument("--output", "-o", help="Output masked file")
    p_mask.add_argument("--mode", choices=["partial", "full"], default="partial", help="Masking mode")

    # example
    p_ex = subparsers.add_parser("example", help="Generate sanitized .env.example")
    p_ex.add_argument("file", help="Input .env file")
    p_ex.add_argument("--output", "-o", help="Output .env.example file")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt .env into armored vault")
    p_enc.add_argument("file", help="Input .env file")
    p_enc.add_argument("--password", "-p", help="Master encryption password")
    p_enc.add_argument("--out", "-o", help="Output vault file (.env.enc)")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt armored vault back to plaintext")
    p_dec.add_argument("file", help="Input vault file (.env.enc)")
    p_dec.add_argument("--password", "-p", help="Master decryption password")
    p_dec.add_argument("--out", "-o", help="Output plaintext .env file")

    # diff
    p_diff = subparsers.add_parser("diff", help="Compare two .env files")
    p_diff.add_argument("file_a", help="First .env file")
    p_diff.add_argument("file_b", help="Second .env file")
    p_diff.add_argument("--json", action="store_true", help="Output diff as JSON")

    # check
    p_chk = subparsers.add_parser("check", help="CI/CD pre-commit security check")
    p_chk.add_argument("path", help="File or directory path to check")
    p_chk.add_argument("--min-score", type=int, default=85, help="Minimum score to pass CI (default: 85)")
    p_chk.add_argument("--format", choices=["text", "github", "json", "markdown"], default="text")

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run stdio MCP server or display client configs")
    p_mcp.add_argument("--config", choices=["claude", "cursor", "cline", "zed", "all"], help="Display MCP client config")

    # platform
    subparsers.add_parser("platform", help="Display system runtime and crypto capabilities")

    # test
    subparsers.add_parser("test", help="Run built-in engine verification test suite")

    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    if parsed.command == "serve":
        return cmd_serve(parsed)
    elif parsed.command == "scan":
        return cmd_scan(parsed)
    elif parsed.command == "mask":
        return cmd_mask(parsed)
    elif parsed.command == "example":
        return cmd_example(parsed)
    elif parsed.command == "encrypt":
        return cmd_encrypt(parsed)
    elif parsed.command == "decrypt":
        return cmd_decrypt(parsed)
    elif parsed.command == "diff":
        return cmd_diff(parsed)
    elif parsed.command == "check":
        return cmd_check(parsed)
    elif parsed.command == "mcp":
        return cmd_mcp(parsed)
    elif parsed.command == "platform":
        return cmd_platform(parsed)
    elif parsed.command == "test":
        return run_internal_tests()

    return 0


if __name__ == "__main__":
    sys.exit(main())
