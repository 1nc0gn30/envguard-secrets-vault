"""EnvGuard Secrets Vault - CI/CD Security Gate Module.

Enforces automated zero-trust secrets scanning and security gates in CI/CD
pipelines, generating GitHub Actions annotations, ASCII tables, and JSON reports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from envguard_secrets_vault.mcp_server import scan_file_or_dir, scan_secrets


def run_security_check(
    target_path: str,
    min_score: int = 80,
    fail_on_critical: bool = True,
    output_format: str = "text",
) -> Tuple[bool, Dict[str, Any], str]:
    """Executes an automated secrets security audit against CI policy thresholds.

    Args:
        target_path: Path to .env file, config file, or directory.
        min_score: Minimum allowable score (0-100) to pass CI (default: 80).
        fail_on_critical: If True, any CRITICAL finding fails CI regardless of score.
        output_format: "text", "json", "github", or "markdown".

    Returns:
        Tuple[bool, Dict[str, Any], str]: (passed, result_dict, formatted_output)
    """
    path = Path(target_path)
    if not path.exists():
        # If target doesn't exist, treat as raw text content if not looking like a file path
        if "\n" in target_path or "=" in target_path:
            audit_result = scan_secrets(target_path, source="<raw_input>", min_score=min_score)
        else:
            raise FileNotFoundError(f"Target path not found: {target_path}")
    else:
        audit_result = scan_file_or_dir(str(path), min_score=min_score)

    score = audit_result["score"]
    metrics = audit_result["metrics"]
    crit_count = metrics.get("critical_count", 0)

    score_passed = score >= min_score
    critical_passed = not (fail_on_critical and crit_count > 0)
    passed = score_passed and critical_passed

    audit_result["ci_gate"] = {
        "passed": passed,
        "min_score": min_score,
        "fail_on_critical": fail_on_critical,
        "score_passed": score_passed,
        "critical_passed": critical_passed,
        "has_critical": crit_count > 0,
        "critical_count": crit_count,
    }

    fmt = output_format.lower().strip()
    if fmt == "json":
        formatted_output = json.dumps(audit_result, indent=2)
    elif fmt == "github":
        formatted_output = _format_github_actions_output(audit_result, passed, min_score, fail_on_critical)
    elif fmt == "markdown":
        formatted_output = _format_markdown_output(audit_result, passed, min_score)
    else:  # "text"
        formatted_output = _format_ascii_table_output(audit_result, passed, min_score, fail_on_critical)

    # Append to GITHUB_STEP_SUMMARY if active in GitHub Actions
    step_summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_file and Path(step_summary_file).parent.exists():
        try:
            with open(step_summary_file, "a", encoding="utf-8") as f:
                f.write(_format_markdown_output(audit_result, passed, min_score) + "\n")
        except Exception:
            pass

    return passed, audit_result, formatted_output


# ============================================================================
# Output Formatters
# ============================================================================

def _format_ascii_table_output(
    res: Dict[str, Any],
    passed: bool,
    min_score: int,
    fail_on_critical: bool,
) -> str:
    crit = res["metrics"]["critical_count"]
    high = res["metrics"]["high_count"]
    med = res["metrics"]["medium_count"]
    low = res["metrics"]["low_count"]
    total = res["metrics"]["total_findings"]

    status_str = "PASSED" if passed else "FAILED"
    status_icon = "[PASS]" if passed else "[FAIL]"

    lines = [
        "=" * 82,
        "                   ENVGUARD SECRETS VAULT - CI/CD GATEWAY",
        "=" * 82,
        f" Target:         {res.get('source', 'Unknown')}",
        f" Security Score: {res.get('score', 0)} / 100   (Grade: {res.get('grade', 'N/A')})",
        f" Gate Status:    {status_icon} {status_str} (Required: >={min_score}, No Critical: {fail_on_critical})",
        f" Breakdown:      {crit} Critical | {high} High | {med} Medium | {low} Low (Total: {total})",
        "-" * 82,
    ]

    findings = res.get("findings", [])
    if not findings:
        lines.append("  [+] No secrets or security risks detected! (100% Clean)")
    else:
        lines.append(
            f" {'ID':<10} | {'SEVERITY':<10} | {'DEDUCT':<6} | {'LINE':<5} | {'SECRET TYPE':<24} | {'SAMPLE'}"
        )
        lines.append("-" * 82)
        for f in findings:
            name_trunc = f["name"][:24]
            sample = f.get("matched_sample", "")[:18]
            lines.append(
                f" {f['id']:<10} | {f['severity']:<10} | -{f['deduction']:<5} | {f.get('line', 1):<5} | {name_trunc:<24} | {sample}"
            )

    lines.append("=" * 82)
    if not passed:
        lines.append(" [!] Action Required: Run 'envguard mask' or 'envguard encrypt' to protect leaked secrets.")
    return "\n".join(lines)


def _format_github_actions_output(
    res: Dict[str, Any],
    passed: bool,
    min_score: int,
    fail_on_critical: bool,
) -> str:
    lines = []
    target_file = res.get("source", ".env")
    if target_file.startswith("<"):
        target_file = ".env"

    for f in res.get("findings", []):
        file_path = f.get("file", target_file)
        line_num = f.get("line", 1)
        msg = f"{f['name']}: {f['description']} (Remediation: {f['remediation']})"
        sev = f["severity"]
        if sev in ("CRITICAL", "HIGH"):
            lines.append(f"::error file={file_path},line={line_num},title={f['id']}::{msg}")
        elif sev == "MEDIUM":
            lines.append(f"::warning file={file_path},line={line_num},title={f['id']}::{msg}")
        else:
            lines.append(f"::notice file={file_path},line={line_num},title={f['id']}::{msg}")

    status_str = "PASSED" if passed else "FAILED"
    lines.append(
        f"::notice title=EnvGuard Security Gate {status_str}::Score: {res['score']}/100 ({res['grade']}) - "
        f"{res['metrics']['critical_count']} Critical, {res['metrics']['high_count']} High, {res['metrics']['medium_count']} Medium"
    )

    lines.append("")
    lines.append(_format_markdown_output(res, passed, min_score))
    return "\n".join(lines)


def _format_markdown_output(res: Dict[str, Any], passed: bool, min_score: int) -> str:
    status_badge = "✅ **PASSED**" if passed else "❌ **FAILED**"
    metrics = res.get("metrics", {})
    lines = [
        "## 🛡️ EnvGuard Secrets Vault CI Gate Summary",
        "",
        f"- **Target:** `{res.get('source', 'Unknown')}`",
        f"- **Security Score:** **{res.get('score', 0)}/100** (Grade: `{res.get('grade', 'N/A')}`)",
        f"- **CI Threshold:** Minimum **{min_score}** | Status: {status_badge}",
        f"- **Findings:** 🔴 {metrics.get('critical_count', 0)} Critical | 🟠 {metrics.get('high_count', 0)} High | 🟡 {metrics.get('medium_count', 0)} Medium | 🔵 {metrics.get('low_count', 0)} Low",
        "",
    ]

    findings = res.get("findings", [])
    if findings:
        lines.extend([
            "| Severity | Finding ID | Line | Secret Type | Deduction | Remediation |",
            "| :---: | :--- | :---: | :--- | :---: | :--- |",
        ])
        for f in findings:
            sev = f["severity"]
            sev_icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🔵"))
            lines.append(
                f"| {sev_icon} **{sev}** | `{f['id']}` | `{f.get('line', 1)}` | {f['name']} | `-{f['deduction']}` | {f['remediation']} |"
            )
    else:
        lines.append("🎉 **No secrets or credentials found. Environment configuration meets 100/100 A+ standard.**")

    return "\n".join(lines)


# ============================================================================
# CLI Entry Point
# ============================================================================

def main(args: Optional[List[str]] = None) -> int:
    """CLI entrypoint for envguard CI security check."""
    parser = argparse.ArgumentParser(
        prog="envguard-check",
        description="Zero-Trust Secrets & Configuration CI Security Gate",
    )
    parser.add_argument("target", help="File (.env) or directory to audit for secrets")
    parser.add_argument("--min-score", type=int, default=80, help="Minimum score to pass CI (default: 80)")
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=True,
        help="Fail if any critical vulnerabilities/secrets found (default: True)",
    )
    parser.add_argument(
        "--no-fail-on-critical",
        action="store_false",
        dest="fail_on_critical",
        help="Do not fail solely on critical findings",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "github", "markdown"],
        default="text",
        help="Output report format",
    )
    parser.add_argument("--output", "-o", type=str, help="Save report output to file")

    parsed = parser.parse_args(args)

    passed, result_dict, output_str = run_security_check(
        target_path=parsed.target,
        min_score=parsed.min_score,
        fail_on_critical=parsed.fail_on_critical,
        output_format=parsed.format,
    )

    print(output_str)

    if parsed.output:
        out_path = Path(parsed.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
