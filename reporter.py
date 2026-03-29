"""
reporter.py - Generates clean Markdown reports for each vulnerability fix.
Includes: vulnerability details, fix summary, before/after code, OWASP reference,
test results, and patch location.
"""
import os
import datetime
from typing import Dict, Any, List


# OWASP Top 10 mapping
OWASP_MAPPING = {
    'sql_injection': 'A03:2021 – Injection',
    'command_injection': 'A03:2021 – Injection',
    'ldap_injection': 'A03:2021 – Injection',
    'xpath_injection': 'A03:2021 – Injection',
    'xss': 'A03:2021 – Injection',
    'csrf': 'A01:2021 – Broken Access Control',
    'open_redirect': 'A01:2021 – Broken Access Control',
    'xxe': 'A05:2021 – Security Misconfiguration',
    'path_traversal': 'A01:2021 – Broken Access Control',
    'insecure_deserialization': 'A08:2021 – Software and Data Integrity Failures',
    'arbitrary_file_upload': 'A01:2021 – Broken Access Control',
    'log_injection': 'A09:2021 – Security Logging and Monitoring Failures',
    'hardcoded_secrets': 'A07:2021 – Identification and Authentication Failures',
    'weak_hashing': 'A02:2021 – Cryptographic Failures',
    'broken_jwt_auth': 'A07:2021 – Identification and Authentication Failures',
    'weak_randomness': 'A02:2021 – Cryptographic Failures',
    'insecure_eval': 'A03:2021 – Injection',
    'debug_mode_in_prod': 'A05:2021 – Security Misconfiguration',
    'overly_permissive_cors': 'A05:2021 – Security Misconfiguration',
    'missing_security_headers': 'A05:2021 – Security Misconfiguration',
    'buffer_overflow': 'A06:2021 – Vulnerable and Outdated Components',
    'use_after_free': 'A06:2021 – Vulnerable and Outdated Components',
    'integer_overflow': 'A06:2021 – Vulnerable and Outdated Components',
    'redos': 'A06:2021 – Vulnerable and Outdated Components',
}


def generate_report(
    vulnerability: dict,
    status: str,
    attempts: List[dict],
    diff_text: str = "",
    patch_file_path: str = "",
    repo_path: str = ".",
    output_dir: str = "output",
) -> Dict[str, Any]:
    """
    Generate a Markdown report for a single vulnerability remediation.
    """
    vuln_type = vulnerability.get('vuln_type', 'unknown')
    file_path = vulnerability.get('file_path', 'unknown')
    line_number = vulnerability.get('line_number', 0)
    severity = vulnerability.get('severity', 'MEDIUM')
    description = vulnerability.get('description', '')
    owasp = OWASP_MAPPING.get(vuln_type, 'N/A')

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_attempts = len(attempts)
    best_attempt = _get_best_attempt(attempts)

    # Build report content
    lines = []
    lines.append(f"# SecureGuard AI - Remediation Report")
    lines.append(f"")
    lines.append(f"**Generated**: {timestamp}")
    lines.append(f"**Status**: {_status_badge(status)}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Vulnerability details
    lines.append(f"## Vulnerability Details")
    lines.append(f"")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Type** | {vuln_type} |")
    lines.append(f"| **File** | `{file_path}` |")
    lines.append(f"| **Line** | {line_number} |")
    lines.append(f"| **Severity** | {severity} |")
    lines.append(f"| **OWASP** | {owasp} |")
    lines.append(f"| **Description** | {description} |")
    lines.append(f"")

    # Fix summary
    lines.append(f"## Fix Summary")
    lines.append(f"")
    lines.append(f"- **Total attempts**: {total_attempts}")
    lines.append(f"- **Final status**: {status}")
    if best_attempt:
        lines.append(f"- **Tests passed**: {best_attempt.get('tests_passed', 0)}")
        lines.append(f"- **Tests failed**: {best_attempt.get('tests_failed', 0)}")
    lines.append(f"")

    # Before/After code
    if best_attempt and best_attempt.get('fix_code'):
        original = vulnerability.get('code_snippet', '')
        if original:
            lines.append(f"## Before (Vulnerable Code)")
            lines.append(f"")
            lines.append(f"```")
            lines.append(original)
            lines.append(f"```")
            lines.append(f"")

        lines.append(f"## After (Fixed Code)")
        lines.append(f"")
        lines.append(f"```")
        # Show a snippet of the fix around the vulnerable line
        fix_snippet = _extract_fix_snippet(best_attempt['fix_code'], line_number)
        lines.append(fix_snippet)
        lines.append(f"```")
        lines.append(f"")

    # Diff
    if diff_text:
        lines.append(f"## Unified Diff")
        lines.append(f"")
        lines.append(f"```diff")
        lines.append(diff_text)
        lines.append(f"```")
        lines.append(f"")

    # Attempt history
    if total_attempts > 1:
        lines.append(f"## Attempt History")
        lines.append(f"")
        for a in attempts:
            status_icon = "✅" if a.get('tests_failed', 1) == 0 else "❌"
            lines.append(f"### Attempt {a.get('attempt', '?')} {status_icon}")
            lines.append(f"")
            lines.append(f"- Tests passed: {a.get('tests_passed', 0)}")
            lines.append(f"- Tests failed: {a.get('tests_failed', 0)}")
            if a.get('test_output'):
                lines.append(f"- Output: `{a['test_output'][:200]}`")
            lines.append(f"")

    # Patch file reference
    if patch_file_path:
        lines.append(f"## Patch File")
        lines.append(f"")
        lines.append(f"Apply with: `git apply {os.path.basename(patch_file_path)}`")
        lines.append(f"")
        lines.append(f"Location: `{patch_file_path}`")
        lines.append(f"")

    # Warning for unverified fixes
    if status == 'UNVERIFIED':
        lines.append(f"## ⚠️ Warning")
        lines.append(f"")
        lines.append(f"This fix could not be fully verified against the test suite.")
        lines.append(f"The best attempt is included but requires manual review before applying.")
        lines.append(f"All {total_attempts} attempt(s) and their failure reasons are documented above.")
        lines.append(f"")

    report_content = '\n'.join(lines)

    # Write report file
    abs_repo = os.path.abspath(repo_path)
    abs_output = os.path.join(abs_repo, output_dir)
    os.makedirs(abs_output, exist_ok=True)

    safe_name = file_path.replace('/', '_').replace('\\', '_').replace('.', '_')
    report_filename = f"report_{safe_name}_{vuln_type}.md"
    report_path = os.path.join(abs_output, report_filename)

    with open(report_path, 'w') as f:
        f.write(report_content)

    print(f"  Report: {report_path}")

    # Build one-line summary
    summary = (f"{_status_badge(status)} {vuln_type} in {file_path}:{line_number} "
               f"- {total_attempts} attempt(s)")

    return {
        'report_file_path': report_path,
        'summary': summary,
        'report_content': report_content,
    }


def generate_summary_report(
    results: List[dict],
    repo_path: str = ".",
    output_dir: str = "output",
) -> str:
    """Generate a summary report across all vulnerabilities processed."""
    abs_repo = os.path.abspath(repo_path)
    abs_output = os.path.join(abs_repo, output_dir)
    os.makedirs(abs_output, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    verified = sum(1 for r in results if r.get('status') == 'VERIFIED')
    unverified = sum(1 for r in results if r.get('status') == 'UNVERIFIED')
    skipped = sum(1 for r in results if r.get('status') == 'SKIPPED')
    total = len(results)

    lines = []
    lines.append(f"# SecureGuard AI - Summary Report")
    lines.append(f"")
    lines.append(f"**Generated**: {timestamp}")
    lines.append(f"**Repository**: `{repo_path}`")
    lines.append(f"")
    lines.append(f"## Results Overview")
    lines.append(f"")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total vulnerabilities | {total} |")
    lines.append(f"| ✅ Verified fixes | {verified} |")
    lines.append(f"| ⚠️ Unverified fixes | {unverified} |")
    lines.append(f"| ⏭️ Skipped | {skipped} |")
    lines.append(f"| **Accuracy** | **{verified/total*100:.0f}%** |" if total > 0 else "| **Accuracy** | N/A |")
    lines.append(f"")
    lines.append(f"## Individual Results")
    lines.append(f"")

    for r in results:
        vuln = r.get('vulnerability', {})
        lines.append(f"- {_status_badge(r.get('status', ''))} "
                     f"`{vuln.get('vuln_type', '?')}` in "
                     f"`{vuln.get('file_path', '?')}:{vuln.get('line_number', '?')}` "
                     f"- {r.get('summary', '')}")

    lines.append(f"")
    lines.append(f"---")
    lines.append(f"*Generated by SecureGuard AI*")

    content = '\n'.join(lines)
    summary_path = os.path.join(abs_output, "summary_report.md")
    with open(summary_path, 'w') as f:
        f.write(content)

    return summary_path


def _status_badge(status: str) -> str:
    """Return a status badge emoji."""
    badges = {
        'VERIFIED': '✅ VERIFIED',
        'UNVERIFIED': '⚠️ UNVERIFIED',
        'SKIPPED': '⏭️ SKIPPED',
        'SYNTAX_ONLY_VERIFIED': '🔍 SYNTAX-ONLY',
        'PENDING': '⏳ PENDING',
    }
    return badges.get(status, status)


def _get_best_attempt(attempts: list) -> dict:
    """Get the best attempt (fewest test failures)."""
    if not attempts:
        return {}
    return min(attempts, key=lambda a: a.get('tests_failed', 999))


def _extract_fix_snippet(fix_code: str, target_line: int, context: int = 10) -> str:
    """Extract a snippet of the fix around the target line."""
    lines = fix_code.split('\n')
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet_lines = lines[start:end]
    # Add line numbers
    numbered = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(snippet_lines)]
    return '\n'.join(numbered)
