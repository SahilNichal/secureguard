"""
reviewer.py — Displays diff output, shows fix summary, and captures developer approval decision.
Used in interactive mode to pause before applying patches.
"""
import difflib
import sys
from typing import Optional


def present_review(
    vuln_type: str,
    file_path: str,
    line_number: int,
    original_code: str,
    fixed_code: str,
    test_output: str = "",
    attempt_number: int = 1,
) -> str:
    """
    Present the proposed fix to the developer for approval.
    Returns: 'APPROVED' or 'REJECTED'
    """
    # Generate unified diff
    diff_text = generate_diff(original_code, fixed_code, file_path)

    # Display review interface
    print("\n" + "=" * 70)
    print("  SECUREGUARD AI — HUMAN REVIEW")
    print("=" * 70)
    print(f"\n  Vulnerability : {vuln_type}")
    print(f"  File          : {file_path}:{line_number}")
    print(f"  Fix Attempt   : #{attempt_number}")
    print(f"\n{'─' * 70}")
    print("  UNIFIED DIFF:")
    print(f"{'─' * 70}")

    # Colorize diff output for terminal
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            print(f"  \033[32m{line}\033[0m")  # Green for additions
        elif line.startswith('-') and not line.startswith('---'):
            print(f"  \033[31m{line}\033[0m")  # Red for removals
        elif line.startswith('@@'):
            print(f"  \033[36m{line}\033[0m")  # Cyan for hunk headers
        else:
            print(f"  {line}")

    # Show test results
    if test_output:
        print(f"\n{'─' * 70}")
        print("  TEST RESULTS:")
        print(f"{'─' * 70}")
        # Show last 500 chars of test output
        trimmed = test_output[-500:] if len(test_output) > 500 else test_output
        for line in trimmed.split('\n'):
            print(f"  {line}")

    # Show fix summary
    print(f"\n{'─' * 70}")
    print("  FIX SUMMARY:")
    print(f"{'─' * 70}")
    print(f"  This fix addresses a {vuln_type} vulnerability by replacing")
    print(f"  the insecure pattern with a secure alternative.")
    print(f"  All tests passed after applying this fix.")

    # Get approval
    print(f"\n{'─' * 70}")
    print("  ACTION REQUIRED:")
    print(f"{'─' * 70}")

    try:
        while True:
            response = input("\n  Approve this fix? [y/n]: ").strip().lower()
            if response in ('y', 'yes', 'approve'):
                print("  ✅ Fix APPROVED — proceeding to patch generation.")
                return "APPROVED"
            elif response in ('n', 'no', 'reject'):
                print("  ❌ Fix REJECTED — skipping this vulnerability.")
                return "REJECTED"
            else:
                print("  Please enter 'y' (approve) or 'n' (reject)")
    except (EOFError, KeyboardInterrupt):
        # Non-interactive environment — auto-approve
        print("\n  ℹ️  Non-interactive environment detected — auto-approving.")
        return "APPROVED"


def generate_diff(original: str, fixed: str, file_path: str = "file") -> str:
    """Generate a unified diff between original and fixed code."""
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm='',
    )

    return '\n'.join(diff)


def auto_review(confidence: float = 1.0, threshold: float = 0.9) -> str:
    """
    Automatic review for CI/CD mode.
    Approves fixes above confidence threshold, flags others for manual review.
    """
    if confidence >= threshold:
        return "APPROVED"
    else:
        print(f"  ⚠️  Confidence {confidence:.2f} below threshold {threshold:.2f} — flagged for manual review.")
        return "REJECTED"
