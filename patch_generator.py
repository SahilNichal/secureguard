"""
patch_generator.py - Generates valid .patch files (git diff format) from the proposed fix.
Produces PR-ready unified diff output.
"""
import os
import difflib
import datetime
from typing import Dict, Any


def generate_patch(
    file_path: str,
    fix_code: str,
    repo_path: str = ".",
    output_dir: str = "output",
) -> Dict[str, Any]:
    """
    Generate a .patch file from the original file and the proposed fix.
    Returns the patch file path and diff text.
    """
    abs_repo = os.path.abspath(repo_path)
    abs_file = os.path.join(abs_repo, file_path) if not os.path.isabs(file_path) else file_path

    # Read original file
    if os.path.exists(abs_file):
        with open(abs_file, 'r') as f:
            original_code = f.read()
    else:
        original_code = ""

    # Generate unified diff
    diff_text = _generate_unified_diff(original_code, fix_code, file_path)

    # Create output directory
    abs_output = os.path.join(abs_repo, output_dir)
    os.makedirs(abs_output, exist_ok=True)

    # Generate patch filename
    safe_name = file_path.replace('/', '_').replace('\\', '_').replace('.', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    patch_filename = f"{safe_name}_{timestamp}.patch"
    patch_path = os.path.join(abs_output, patch_filename)

    # Write patch file
    with open(patch_path, 'w') as f:
        f.write(diff_text)

    print(f"  Patch file: {patch_path}")
    print(f"  Lines changed: +{_count_additions(diff_text)} / -{_count_deletions(diff_text)}")

    return {
        'patch_file_path': patch_path,
        'diff_text': diff_text,
        'additions': _count_additions(diff_text),
        'deletions': _count_deletions(diff_text),
    }


def apply_patch(file_path: str, fix_code: str, repo_path: str = ".") -> bool:
    """
    Apply the fix by writing the fixed code to the original file.
    Returns True if successful.
    """
    abs_repo = os.path.abspath(repo_path)
    abs_file = os.path.join(abs_repo, file_path) if not os.path.isabs(file_path) else file_path

    try:
        # Backup original
        backup_path = abs_file + ".secureguard.bak"
        if os.path.exists(abs_file):
            with open(abs_file, 'r') as f:
                original = f.read()
            with open(backup_path, 'w') as f:
                f.write(original)

        # Write fix
        with open(abs_file, 'w') as f:
            f.write(fix_code)

        print(f"  ✅ Fix applied to {file_path}")
        print(f"  📋 Backup saved to {backup_path}")
        return True

    except Exception as e:
        print(f"  ❌ Failed to apply fix: {e}")
        return False


def _generate_unified_diff(original: str, fixed: str, file_path: str) -> str:
    """Generate a git-style unified diff."""
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)

    # Ensure files end with newline
    if original_lines and not original_lines[-1].endswith('\n'):
        original_lines[-1] += '\n'
    if fixed_lines and not fixed_lines[-1].endswith('\n'):
        fixed_lines[-1] += '\n'

    diff_lines = list(difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    ))

    if not diff_lines:
        return f"--- a/{file_path}\n+++ b/{file_path}\n# No changes detected\n"

    return ''.join(diff_lines)


def _count_additions(diff_text: str) -> int:
    """Count added lines in a diff."""
    return sum(1 for line in diff_text.split('\n')
               if line.startswith('+') and not line.startswith('+++'))


def _count_deletions(diff_text: str) -> int:
    """Count deleted lines in a diff."""
    return sum(1 for line in diff_text.split('\n')
               if line.startswith('-') and not line.startswith('---'))
