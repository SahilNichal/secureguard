"""
agent/tools.py — LangChain tools used within LangGraph nodes.
Defines the 4 tools: read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool.
Each tool is a Python function wrapped with @tool decorator.
"""
import os
import ast
import subprocess
import tempfile
import shutil
from typing import Optional

from langchain_core.tools import tool

from locator import read_file_content, search_codebase


# Global reference to the repo path — set by the agent before running
_repo_path: str = "."


def set_repo_path(path: str) -> None:
    """Set the repository path for tools that need it."""
    global _repo_path
    _repo_path = os.path.abspath(path)


@tool
def read_file_tool(file_path: str) -> str:
    """Read the contents of a file. Use this to examine source code before generating a fix.
    Provide the full or relative file path."""
    # Resolve relative paths against repo
    if not os.path.isabs(file_path):
        file_path = os.path.join(_repo_path, file_path)
    return read_file_content(file_path)


@tool
def run_tests_tool(file_path: str, fix_code: str, test_command: Optional[str] = None) -> str:
    """Apply a proposed fix to a file and run the test suite.
    Returns test output including pass/fail counts.

    Args:
        file_path: Path to the file to fix
        fix_code: The complete fixed file content to write
        test_command: Optional custom test command. Defaults to pytest.
    """
    if not os.path.isabs(file_path):
        file_path = os.path.join(_repo_path, file_path)

    if not os.path.exists(file_path):
        return f"Error: File not found: {file_path}"

    # Create a temporary copy of the original file
    backup_path = file_path + ".secureguard.bak"
    shutil.copy2(file_path, backup_path)

    try:
        # Write the fix
        with open(file_path, 'w') as f:
            f.write(fix_code)

        # Syntax check first
        if file_path.endswith('.py'):
            try:
                ast.parse(fix_code)
            except SyntaxError as e:
                return f"SYNTAX ERROR: {e}\nFix did not compile. Line {e.lineno}: {e.msg}"

        # Run tests
        if test_command is None:
            test_dir = os.path.dirname(file_path)
            test_command = f"python -m pytest {test_dir} -v --tb=short -q"

        try:
            result = subprocess.run(
                test_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=_repo_path,
            )
            output = result.stdout + result.stderr

            # Parse pytest output for pass/fail counts
            passed = output.count(" passed")
            failed = output.count(" failed")
            errors = output.count(" error")

            summary = f"Tests completed. Return code: {result.returncode}\n"
            summary += f"Passed: {passed}, Failed: {failed}, Errors: {errors}\n"
            summary += f"\nFull output:\n{output[-2000:]}"  # Last 2000 chars
            return summary

        except subprocess.TimeoutExpired:
            return "TIMEOUT: Tests took longer than 60 seconds"

    finally:
        # Restore original file
        shutil.move(backup_path, file_path)


@tool
def search_codebase_tool(pattern: str) -> str:
    """Search the codebase for occurrences of a pattern.
    Use this to find related code, usages of a function, or similar vulnerability patterns.

    Args:
        pattern: The text pattern to search for in the codebase.
    """
    return search_codebase(_repo_path, pattern)


@tool
def explain_fix_tool(vulnerability_type: str, original_code: str, fixed_code: str) -> str:
    """Generate a clear explanation of what the fix does and why it's secure.
    Use this AFTER generating a fix to verify your own reasoning.
    If you cannot explain the fix clearly, regenerate it.

    Args:
        vulnerability_type: The type of vulnerability being fixed
        original_code: The original vulnerable code
        fixed_code: The proposed fix
    """
    explanation = []
    explanation.append(f"## Fix Explanation: {vulnerability_type}")
    explanation.append("")
    explanation.append("### What was vulnerable:")
    explanation.append(f"```\n{original_code}\n```")
    explanation.append("")
    explanation.append("### What the fix does:")
    explanation.append(f"```\n{fixed_code}\n```")
    explanation.append("")
    explanation.append("### Why this is secure:")
    explanation.append(f"The fix addresses {vulnerability_type} by replacing the vulnerable pattern "
                      f"with a secure alternative. Please verify the fix preserves all existing "
                      f"functionality and follows secure coding practices.")
    explanation.append("")
    explanation.append("### Edge cases to consider:")
    explanation.append("- Does the fix handle null/empty inputs?")
    explanation.append("- Does the fix preserve error handling?")
    explanation.append("- Are there other call sites that need the same fix?")

    return "\n".join(explanation)


def get_all_tools():
    """Return a list of all available tools."""
    return [read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool]
