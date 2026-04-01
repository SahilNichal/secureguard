"""
agent/test_generator.py - Stateless LLM test generator (Strategy 4).

Uses a completely fresh LLM context (no memory of the fix-generation conversation)
to write a minimal pytest test that:
  - PASSES when the vulnerability is correctly fixed
  - FAILS when the original vulnerability is still present

The generated test is run in a temp location and discarded after validation.
"""
import os
import sys
import re
import tempfile
import subprocess
from typing import Dict, Any


TEST_GEN_SYSTEM_PROMPT = """You are a security test engineer.
Write a minimal pytest test function that PASSES when the vulnerability is fixed
and FAILS when the original vulnerability pattern is still present.

Rules:
- Write ONLY ONE test function named exactly: test_security_fix()
- Import the module under test using importlib.util so you can load it from an absolute path
- The test must be self-contained — no external fixtures needed
- Focus exclusively on the security property, not business logic
- Return ONLY valid Python code, no markdown fences, no explanation
"""


def _response_to_text(response_content: Any) -> str:
    """Normalize provider-specific response content into plain text."""
    if response_content is None:
        return ""

    if isinstance(response_content, str):
        return response_content

    if isinstance(response_content, list):
        parts = []
        for item in response_content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif item.get("type") == "text" and isinstance(item.get("content"), str):
                    parts.append(item["content"])
            else:
                text_attr = getattr(item, "text", None)
                if isinstance(text_attr, str):
                    parts.append(text_attr)
                else:
                    parts.append(str(item))
        return "\n".join(part for part in parts if part)

    text_attr = getattr(response_content, "text", None)
    if isinstance(text_attr, str):
        return text_attr

    return str(response_content)


def run_test_generator(
    vuln_type: str,
    fix_strategy: str,
    fixed_code: str,
    file_path: str,
    repo_path: str,
) -> Dict[str, Any]:
    """
    Ask a fresh LLM to write a minimal security test, run it, and return results.

    Returns a dict with:
      tests_passed: int
      tests_failed: int
      test_output:  str
      generated_test: str (the test code that was generated)
      error:        str (only if something failed catastrophically)
    """
    # Step 1: Generate the test
    test_code = _generate_test_code(vuln_type, fix_strategy, fixed_code, file_path, repo_path)

    if not test_code:
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": "Test generator failed to produce valid test code.",
            "generated_test": "",
        }

    # Step 2: Run the generated test in a temp file
    return _run_generated_test(test_code, fixed_code, file_path, repo_path)


def _generate_test_code(
    vuln_type: str,
    fix_strategy: str,
    fixed_code: str,
    file_path: str,
    repo_path: str,
) -> str:
    """Call the LLM to generate a test. Returns raw Python test code string."""
    try:
        from config.llm_factory import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = get_llm()

        abs_file = os.path.join(os.path.abspath(repo_path), file_path)
        module_name = os.path.splitext(os.path.basename(file_path))[0]

        user_message = f"""Vulnerability Type: {vuln_type}
Fix Strategy: {fix_strategy}
File path (absolute): {abs_file}
Module name: {module_name}

FIXED CODE:
{fixed_code[:3000]}

Write a single pytest test function test_security_fix() that:
1. Loads the fixed code from the absolute path above using importlib.util
2. Calls the relevant function with a payload that would trigger {vuln_type} if unfixed
3. Asserts that the result does NOT contain the unsafe pattern

Return ONLY the Python test code, no explanation, no markdown."""

        print(f"  [TestGen] Asking LLM to generate a security test for {vuln_type}...")

        # Fresh context — completely stateless, no previous messages
        messages = [
            SystemMessage(content=TEST_GEN_SYSTEM_PROMPT),
            HumanMessage(content=user_message),
        ]

        response = llm.invoke(messages)
        raw = _response_to_text(getattr(response, "content", response))

        # Strip markdown fences if present
        code = re.sub(r"```(?:python)?", "", raw, flags=re.IGNORECASE).strip()
        code = re.sub(r"```$", "", code, flags=re.MULTILINE).strip()

        # Basic sanity check — must have the required function name
        if "def test_security_fix" not in code:
            print(f"  [TestGen] Warning: Generated code missing test_security_fix() — skipping")
            return ""

        return code

    except Exception as e:
        print(f"  [TestGen] Error generating test: {e}")
        return ""


def _run_generated_test(
    test_code: str,
    fixed_code: str,
    file_path: str,
    repo_path: str,
) -> Dict[str, Any]:
    """
    Write the generated test and fixed code to temp files, run pytest, return results.
    Both temp files are discarded after the run.
    """
    tmp_dir = tempfile.mkdtemp(prefix="sg_testgen_")
    try:
        abs_repo = os.path.abspath(repo_path)
        abs_file = os.path.join(abs_repo, file_path)

        # Write the fixed source file into the temp dir so the test can import it
        source_name = os.path.basename(file_path)
        temp_source = os.path.join(tmp_dir, source_name)
        with open(temp_source, "w") as f:
            f.write(fixed_code)

        # Rewrite the import path in the generated test to point to temp_source
        patched_test = test_code.replace(abs_file, temp_source)

        # Write the generated test file
        test_file = os.path.join(tmp_dir, "test_generated_security.py")
        with open(test_file, "w") as f:
            f.write(patched_test)

        # Run pytest against the generated test only
        python = sys.executable
        env = os.environ.copy()
        env["PYTHONPATH"] = tmp_dir + os.pathsep + abs_repo + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        result = subprocess.run(
            [python, "-m", "pytest", test_file, "-v", "--tb=short", "-q"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_dir,
            env=env,
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        output = stdout + stderr

        # Parse counts
        import re as _re
        passed = int((_re.search(r"(\d+) passed", output) or type("", (), {"group": lambda s, i: "0"})()).group(1))
        failed = int((_re.search(r"(\d+) failed", output) or type("", (), {"group": lambda s, i: "0"})()).group(1))
        errors = int((_re.search(r"(\d+) error", output) or type("", (), {"group": lambda s, i: "0"})()).group(1))

        if passed == 0 and failed == 0 and errors == 0:
            passed = 1 if result.returncode == 0 else 0
            failed = 0 if result.returncode == 0 else 1

        return {
            "tests_passed": passed,
            "tests_failed": failed + errors,
            "test_output": output[-2000:],
            "generated_test": test_code,
        }

    except subprocess.TimeoutExpired:
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": "TIMEOUT: Generated test exceeded 60 second limit",
            "generated_test": test_code,
        }
    except Exception as e:
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": f"Error running generated test: {e}",
            "generated_test": test_code,
        }
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
