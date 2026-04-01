"""
validator.py - Applies the proposed fix to a temp copy and runs tests.
Falls back to ast.parse + LLM Judge + LLM Test Generator when no tests exist.
Returns pass/fail counts and test output.
"""
import os
import ast
import subprocess
import shutil
import sys
import tempfile
import concurrent.futures
from typing import Dict, Any
from agent.feedback_loop import sanitize_generated_code


def validate_fix(
    file_path: str,
    fix_code: str,
    repo_path: str = ".",
    test_command: str = None,
    original_code: str = "",
    vuln_type: str = "",
    fix_strategy: str = "",
    enable_llm_fix_verification: bool = True,
) -> Dict[str, Any]:
    """
    Validate a proposed fix by:
    1. Syntax check (ast.parse for Python)
    2. Apply fix to a temp copy of the repo
    3. Run test suite against the temp copy
    4. Return results without modifying the original

    If no tests exist, falls back to syntax validation + SAST re-scan.
    """
    fix_code = sanitize_generated_code(fix_code)
    abs_file = os.path.join(os.path.abspath(repo_path), file_path) if not os.path.isabs(file_path) else file_path
    abs_repo = os.path.abspath(repo_path)

    # Step 1: Syntax check
    if file_path.endswith('.py'):
        syntax_result = _check_python_syntax(fix_code)
        if not syntax_result['valid']:
            return {
                'tests_passed': 0,
                'tests_failed': 1,
                'test_output': f"SYNTAX ERROR: {syntax_result['error']}",
                'status': 'SYNTAX_ERROR',
            }

    # Step 2: Create temp copy of the repo with the fix applied
    temp_dir = tempfile.mkdtemp(prefix="secureguard_validate_")
    try:
        # Copy the repo to temp location
        temp_repo = os.path.join(temp_dir, "repo")
        shutil.copytree(abs_repo, temp_repo, ignore=shutil.ignore_patterns(
            '.git', '__pycache__', '*.pyc', 'node_modules', '.venv', 'venv', 'secure-venv',
            'output',  # exclude generated patch/report files — not needed for testing
        ))

        # Apply fix to the temp copy
        rel_path = os.path.relpath(abs_file, abs_repo)
        temp_file = os.path.join(temp_repo, rel_path)
        os.makedirs(os.path.dirname(temp_file), exist_ok=True)
        with open(temp_file, 'w') as f:
            f.write(fix_code)

        # Step 3: Run tests
        test_result = _run_tests(temp_repo, rel_path, test_command)

        if not enable_llm_fix_verification:
            if test_result.get('no_tests', False):
                return {
                    'tests_passed': 0,
                    'tests_failed': 0,
                    'test_output': 'No test suite detected. LLM fix verification is disabled, so this fix remains unverified.',
                    'status': 'NO_TESTS',
                }
            return test_result

        # Always run AI-enhanced validation when enabled.
        # If no tests were found, run Judge + TestGen.
        # If tests were found, run Judge and incorporate test_result instead of TestGen.
        print(f"  [Validate] Running LLM Security Judge verification...")
        return _ai_enhanced_validation(
            file_path=rel_path,
            fix_code=fix_code,
            original_code=original_code,
            vuln_type=vuln_type,
            fix_strategy=fix_strategy,
            repo_path=repo_path,
            local_test_result=test_result if not test_result.get('no_tests', False) else None
        )

    finally:
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


def _check_python_syntax(code: str) -> Dict[str, Any]:
    """Check Python code for syntax errors using ast.parse."""
    try:
        ast.parse(code)
        return {'valid': True, 'error': None}
    except SyntaxError as e:
        return {
            'valid': False,
            'error': f"Line {e.lineno}: {e.msg}",
        }


def _run_tests(
    repo_path: str,
    changed_file: str,
    test_command: str = None,
) -> Dict[str, Any]:
    """Run the test suite in the repo and return results."""

    # Auto-detect test command if not provided
    if test_command is None:
        test_command = _detect_test_command(repo_path, changed_file)

    if test_command is None:
        return {
            'tests_passed': 0,
            'tests_failed': 0,
            'test_output': 'No test suite detected',
            'no_tests': True,
        }

    try:
        # Ensure Python imports come from temp repo, not original
        test_env = os.environ.copy()
        test_env['PYTHONDONTWRITEBYTECODE'] = '1'
        test_env['PYTHONPATH'] = repo_path + os.pathsep + test_env.get('PYTHONPATH', '')
        
        result = subprocess.run(
            test_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_path,
            env=test_env,
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        output = stdout + stderr

        # Parse pytest output
        passed = _count_pattern(output, r'(\d+) passed')
        failed = _count_pattern(output, r'(\d+) failed')
        errors = _count_pattern(output, r'(\d+) error')

        # If we can't parse counts, use return code
        if passed == 0 and failed == 0 and errors == 0:
            if result.returncode == 0:
                passed = 1
            else:
                failed = 1

        return {
            'tests_passed': passed,
            'tests_failed': failed + errors,
            'test_output': output[-3000:],  # Last 3000 chars
            'status': 'VERIFIED' if (failed + errors) == 0 else 'FAILED',
        }

    except subprocess.TimeoutExpired:
        return {
            'tests_passed': 0,
            'tests_failed': 1,
            'test_output': 'TIMEOUT: Tests exceeded 120 second limit',
            'status': 'TIMEOUT',
        }
    except Exception as e:
        return {
            'tests_passed': 0,
            'tests_failed': 1,
            'test_output': f'Error running tests: {e}',
            'status': 'ERROR',
        }


def _detect_test_command(repo_path: str, changed_file: str) -> str | None:
    """Auto-detect the appropriate test command for the repo."""
    python = sys.executable

    # Check for test files matching the changed file first
    dirname = os.path.dirname(changed_file)
    basename = os.path.basename(changed_file)
    name_no_ext = os.path.splitext(basename)[0]

    test_file_patterns = [
        os.path.join(dirname, f"test_{basename}"),
        os.path.join(dirname, f"{name_no_ext}_test.py"),
        os.path.join("tests", f"test_{basename}"),
        os.path.join(dirname, "tests", f"test_{basename}"),
    ]

    for tf in test_file_patterns:
        if os.path.exists(os.path.join(repo_path, tf)):
            return f"{python} -m pytest {tf} -v --tb=short -q"

    # Fallback: Check for whole test directories
    test_dirs = ['tests', 'test', 'sample_vulns/tests']
    for td in test_dirs:
        test_path = os.path.join(repo_path, td)
        if os.path.isdir(test_path):
            return f"{python} -m pytest {td} -v --tb=short -q"

    # Check for pyproject.toml or setup.py
    if os.path.exists(os.path.join(repo_path, 'pyproject.toml')):
        return f"{python} -m pytest -v --tb=short -q"

    if os.path.exists(os.path.join(repo_path, 'setup.py')):
        return f"{python} -m pytest -v --tb=short -q"

    return None


def _count_pattern(text: str, pattern: str) -> int:
    """Extract a count from pytest output using regex."""
    import re
    match = re.search(pattern, text)
    if match:
        return int(match.group(1))
    return 0


def _ai_enhanced_validation(
    file_path: str,
    fix_code: str,
    original_code: str,
    vuln_type: str,
    fix_strategy: str,
    repo_path: str,
    local_test_result: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    ALWAYS runs Strategy 3 (LLM Judge). 
    If local_test_result is None, runs Strategy 4 (LLM Test Generator) in parallel.

    Decision table:
      Judge=SAFE     + Test=PASS  → AI-VERIFIED        (tests_failed=0)
      Judge=SAFE     + Test=FAIL  → UNCERTAIN / retry  (tests_failed=1)
      Judge=VULNERABLE + any      → FAILED / retry     (tests_failed=1)
      Judge=UNCERTAIN + Test=PASS → UNCERTAIN (proceed)(tests_failed=0, warning in output)
      Judge=UNCERTAIN + Test=FAIL → FAILED / retry     (tests_failed=1)
      Judge=error    + Test=PASS  → UNCERTAIN (proceed)(tests_failed=0)
      Judge=error    + Test=error → fallback syntax-only
    """
    from agent.llm_judge import run_llm_judge
    from agent.test_generator import run_test_generator

    judge_result = {}
    testgen_result = {}

    # Run both in parallel — neither call knows about the other
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        judge_future = executor.submit(
            run_llm_judge,
            vuln_type=vuln_type,
            fix_strategy=fix_strategy,
            original_code=original_code,
            fixed_code=fix_code,
        )

        testgen_future = executor.submit(
            run_test_generator,
            vuln_type=vuln_type,
            fix_strategy=fix_strategy,
            fixed_code=fix_code,
            file_path=file_path,
            repo_path=repo_path,
        )

        try:
            judge_result = judge_future.result(timeout=120)
        except Exception as e:
            judge_result = {"verdict": "UNCERTAIN", "confidence": 0.0,
                            "reason": f"Judge timed out or crashed: {e}", "error": str(e)}

        try:
            testgen_result = testgen_future.result(timeout=120)
        except Exception as e:
            testgen_result = {"tests_passed": 0, "tests_failed": 0,
                              "test_output": f"TestGen timed out or crashed: {e}", "error": str(e)}

    # If we also have a local test result, merge them so both matter
    if local_test_result:
        testgen_result["tests_passed"] += local_test_result.get("tests_passed", 0)
        testgen_result["tests_failed"] += local_test_result.get("tests_failed", 0)
        local_output = local_test_result.get("test_output", "")
        testgen_result["test_output"] = (
            f"=== Local Repository Tests ===\n{local_output}\n\n"
            f"=== LLM Generated Test ===\n{testgen_result.get('test_output', '(no output)')}"
        )

    verdict = judge_result.get("verdict", "UNCERTAIN")
    judge_reason = judge_result.get("reason", "")
    judge_confidence = judge_result.get("confidence", 0.0)
    test_passed = testgen_result.get("tests_passed", 0) > 0
    test_failed = testgen_result.get("tests_failed", 0) > 0
    test_error = "error" in testgen_result
    generated_test = testgen_result.get("generated_test", "")

    print(f"  [Judge]   verdict={verdict} confidence={judge_confidence:.2f} | {judge_reason}")
    print(f"  [TestGen] passed={testgen_result.get('tests_passed',0)} "
          f"failed={testgen_result.get('tests_failed',0)}")

    # ── Decision table ──────────────────────────────────────────────
    full_output = (
        f"=== LLM Security Judge ===\n"
        f"Verdict: {verdict} (confidence: {judge_confidence:.0%})\n"
        f"Reason:  {judge_reason}\n\n"
    )

    if local_test_result is None:
        full_output += f"=== LLM Generated Test ===\n"

    full_output += f"{testgen_result.get('test_output', '(no output)')}\n"
    if generated_test:
        full_output += f"\n--- Generated Test Code ---\n{generated_test}\n"

    if verdict == "VULNERABLE":
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": full_output,
            "status": "FAILED",
        }

    if verdict == "SAFE":
        if test_passed or test_error:
            return {
                "tests_passed": 1,
                "tests_failed": 0,
                "test_output": f"AI-VERIFIED: {full_output}",
                "status": "AI_VERIFIED",
            }
        else:  # test_failed
            return {
                "tests_passed": 0,
                "tests_failed": 1,
                "test_output": f"UNCERTAIN — Judge approved but generated test failed:\n{full_output}",
                "status": "FAILED",
            }

    # verdict == "UNCERTAIN"
    if test_passed:
        return {
            "tests_passed": 1,
            "tests_failed": 0,
            "test_output": f"UNCERTAIN — Judge inconclusive but generated test passed:\n{full_output}",
            "status": "AI_VERIFIED",
        }
    elif test_failed:
        return {
            "tests_passed": 0,
            "tests_failed": 1,
            "test_output": f"UNCERTAIN — Judge inconclusive and generated test failed:\n{full_output}",
            "status": "FAILED",
        }
    else:
        # Both inconclusive — fall back to syntax-only
        return {
            "tests_passed": 1,
            "tests_failed": 0,
            "test_output": f"SYNTAX-ONLY-VERIFIED (AI checks inconclusive):\n{full_output}",
            "status": "SYNTAX_ONLY_VERIFIED",
        }
