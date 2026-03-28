"""
agent/feedback_loop.py — Implements retry logic aligned with LangGraph state transitions.
Captures test results, injects failure context, and decides when to escalate after 3 attempts.
"""
import re
from typing import List, Dict, Any


def build_initial_prompt(vulnerability: dict) -> str:
    """Build the first-attempt prompt for the agent."""
    return f"""Fix the following security vulnerability:

**Type**: {vulnerability.get('vuln_type', 'unknown')}
**File**: {vulnerability.get('file_path', '')}
**Line**: {vulnerability.get('line_number', 0)}
**Severity**: {vulnerability.get('severity', 'MEDIUM')}
**Description**: {vulnerability.get('description', '')}

**Vulnerable code snippet**:
```
{vulnerability.get('code_snippet', 'N/A')}
```

**Full context (surrounding code)**:
```
{vulnerability.get('full_context', 'N/A')}
```

**Function scope**:
```
{vulnerability.get('function_scope', 'N/A')}
```

**File imports**:
```
{vulnerability.get('imports', 'N/A')}
```

Steps:
1. Use read_file_tool to read the full file and understand the complete context.
2. Use search_codebase_tool to find other usages of the vulnerable pattern.
3. Generate a minimal, targeted fix that preserves all existing functionality.
4. Use explain_fix_tool to verify your reasoning.
5. Use run_tests_tool to validate your fix passes all tests.

Return the COMPLETE fixed file content (all lines, not just the changed function).
"""


def build_retry_prompt(
    vulnerability: dict,
    previous_attempts: List[Dict[str, Any]],
    last_failure: str,
) -> str:
    """
    Build a retry prompt that includes all previous failure context.
    Forces the agent to reason about what went wrong before generating a new fix.
    """
    attempt_history = ""
    for a in previous_attempts:
        attempt_history += f"Attempt {a['attempt']}:\n"
        attempt_history += f"Your fix:\n{a['fix_code'][:500]}\n"
        attempt_history += f"Test result: {a['tests_failed']} test(s) failed\n"
        attempt_history += f"Failure output:\n{a['test_output'][:500]}\n\n"

    return f"""You are fixing: {vulnerability.get('vuln_type', '')} in {vulnerability.get('file_path', '')} at line {vulnerability.get('line_number', 0)}.

YOUR PREVIOUS ATTEMPTS FAILED. Here is the full history:
{attempt_history}

Before generating a new fix, answer these questions in your reasoning:
1. What assumption did you make in your previous attempt(s) that was wrong?
2. What does the test failure tell you about the correct behavior expected?
3. What will you do differently this time?

Then generate a new fix that addresses the root cause of the test failure.
Use read_file_tool to re-read the file and verify your understanding.
Return the COMPLETE fixed file content.
"""


def sanitize_generated_code(text: str) -> str:
    """Normalize common LLM formatting artifacts before validation."""
    if not text:
        return ""

    cleaned = text.replace("\u00a0", " ")
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = cleaned.strip()

    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        if first_newline != -1:
            first_line = cleaned[:first_newline]
            remainder = cleaned[first_newline + 1:]
            if first_line.strip() in {"```", "```python"}:
                cleaned = remainder
            else:
                cleaned = cleaned[3:]
        else:
            cleaned = cleaned[3:]

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]

    cleaned = re.sub(
        r'(?m)^ (?=(def |class |from |import |@|if __name__|"""|\'\'\'))',
        '',
        cleaned,
    )

    cleaned = cleaned.strip()
    return cleaned


def extract_code_from_response(response: str) -> str:
    """
    Extract code from agent response. Handles:
    - Fenced code blocks (```python ... ```)
    - Raw code output
    - Mixed text and code
    """
    if not response:
        return ""

    # Try to extract from fenced code block
    code_blocks = re.findall(r'```(?:python)?\s*\n(.*?)```', response, re.DOTALL)
    if code_blocks:
        # Return the longest code block (likely the full file)
        return sanitize_generated_code(max(code_blocks, key=len))

    # If the response looks like pure code (starts with import, def, class, #)
    lines = response.strip().split('\n')
    code_indicators = ('import ', 'from ', 'def ', 'class ', '#', '"""', "'''")
    if lines and lines[0].strip().startswith(code_indicators):
        return sanitize_generated_code(response)

    # Fallback: return as-is
    return sanitize_generated_code(response)
