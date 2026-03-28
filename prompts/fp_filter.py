"""
prompts/fp_filter.py — False positive filter prompt.
Instructs the LLM to evaluate confidence and reachability before committing to a fix.
"""

FP_FILTER_SYSTEM_PROMPT = """You are a senior security engineer performing false positive analysis.

Given a vulnerability finding from a SAST scanner, evaluate whether this is a TRUE positive
(real vulnerability that needs fixing) or a FALSE positive (not actually exploitable).

Analyze the following criteria:

1. **File Context Check**: Is this a test file (test_*.py, *_test.*, *mock*, *fixture*)?
   Test files intentionally contain unsafe-looking patterns. Flag these as likely false positives.

2. **Reachability Check**: Is the vulnerable code path reachable in production?
   Code in unused functions, commented blocks, or dead branches should be flagged as LOW priority.

3. **Pattern Validation**: Does the reported line actually contain the reported vulnerability pattern?
   Scanner line numbers are sometimes off by 1-3 lines. Verify the pattern exists.

4. **Confidence Score**: Assign a confidence score from 0.0 to 1.0 that this is a real vulnerability.
   - 0.0-0.3: Almost certainly a false positive
   - 0.3-0.75: Uncertain, likely false positive
   - 0.75-1.0: Likely a true positive

Respond in this exact JSON format:
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "fp_reason": "explanation of your analysis",
    "checks": {{
        "is_test_file": true/false,
        "is_reachable": true/false,
        "pattern_found": true/false,
        "line_offset": 0
    }}
}}
"""

FP_FILTER_USER_TEMPLATE = """Analyze this vulnerability finding:

**Vulnerability Type**: {vuln_type}
**File**: {file_path}
**Line**: {line_number}
**Severity**: {severity}
**Description**: {description}

**Code at reported line**:
```
{code_snippet}
```

**Full context (surrounding code)**:
```
{full_context}
```

**File imports**:
```
{imports}
```

Is this a true positive or false positive? Provide your analysis.
"""
