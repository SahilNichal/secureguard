"""
fp_filter.py - False positive filtering stage.
Calls LLM to evaluate confidence and reachability. Deduplicates findings.
Returns filtered list with only true positives above confidence threshold.
"""
import json
import os
import re
import time
from typing import List, Dict, Any

from langchain_core.messages import SystemMessage, HumanMessage

from config.llm_factory import get_llm
from prompts.fp_filter import FP_FILTER_SYSTEM_PROMPT, FP_FILTER_USER_TEMPLATE


def _response_to_text(response_content: Any) -> str:
    """Normalize LLM response content into plain text."""
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


def filter_false_positives(
    findings: List[Dict[str, Any]],
    confidence_threshold: float = 0.75,
    enabled_types: List[str] = None,
) -> List[Dict[str, Any]]:
    """
    Filter out false positives from the findings list.
    Each finding is evaluated by the LLM for confidence and reachability.
    Findings below the confidence threshold are marked as false positives.
    Deduplicates findings that point to the same root cause.
    """
    if not findings:
        return []

    # Filter by enabled vulnerability types if specified
    if enabled_types:
        findings = [f for f in findings if f.get('vuln_type') in enabled_types]

    # Deduplicate findings pointing to the same location
    findings = _deduplicate(findings)

    filtered = []
    for i, finding in enumerate(findings):
        result = _evaluate_finding(finding, confidence_threshold)
        filtered.append(result)
        # Pace API calls to avoid 429 rate-limit errors — sleep between calls, not after all
        if i < len(findings) - 1:
            time.sleep(2)
    # Separate true positives from false positives
    true_positives = [f for f in filtered if not f.get('is_false_positive', False)]
    false_positives = [f for f in filtered if f.get('is_false_positive', False)]

    print(f"\n[FP Filter] {len(true_positives)} true positives, {len(false_positives)} false positives filtered")
    for fp in false_positives:
        print(f"  Filtered: {fp['vuln_type']} at {fp['file_path']}:{fp['line_number']} - {fp.get('fp_reason', 'below threshold')}")

    return true_positives


def _evaluate_finding(finding: Dict[str, Any], threshold: float) -> Dict[str, Any]:
    """Evaluate a single finding using LLM-based false positive analysis."""
    # Quick pre-checks before calling LLM
    pre_check = _pre_filter_check(finding)
    if pre_check is not None:
        return {**finding, **pre_check}

    # LLM-based evaluation
    try:
        llm = get_llm()

        user_msg = FP_FILTER_USER_TEMPLATE.format(
            vuln_type=finding.get('vuln_type', 'unknown'),
            file_path=finding.get('file_path', ''),
            line_number=finding.get('line_number', 0),
            severity=finding.get('severity', 'MEDIUM'),
            description=finding.get('description', ''),
            code_snippet=finding.get('code_snippet', 'N/A'),
            full_context=finding.get('full_context', 'N/A'),
            imports=finding.get('imports', 'N/A'),
        )

        response = llm.invoke([
            SystemMessage(content=FP_FILTER_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ])

        response_text = _response_to_text(getattr(response, "content", response))
        analysis = _parse_fp_response(response_text)
        analysis = _normalize_fp_analysis(analysis, finding)

        confidence = analysis.get('confidence', 0.5)
        is_fp = analysis.get('is_false_positive', confidence < threshold)

        return {
            **finding,
            'is_false_positive': is_fp,
            'fp_reason': analysis.get('fp_reason', ''),
            'confidence': confidence,
            'fp_checks': analysis.get('checks', {}),
        }

    except Exception as e:
        # On LLM failure, default to keeping the finding (conservative)
        print(f"  [FP Filter] LLM evaluation failed for {finding.get('vuln_type')}: {e}")
        return {
            **finding,
            'is_false_positive': False,
            'fp_reason': f'LLM evaluation failed: {e}',
            'confidence': 0.5,
        }


def _pre_filter_check(finding: Dict[str, Any]) -> dict | None:
    """Quick pre-checks that don't need LLM calls."""
    file_path = finding.get('file_path', '')
    filename = os.path.basename(file_path).lower()
    path_lower = file_path.lower()

    # Check if it's a test file
    test_patterns = ['test_', '_test.', 'mock', 'fixture', 'conftest', 'spec_', '_spec.']
    if any(p in filename for p in test_patterns):
        return {
            'is_false_positive': True,
            'fp_reason': f'Test file detected: {filename}',
            'confidence': 0.1,
        }

    # Check if it's a known non-source file
    non_source = ['.md', '.txt', '.rst', '.json', '.yaml', '.yml', '.toml', '.cfg', '.ini']
    if any(filename.endswith(ext) for ext in non_source):
        return {
            'is_false_positive': True,
            'fp_reason': f'Non-source file: {filename}',
            'confidence': 0.05,
        }

    # Check if it's inside a vendor/dependency/migration directory
    skip_dirs = ['node_modules', 'vendor', 'migrations', '.venv', 'venv', 'env', 'site-packages']
    if any(f'/{d}/' in path_lower or path_lower.startswith(f'{d}/') for d in skip_dirs):
        return {
            'is_false_positive': True,
            'fp_reason': f'Vendor/dependency/migration directory: {file_path}',
            'confidence': 0.05,
        }

    # Unresolved line number — scanner couldn't find the exact location
    if finding.get('line_number', 0) == 0:
        return {
            'is_false_positive': True,
            'fp_reason': 'Line number is 0 — scanner could not resolve location',
            'confidence': 0.2,
        }

    # Locator failed or returned empty snippet — not worth an LLM call
    code_snippet = finding.get('code_snippet', '').strip()
    if not code_snippet or code_snippet == 'N/A':
        locator_error = finding.get('locator_error', '').strip()
        return {
            'is_false_positive': True,
            'fp_reason': locator_error or 'Code snippet empty — locator could not resolve the reported line',
            'confidence': 0.1,
        }

    return None


def _parse_fp_response(response_text: str) -> dict:
    """Parse the LLM response into a structured dict."""
    cleaned = _strip_code_fences(response_text or "").strip()

    # Try exact JSON first
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to extract a JSON object from prose or markdown
    candidate = _extract_json_candidate(cleaned)
    if candidate:
        for attempt in (candidate, _normalize_json_like(candidate)):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError:
                continue

    # Fallback: parse key indicators from text more explicitly
    text_lower = cleaned.lower()
    is_fp = _extract_bool_value(cleaned, "is_false_positive")
    if is_fp is None:
        is_fp = 'false positive' in text_lower and 'true positive' not in text_lower

    confidence = _extract_confidence(cleaned)
    checks = {
        "is_test_file": _extract_bool_value(cleaned, "is_test_file"),
        "is_reachable": _extract_bool_value(cleaned, "is_reachable"),
        "pattern_found": _extract_bool_value(cleaned, "pattern_found"),
        "line_offset": _extract_int_value(cleaned, "line_offset"),
    }

    return {
        'is_false_positive': is_fp,
        'confidence': confidence,
        'fp_reason': cleaned[:200],
        'checks': {k: v for k, v in checks.items() if v is not None},
    }


def _normalize_fp_analysis(analysis: dict, finding: Dict[str, Any]) -> dict:
    """Normalize parser output and enforce a few deterministic consistency rules."""
    normalized = dict(analysis or {})
    checks = dict(normalized.get("checks") or {})

    original_is_fp = bool(normalized.get("is_false_positive", False))
    path_is_test_file = _path_looks_like_test_file(finding.get("file_path", ""))
    checks["is_test_file"] = path_is_test_file

    confidence = normalized.get("confidence", 0.5)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    if confidence > 1:
        confidence = confidence / 100.0
    confidence = max(0.0, min(1.0, confidence))

    line_offset = checks.get("line_offset", 0)
    try:
        line_offset = int(line_offset)
    except (TypeError, ValueError):
        line_offset = 0
    checks["line_offset"] = line_offset

    fp_reason = str(normalized.get("fp_reason", ""))
    sample_source = _path_looks_like_sample_source(finding.get("file_path", ""))
    pattern_found = bool(checks.get("pattern_found", False))

    # A sample/demo/example source file is still a real vulnerability if the pattern is present.
    # Only test/mock/fixture paths should be auto-demoted based on context alone.
    if original_is_fp and sample_source and not path_is_test_file:
        if pattern_found or _reason_mentions_sample_only(fp_reason):
            normalized["is_false_positive"] = False
            confidence = max(confidence, 0.8)

    normalized["checks"] = checks
    normalized["confidence"] = confidence
    return normalized


def _strip_code_fences(text: str) -> str:
    return re.sub(r"```(?:json)?|```", "", text, flags=re.IGNORECASE)


def _extract_json_candidate(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _normalize_json_like(text: str) -> str:
    normalized = text.strip()
    normalized = normalized.replace("{{", "{").replace("}}", "}")
    return normalized


def _extract_bool_value(text: str, field: str) -> bool | None:
    match = re.search(rf'"?{re.escape(field)}"?\s*[:=]\s*(true|false)', text, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).lower() == "true"


def _extract_confidence(text: str) -> float:
    conf_match = re.search(r'"?confidence"?\s*[:=]\s*(\d+\.?\d*)', text, re.IGNORECASE)
    if not conf_match:
        return 0.5
    confidence = float(conf_match.group(1))
    if confidence > 1:
        confidence = confidence / 100.0
    return max(0.0, min(1.0, confidence))


def _extract_int_value(text: str, field: str) -> int | None:
    match = re.search(rf'"?{re.escape(field)}"?\s*[:=]\s*(-?\d+)', text, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def _path_looks_like_test_file(file_path: str) -> bool:
    filename = os.path.basename(file_path).lower()
    path_lower = file_path.lower()
    test_patterns = ['test_', '_test.', 'mock', 'fixture', 'conftest', 'spec_', '_spec.']
    return any(p in filename or f'/{p}' in path_lower for p in test_patterns)


def _path_looks_like_sample_source(file_path: str) -> bool:
    path_lower = file_path.lower()
    sample_markers = ('sample', 'samples', 'demo', 'example', 'examples', 'benchmark')
    return any(marker in path_lower for marker in sample_markers)


def _reason_mentions_sample_only(reason: str) -> bool:
    reason_lower = reason.lower()
    sample_terms = ('sample vulnerable', 'sample code', 'example code', 'demo code', 'intentionally vulnerable')
    disqualifying_terms = ('test file', 'mock', 'fixture', 'not reachable', 'pattern not found')
    return any(term in reason_lower for term in sample_terms) and not any(
        term in reason_lower for term in disqualifying_terms
    )


def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings that point to the same root cause.
    Groups by (file_path, vuln_type) and keeps the highest severity.
    """
    seen = {}
    for f in findings:
        key = (f.get('file_path', ''), f.get('vuln_type', ''))
        if key not in seen:
            seen[key] = f
        else:
            # Keep the one with higher severity or lower line number
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            existing_sev = severity_order.get(seen[key].get('severity', 'MEDIUM'), 2)
            new_sev = severity_order.get(f.get('severity', 'MEDIUM'), 2)
            if new_sev < existing_sev:
                seen[key] = f

    deduped = list(seen.values())
    if len(deduped) < len(findings):
        print(f"  [FP Filter] Deduplicated {len(findings)} findings -> {len(deduped)}")
    return deduped
