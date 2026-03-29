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
    for finding in findings:
        result = _evaluate_finding(finding, confidence_threshold)
        filtered.append(result)

    print("  [Rate Limit] Pacing API to avoid 429 error. Sleeping 5s...")
    time.sleep(5)
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

        analysis = _parse_fp_response(response.content)

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

    return None


def _parse_fp_response(response_text: str) -> dict:
    """Parse the LLM response into a structured dict."""
    # Try to extract JSON from the response
    try:
        # Look for JSON block in the response
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response_text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: parse key indicators from text
    text_lower = response_text.lower()
    is_fp = 'false positive' in text_lower and 'true positive' not in text_lower
    confidence = 0.5
    # Try to extract confidence score
    conf_match = re.search(r'confidence[:\s]+(\d+\.?\d*)', text_lower)
    if conf_match:
        confidence = float(conf_match.group(1))
        if confidence > 1:
            confidence = confidence / 100.0

    return {
        'is_false_positive': is_fp,
        'confidence': confidence,
        'fp_reason': response_text[:200],
    }


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
