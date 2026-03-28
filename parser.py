"""
parser.py — Reads JSON/text scan reports from any SAST tool.
Extracts: vuln_type, file_path, line_number, severity, description, scanner_id.
Normalizes output into a consistent dict format for downstream stages.
"""
import json
import os
from typing import List, Dict, Any


def parse_scan_report(report_path: str) -> List[Dict[str, Any]]:
    """
    Parse a SAST scan report file and return normalized vulnerability findings.
    Supports: Semgrep JSON, Bandit JSON, and a generic SecureGuard JSON format.
    """
    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Scan report not found: {report_path}")

    with open(report_path, 'r') as f:
        raw = json.load(f)

    # Detect format and dispatch
    if isinstance(raw, dict):
        if 'results' in raw and isinstance(raw['results'], list):
            # Semgrep format
            if raw['results'] and 'check_id' in raw['results'][0]:
                return _parse_semgrep(raw)
            # Bandit format
            if raw['results'] and 'test_id' in raw['results'][0]:
                return _parse_bandit(raw)
        # SecureGuard / generic format
        if 'vulnerabilities' in raw:
            return _parse_generic(raw)
        if 'findings' in raw:
            return _parse_generic_findings(raw)

    # If top-level is a list, treat as generic findings
    if isinstance(raw, list):
        return _parse_list(raw)

    raise ValueError(f"Unrecognized scan report format in {report_path}")


def _parse_semgrep(data: dict) -> List[Dict[str, Any]]:
    """Parse Semgrep JSON output."""
    findings = []
    for result in data.get('results', []):
        findings.append({
            'vuln_type': _normalize_vuln_type(result.get('check_id', '')),
            'file_path': result.get('path', ''),
            'line_number': result.get('start', {}).get('line', 0),
            'end_line': result.get('end', {}).get('line', 0),
            'severity': _normalize_severity(result.get('extra', {}).get('severity', 'MEDIUM')),
            'description': result.get('extra', {}).get('message', ''),
            'scanner_id': 'semgrep',
            'rule_id': result.get('check_id', ''),
            'raw': result,
        })
    return findings


def _parse_bandit(data: dict) -> List[Dict[str, Any]]:
    """Parse Bandit JSON output."""
    findings = []
    for result in data.get('results', []):
        findings.append({
            'vuln_type': _normalize_vuln_type(result.get('test_name', result.get('test_id', ''))),
            'file_path': result.get('filename', ''),
            'line_number': result.get('line_number', 0),
            'end_line': result.get('line_range', [0])[-1] if result.get('line_range') else 0,
            'severity': _normalize_severity(result.get('issue_severity', 'MEDIUM')),
            'description': result.get('issue_text', ''),
            'scanner_id': 'bandit',
            'rule_id': result.get('test_id', ''),
            'raw': result,
        })
    return findings


def _parse_generic(data: dict) -> List[Dict[str, Any]]:
    """Parse SecureGuard generic JSON format with 'vulnerabilities' key."""
    findings = []
    for vuln in data.get('vulnerabilities', []):
        findings.append({
            'vuln_type': _normalize_vuln_type(vuln.get('type', vuln.get('vuln_type', ''))),
            'file_path': vuln.get('file_path', vuln.get('file', '')),
            'line_number': vuln.get('line_number', vuln.get('line', 0)),
            'end_line': vuln.get('end_line', 0),
            'severity': _normalize_severity(vuln.get('severity', 'MEDIUM')),
            'description': vuln.get('description', vuln.get('message', '')),
            'scanner_id': vuln.get('scanner', data.get('scanner', 'unknown')),
            'rule_id': vuln.get('rule_id', ''),
            'raw': vuln,
        })
    return findings


def _parse_generic_findings(data: dict) -> List[Dict[str, Any]]:
    """Parse generic format with 'findings' key."""
    converted = {'vulnerabilities': data['findings']}
    if 'scanner' in data:
        converted['scanner'] = data['scanner']
    return _parse_generic(converted)


def _parse_list(data: list) -> List[Dict[str, Any]]:
    """Parse a plain list of vulnerability dicts."""
    return _parse_generic({'vulnerabilities': data})


def _normalize_vuln_type(raw_type: str) -> str:
    """Normalize vulnerability type names to internal keys."""
    mapping = {
        'sql_injection': 'sql_injection',
        'sql-injection': 'sql_injection',
        'sqli': 'sql_injection',
        'command_injection': 'command_injection',
        'command-injection': 'command_injection',
        'os_command_injection': 'command_injection',
        'ldap_injection': 'ldap_injection',
        'xpath_injection': 'xpath_injection',
        'xss': 'xss',
        'cross_site_scripting': 'xss',
        'cross-site-scripting': 'xss',
        'csrf': 'csrf',
        'cross_site_request_forgery': 'csrf',
        'open_redirect': 'open_redirect',
        'xxe': 'xxe',
        'xml_external_entity': 'xxe',
        'path_traversal': 'path_traversal',
        'directory_traversal': 'path_traversal',
        'insecure_deserialization': 'insecure_deserialization',
        'arbitrary_file_upload': 'arbitrary_file_upload',
        'log_injection': 'log_injection',
        'hardcoded_secrets': 'hardcoded_secrets',
        'hardcoded_password': 'hardcoded_secrets',
        'hardcoded_credentials': 'hardcoded_secrets',
        'weak_hashing': 'weak_hashing',
        'weak_hash': 'weak_hashing',
        'broken_jwt_auth': 'broken_jwt_auth',
        'jwt_verification_disabled': 'broken_jwt_auth',
        'weak_randomness': 'weak_randomness',
        'insecure_random': 'weak_randomness',
        'insecure_eval': 'insecure_eval',
        'eval_injection': 'insecure_eval',
        'exec_injection': 'insecure_eval',
        'debug_mode_in_prod': 'debug_mode_in_prod',
        'debug_mode': 'debug_mode_in_prod',
        'overly_permissive_cors': 'overly_permissive_cors',
        'cors_misconfiguration': 'overly_permissive_cors',
        'missing_security_headers': 'missing_security_headers',
        'buffer_overflow': 'buffer_overflow',
        'use_after_free': 'use_after_free',
        'integer_overflow': 'integer_overflow',
        'redos': 'redos',
        'regex_dos': 'redos',
    }

    key = raw_type.lower().strip().replace('-', '_').replace(' ', '_')
    # Strip common prefixes from scanner rules
    for prefix in ['security.', 'python.', 'java.', 'cwe-', 'b']:
        if key.startswith(prefix):
            key = key[len(prefix):]

    return mapping.get(key, key)


def _normalize_severity(raw_severity: str) -> str:
    """Normalize severity to CRITICAL/HIGH/MEDIUM/LOW."""
    s = raw_severity.upper().strip()
    if s in ('CRITICAL', 'VERY_HIGH'):
        return 'CRITICAL'
    if s in ('HIGH', 'ERROR'):
        return 'HIGH'
    if s in ('MEDIUM', 'WARNING', 'MODERATE'):
        return 'MEDIUM'
    if s in ('LOW', 'INFO', 'INFORMATIONAL'):
        return 'LOW'
    return 'MEDIUM'
