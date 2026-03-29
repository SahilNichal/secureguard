"""
locator.py - Opens the target file, extracts context around the vulnerable line.
Identifies function scope and imports needed for understanding the fix context.
"""
import os
import ast
import re
from typing import Dict, Any, Optional


def locate_vulnerability(finding: Dict[str, Any], context_lines: int = 20) -> Dict[str, Any]:
    """
    Opens the target file and extracts code context around the vulnerable line.
    Returns the finding dict enriched with code_snippet, full_context, and function_scope.
    """
    file_path = finding['file_path']
    line_number = finding['line_number']

    if not os.path.exists(file_path):
        return {
            **finding,
            'code_snippet': '',
            'full_context': '',
            'function_scope': '',
            'imports': '',
            'locator_error': f'File not found: {file_path}',
        }

    with open(file_path, 'r') as f:
        lines = f.readlines()

    total_lines = len(lines)

    # Extract context window around vulnerable line
    start = max(0, line_number - context_lines - 1)
    end = min(total_lines, line_number + context_lines)
    context_lines_list = lines[start:end]
    full_context = ''.join(context_lines_list)

    # Extract the specific vulnerable line(s)
    vuln_start = max(0, line_number - 1)
    vuln_end = min(total_lines, finding.get('end_line', line_number))
    if vuln_end <= vuln_start:
        vuln_end = vuln_start + 1
    code_snippet = ''.join(lines[vuln_start:vuln_end])

    # Extract function scope
    function_scope = _find_enclosing_function(lines, line_number)

    # Extract imports
    imports = _extract_imports(lines)

    return {
        **finding,
        'code_snippet': code_snippet.rstrip(),
        'full_context': full_context,
        'function_scope': function_scope,
        'imports': imports,
        'total_lines': total_lines,
        'context_start_line': start + 1,
        'context_end_line': end,
    }


def _find_enclosing_function(lines: list, target_line: int) -> str:
    """Find the function or method that encloses the target line."""
    func_pattern = re.compile(r'^(\s*)(def|async\s+def)\s+(\w+)\s*\(')
    class_pattern = re.compile(r'^(\s*)class\s+(\w+)')

    enclosing_func_start = None
    enclosing_func_indent = None
    enclosing_class = None

    for i in range(target_line - 1, -1, -1):
        if i >= len(lines):
            continue
        line = lines[i]

        func_match = func_pattern.match(line)
        if func_match and enclosing_func_start is None:
            indent_len = len(func_match.group(1))
            enclosing_func_start = i
            enclosing_func_indent = indent_len
            continue

        if enclosing_func_start is not None:
            class_match = class_pattern.match(line)
            if class_match:
                class_indent = len(class_match.group(1))
                if class_indent < enclosing_func_indent:
                    enclosing_class = class_match.group(2)
                    break

    if enclosing_func_start is None:
        return '<module level>'

    # Extract the full function body
    func_lines = [lines[enclosing_func_start]]
    base_indent = enclosing_func_indent
    for i in range(enclosing_func_start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if stripped == '':
            func_lines.append(line)
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= base_indent and stripped != '':
            break
        func_lines.append(line)

    scope = ''.join(func_lines)
    if enclosing_class:
        scope = f'# Inside class: {enclosing_class}\n{scope}'
    return scope


def _extract_imports(lines: list) -> str:
    """Extract all import statements from the file."""
    import_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('import ') or stripped.startswith('from '):
            import_lines.append(stripped)
        elif stripped and not stripped.startswith('#') and not stripped.startswith('"""') and not stripped.startswith("'''"):
            # Stop after we leave the import block at the top
            if import_lines:
                break
    return '\n'.join(import_lines)


def read_file_content(file_path: str) -> str:
    """Read and return the full content of a file."""
    if not os.path.exists(file_path):
        return f"Error: File not found: {file_path}"
    with open(file_path, 'r') as f:
        return f.read()


def search_codebase(repo_path: str, pattern: str, file_extensions: Optional[list] = None) -> str:
    """
    Search the codebase for occurrences of a pattern.
    Returns formatted results showing file, line number, and matching line.
    """
    if file_extensions is None:
        file_extensions = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rb']

    results = []
    max_results = 50

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   ('node_modules', '__pycache__', 'venv', '.venv', 'env', '.git')]
        for fname in files:
            if not any(fname.endswith(ext) for ext in file_extensions):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        if pattern in line:
                            rel_path = os.path.relpath(fpath, repo_path)
                            results.append(f"{rel_path}:{line_num}: {line.rstrip()}")
                            if len(results) >= max_results:
                                results.append(f"... (truncated at {max_results} results)")
                                return '\n'.join(results)
            except (IOError, OSError):
                continue

    if not results:
        return f"No matches found for pattern: {pattern}"
    return '\n'.join(results)
