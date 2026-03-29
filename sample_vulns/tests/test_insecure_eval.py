"""Tests for insecure_eval.py - verify eval/exec are replaced."""
import inspect


def test_calculate_no_eval():
    """calculate should not use raw eval."""
    from sample_vulns.insecure_eval import calculate
    source = inspect.getsource(calculate)
    assert 'eval(' not in source or 'literal_eval' in source, \
        "calculate still uses raw eval()"


def test_calculate_safe_input():
    """calculate should handle valid expressions."""
    from sample_vulns.insecure_eval import calculate
    result = calculate("2 + 3")
    assert result == 5


def test_calculate_rejects_dangerous():
    """calculate should reject dangerous expressions."""
    from sample_vulns.insecure_eval import calculate
    try:
        calculate("__import__('os').system('echo hacked')")
        assert False, "Should reject dangerous expressions"
    except (ValueError, TypeError, SyntaxError, NameError):
        pass


def test_parse_config_no_eval():
    """parse_config should not use raw eval."""
    from sample_vulns.insecure_eval import parse_config
    source = inspect.getsource(parse_config)
    assert 'eval(' not in source or 'literal_eval' in source, \
        "parse_config still uses raw eval()"


def test_parse_config_dict():
    """parse_config should parse dict strings."""
    from sample_vulns.insecure_eval import parse_config
    result = parse_config('{"key": "value"}')
    assert result == {"key": "value"}
