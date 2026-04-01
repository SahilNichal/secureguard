"""Baseline behavior tests for insecure_eval.py."""


def test_calculate_simple_expression():
    from sample_vulns.insecure_eval import calculate

    assert calculate("2 + 3") == 5


def test_calculate_literal_expression():
    from sample_vulns.insecure_eval import calculate

    assert calculate("10 - 4") == 6


def test_parse_config_dict():
    from sample_vulns.insecure_eval import parse_config

    assert parse_config('{"key": "value"}') == {"key": "value"}


def test_parse_config_list():
    from sample_vulns.insecure_eval import parse_config

    assert parse_config("[1, 2, 3]") == [1, 2, 3]
