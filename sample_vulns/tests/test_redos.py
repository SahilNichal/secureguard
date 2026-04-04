"""Baseline behavior tests for redos.py."""


def test_validate_url_accepts_basic_https_url():
    from sample_vulns.redos import validate_url

    assert validate_url("https://example.com/path/to/page") is True


def test_validate_url_accepts_domain_without_path():
    from sample_vulns.redos import validate_url

    assert validate_url("http://example.org") is True


def test_validate_url_rejects_non_url_text():
    from sample_vulns.redos import validate_url

    assert validate_url("not a valid url") is False
