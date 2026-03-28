"""Tests for hardcoded_secrets.py — verify no literal secrets in source."""
import inspect
import re


def test_no_hardcoded_api_key():
    """API_KEY should not be a string literal."""
    from sample_vulns.hardcoded_secrets import API_KEY
    # If it's still a hardcoded string starting with 'sk-', it's vulnerable
    assert not isinstance(API_KEY, str) or not API_KEY.startswith('sk-'), \
        "API_KEY is still hardcoded"


def test_no_hardcoded_db_url():
    """DATABASE_URL should not contain literal password."""
    from sample_vulns.hardcoded_secrets import DATABASE_URL
    assert not isinstance(DATABASE_URL, str) or 'supersecretpassword' not in DATABASE_URL, \
        "DATABASE_URL still contains hardcoded password"


def test_uses_env_vars():
    """Module should use os.getenv or os.environ."""
    import sample_vulns.hardcoded_secrets as mod
    source = inspect.getsource(mod)
    assert 'os.getenv' in source or 'os.environ' in source, \
        "Module should use environment variables"
