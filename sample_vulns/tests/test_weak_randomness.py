"""Tests for weak_randomness.py — verify secrets module is used."""
import inspect


def test_generate_token_uses_secrets():
    """generate_token should use secrets, not random."""
    from sample_vulns.weak_randomness import generate_token
    source = inspect.getsource(generate_token)
    assert 'random.randint' not in source, "Still uses random.randint"
    assert 'secrets' in source, "Should use secrets module"


def test_generate_session_id_uses_secrets():
    """generate_session_id should use secrets, not random."""
    from sample_vulns.weak_randomness import generate_session_id
    source = inspect.getsource(generate_session_id)
    assert 'random.choices' not in source, "Still uses random.choices"


def test_generate_reset_code_uses_secrets():
    """generate_reset_code should use secrets."""
    from sample_vulns.weak_randomness import generate_reset_code
    source = inspect.getsource(generate_reset_code)
    assert 'random.choices' not in source, "Still uses random.choices"


def test_token_length():
    """Tokens should be sufficiently long."""
    from sample_vulns.weak_randomness import generate_token
    token = generate_token()
    assert len(str(token)) >= 16, "Token should be at least 16 characters"
