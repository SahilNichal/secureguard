"""Baseline behavior tests for weak_randomness.py."""


def test_generate_token_returns_string():
    from sample_vulns.weak_randomness import generate_token

    token = generate_token()

    assert isinstance(token, str)
    assert len(token) >= 6


def test_generate_session_id_returns_identifier():
    from sample_vulns.weak_randomness import generate_session_id

    session_id = generate_session_id()

    assert isinstance(session_id, str)
    assert len(session_id) >= 16


def test_generate_reset_code_returns_digits():
    from sample_vulns.weak_randomness import generate_reset_code

    code = generate_reset_code()

    assert isinstance(code, str)
    assert code.isdigit()
    assert len(code) >= 6
