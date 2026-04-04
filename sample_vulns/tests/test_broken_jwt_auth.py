"""Baseline behavior tests for broken_jwt_auth.py."""
import importlib
import sys
import types


def test_decode_token_verifies_signature(monkeypatch):
    captured = {}

    def fake_decode(token, key, algorithms=None, **kwargs):
        captured["token"] = token
        captured["key"] = key
        captured["algorithms"] = algorithms
        captured["kwargs"] = kwargs
        return {"user_id": 1}

    monkeypatch.setenv("SAMPLE_JWT_SECRET", "runtime-jwt-secret")
    monkeypatch.setitem(sys.modules, "jwt", types.SimpleNamespace(decode=fake_decode))

    import sample_vulns.broken_jwt_auth as mod
    importlib.reload(mod)

    result = mod.decode_token("token-value")

    assert result == {"user_id": 1}
    assert captured["key"] == "runtime-jwt-secret"
    assert captured["algorithms"] == ["HS256"]
    assert "options" not in captured["kwargs"]


def test_decode_token_v2_rejects_none_algorithm(monkeypatch):
    captured = {}

    def fake_decode(token, key, algorithms=None, **kwargs):
        captured["algorithms"] = algorithms
        return {"user_id": 7}

    monkeypatch.setenv("SAMPLE_JWT_SECRET", "runtime-jwt-secret")
    monkeypatch.setitem(sys.modules, "jwt", types.SimpleNamespace(decode=fake_decode))

    import sample_vulns.broken_jwt_auth as mod
    importlib.reload(mod)

    assert mod.decode_token_v2("token-value") == {"user_id": 7}
    assert captured["algorithms"] == ["HS256"]


def test_verify_user_returns_user_id(monkeypatch):
    def fake_decode(token, key, algorithms=None, **kwargs):
        return {"user_id": 42}

    monkeypatch.setenv("SAMPLE_JWT_SECRET", "runtime-jwt-secret")
    monkeypatch.setitem(sys.modules, "jwt", types.SimpleNamespace(decode=fake_decode))

    import sample_vulns.broken_jwt_auth as mod
    importlib.reload(mod)

    assert mod.verify_user("token-value") == 42
