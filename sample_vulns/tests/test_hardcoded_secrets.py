"""Baseline behavior tests for hardcoded_secrets.py."""
import importlib
import sys
import types


def test_connect_to_api_uses_current_api_key(monkeypatch):
    """connect_to_api should send a bearer token header."""
    captured = {}

    def fake_get(url, headers):
        captured["url"] = url
        captured["headers"] = headers
        return {"ok": True}

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=fake_get))

    import sample_vulns.hardcoded_secrets as mod
    importlib.reload(mod)

    result = mod.connect_to_api()

    assert result == {"ok": True}
    assert captured["url"] == "https://api.example.com/data"
    assert captured["headers"]["Authorization"].startswith("Bearer ")


def test_get_db_connection_uses_current_database_url(monkeypatch):
    """get_db_connection should pass the configured database URL to psycopg2."""
    captured = {}

    def fake_connect(dsn):
        captured["dsn"] = dsn
        return {"connected": True}

    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace(connect=fake_connect))

    import sample_vulns.hardcoded_secrets as mod
    importlib.reload(mod)

    result = mod.get_db_connection()

    assert result == {"connected": True}
    assert captured["dsn"] == mod.DATABASE_URL
