"""Baseline behavior tests for debug_mode_in_prod.py."""
import importlib
import sys
import types


class FakeFlask:
    def __init__(self, name):
        self.name = name
        self.config = {}
        self.routes = {}
        self.secret_key = None

    def route(self, path):
        def decorator(func):
            self.routes[path] = func
            return func
        return decorator


def test_create_app_uses_env_secret_key(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "runtime-secret")
    monkeypatch.setenv("FLASK_DEBUG", "false")
    monkeypatch.setitem(sys.modules, "flask", types.SimpleNamespace(Flask=FakeFlask))

    import sample_vulns.debug_mode_in_prod as mod
    importlib.reload(mod)

    app = mod.create_app()

    assert app.secret_key == "runtime-secret"
    assert app.config["DEBUG"] is False
    assert app.routes["/"]() == "Hello World"


def test_create_app_generates_secret_when_env_missing(monkeypatch):
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    monkeypatch.setenv("FLASK_DEBUG", "true")
    monkeypatch.setitem(sys.modules, "flask", types.SimpleNamespace(Flask=FakeFlask))

    import sample_vulns.debug_mode_in_prod as mod
    importlib.reload(mod)

    app = mod.create_app()

    assert isinstance(app.secret_key, str)
    assert len(app.secret_key) >= 32
    assert app.config["DEBUG"] is True
