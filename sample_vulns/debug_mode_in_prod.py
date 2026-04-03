"""Sample vulnerable file: Debug Mode in Production"""
import os
import secrets

def _is_debug_enabled():
    """Read Flask debug mode from the environment."""
    return os.getenv("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def _get_secret_key():
    """Use an environment secret when present, otherwise generate one."""
    return os.getenv("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)


def create_app():
    """Create Flask app with environment-driven debug and secret settings."""
    from flask import Flask
    app = Flask(__name__)
    app.config['DEBUG'] = _is_debug_enabled()
    app.config['SECRET_KEY'] = _get_secret_key()

    @app.route('/')
    def index():
        return "Hello World"

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(
        debug=_is_debug_enabled(),
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
    )
