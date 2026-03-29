"""Sample vulnerable file: Missing Security Headers"""


def create_response(body):
    """Create HTTP response - VULNERABLE: no security headers."""
    return {
        'status': 200,
        'headers': {
            'Content-Type': 'text/html',
        },
        'body': body,
    }


def create_app():
    """Create Flask app - VULNERABLE: no security headers middleware."""
    from flask import Flask
    app = Flask(__name__)

    @app.route('/')
    def index():
        return "<html><body>Hello</body></html>"

    # No security headers middleware configured
    return app
