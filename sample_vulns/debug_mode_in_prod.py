"""Sample vulnerable file: Debug Mode in Production"""


DEBUG = True
SECRET_KEY = "dev-secret-key"


def create_app():
    """Create Flask app - VULNERABLE: debug=True hardcoded."""
    from flask import Flask
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = SECRET_KEY

    @app.route('/')
    def index():
        return "Hello World"

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
