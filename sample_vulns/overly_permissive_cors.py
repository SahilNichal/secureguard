"""Sample vulnerable file: Overly Permissive CORS"""


def add_cors_headers(response):
    """Add CORS headers — VULNERABLE: wildcard origin."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


def create_app_with_cors():
    """Create app with CORS — VULNERABLE: allows all origins."""
    from flask import Flask
    from flask_cors import CORS
    app = Flask(__name__)
    CORS(app, origins='*', supports_credentials=True)
    return app
