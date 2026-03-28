"""Sample vulnerable file: Hardcoded Secrets"""


API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"
DATABASE_URL = "postgresql://admin:supersecretpassword@db.example.com:5432/production"
JWT_SECRET = "my-jwt-secret-key-12345"


def connect_to_api():
    """Connect using hardcoded API key — VULNERABLE."""
    import requests
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)


def get_db_connection():
    """Connect using hardcoded credentials — VULNERABLE."""
    import psycopg2
    return psycopg2.connect(DATABASE_URL)
