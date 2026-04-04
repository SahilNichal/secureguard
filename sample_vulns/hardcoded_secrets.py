"""Sample vulnerable file: Hardcoded Secrets"""
import os

API_KEY = os.getenv("SAMPLE_API_KEY", "")
DATABASE_URL = os.getenv("SAMPLE_DATABASE_URL", "")
JWT_SECRET = os.getenv("SAMPLE_JWT_SECRET", "")


def connect_to_api():
    """Connect using the configured API key."""
    import requests
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)


def get_db_connection():
    """Connect using the configured database URL."""
    import psycopg2
    return psycopg2.connect(DATABASE_URL)
