"""Sample vulnerable file: Weak Randomness"""
import random
import string


def generate_token():
    """Generate an auth token - VULNERABLE: uses random instead of secrets."""
    return str(random.randint(100000, 999999))


def generate_session_id():
    """Generate a session ID - VULNERABLE: uses random instead of secrets."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def generate_reset_code():
    """Generate a password reset code - VULNERABLE: uses random."""
    return ''.join(random.choices(string.digits, k=6))
