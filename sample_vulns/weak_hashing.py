"""Sample vulnerable file: Weak Hashing"""
import hashlib


def hash_password(password):
    """Hash a password — VULNERABLE: uses MD5."""
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """Verify a password — VULNERABLE: uses MD5."""
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def hash_token(token):
    """Hash a token — VULNERABLE: uses SHA1."""
    return hashlib.sha1(token.encode()).hexdigest()
