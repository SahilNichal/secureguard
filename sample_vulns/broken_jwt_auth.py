"""Sample vulnerable file: Broken JWT Authentication"""
import os

import jwt


JWT_ALGORITHMS = ["HS256"]


def _get_signing_key(secret_key=None):
    """Resolve the signing key from the caller or environment."""
    resolved = secret_key or os.getenv("SAMPLE_JWT_SECRET")
    if not resolved:
        raise ValueError("JWT signing key is not configured")
    return resolved


def decode_token(token, secret_key=None):
    """Decode a JWT while enforcing signature verification."""
    return jwt.decode(token, _get_signing_key(secret_key), algorithms=JWT_ALGORITHMS)


def decode_token_v2(token, secret_key=None):
    """Decode a JWT using the allowed signing algorithms only."""
    return jwt.decode(token, _get_signing_key(secret_key), algorithms=JWT_ALGORITHMS)


def verify_user(token, secret_key=None):
    """Verify the user from a signed JWT."""
    payload = jwt.decode(token, _get_signing_key(secret_key), algorithms=JWT_ALGORITHMS)
    return payload.get("user_id")
