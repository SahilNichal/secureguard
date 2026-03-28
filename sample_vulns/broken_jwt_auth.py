"""Sample vulnerable file: Broken JWT Authentication"""
import jwt


SECRET_KEY = "my-secret-key"


def decode_token(token):
    """Decode a JWT — VULNERABLE: verification disabled."""
    return jwt.decode(token, options={"verify_signature": False})


def decode_token_v2(token):
    """Decode a JWT — VULNERABLE: allows 'none' algorithm."""
    return jwt.decode(token, SECRET_KEY, algorithms=["none", "HS256"])


def verify_user(token):
    """Verify user from token — VULNERABLE: verify=False."""
    payload = jwt.decode(token, SECRET_KEY, options={
        "verify_signature": False,
        "verify_exp": False,
    })
    return payload.get("user_id")
