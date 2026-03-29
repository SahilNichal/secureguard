"""Sample vulnerable file: Open Redirect"""


def redirect_user(request_args):
    """Redirect user - VULNERABLE to open redirect."""
    next_url = request_args.get('next', '/')
    # No validation on redirect target
    return {"status": 302, "Location": next_url}


def login_redirect(return_url):
    """Redirect after login - VULNERABLE to open redirect."""
    return f'<meta http-equiv="refresh" content="0;url={return_url}">'
