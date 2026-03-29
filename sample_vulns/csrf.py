"""Sample vulnerable file: Cross-Site Request Forgery (CSRF)"""


def transfer_funds(request):
    """Transfer funds - VULNERABLE: no CSRF protection."""
    amount = request.form.get('amount')
    to_account = request.form.get('to_account')
    # No CSRF token validation
    return {"status": "transferred", "amount": amount, "to": to_account}


def change_password(request):
    """Change password - VULNERABLE: no CSRF protection."""
    new_password = request.form.get('new_password')
    # No CSRF token check
    return {"status": "password_changed"}


def render_transfer_form():
    """Render form - VULNERABLE: no CSRF token in form."""
    return """
    <form method="POST" action="/transfer">
        <input name="amount" type="number">
        <input name="to_account" type="text">
        <button type="submit">Transfer</button>
    </form>
    """
