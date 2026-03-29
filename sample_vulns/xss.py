"""Sample vulnerable file: Cross-Site Scripting (XSS)"""


def render_greeting(username):
    """Render a greeting - VULNERABLE to XSS."""
    return f"<h1>Welcome, {username}!</h1>"


def render_comment(comment_text):
    """Render a user comment - VULNERABLE to XSS."""
    return "<div class='comment'>" + comment_text + "</div>"


def render_search_results(query, results):
    """Render search results - VULNERABLE to reflected XSS."""
    html = f"<h2>Results for: {query}</h2><ul>"
    for r in results:
        html += f"<li>{r}</li>"
    html += "</ul>"
    return html
