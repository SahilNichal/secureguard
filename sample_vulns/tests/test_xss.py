"""Tests for xss.py - verify HTML escaping is applied."""
import inspect


def test_render_greeting_escapes_html():
    """render_greeting should escape HTML special chars."""
    from sample_vulns.xss import render_greeting
    result = render_greeting("<script>alert('xss')</script>")
    assert "<script>" not in result, "XSS payload not escaped in greeting"
    assert "&lt;script&gt;" in result or "&#" in result, "HTML should be escaped"


def test_render_comment_escapes_html():
    """render_comment should escape HTML special chars."""
    from sample_vulns.xss import render_comment
    result = render_comment('<img src=x onerror=alert(1)>')
    assert 'onerror=' not in result, "XSS payload not escaped in comment"


def test_render_search_escapes_query():
    """render_search_results should escape the query parameter."""
    from sample_vulns.xss import render_search_results
    result = render_search_results("<script>alert(1)</script>", ["item1"])
    assert "<script>" not in result, "XSS payload not escaped in search"


def test_uses_escape_function():
    """Module should use an escape function (markupsafe, html.escape, etc.)."""
    import sample_vulns.xss as mod
    source = inspect.getsource(mod)
    has_escape = ('escape' in source or 'bleach' in source or
                  'html.escape' in source or 'markupsafe' in source)
    assert has_escape, "Module should use an HTML escape function"
