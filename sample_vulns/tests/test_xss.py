"""Baseline behavior tests for xss.py."""


def test_render_greeting_returns_heading():
    from sample_vulns.xss import render_greeting

    result = render_greeting("Alice")

    assert result.startswith("<h1>")
    assert "Welcome" in result
    assert result.endswith("</h1>")


def test_render_comment_wraps_content():
    from sample_vulns.xss import render_comment

    result = render_comment("hello world")

    assert result.startswith("<div class='comment'>")
    assert "hello world" in result
    assert result.endswith("</div>")


def test_render_search_results_lists_items():
    from sample_vulns.xss import render_search_results

    result = render_search_results("item", ["item1", "item2"])

    assert "<ul>" in result
    assert "</ul>" in result
    assert "Results for:" in result
    assert "<li>item1</li>" in result
    assert "<li>item2</li>" in result
