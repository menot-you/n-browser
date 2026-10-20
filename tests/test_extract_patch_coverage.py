"""Targeted patch coverage on nbrowser/extract.py and nbrowser/mcp_server.py."""

from __future__ import annotations

import unittest.mock
from urllib.parse import urlsplit

from nbrowser.extract import (
    MARKDOWN_WALKER,
    _redact_multiline,
    scrape_markdown_live,
    view_from_walker,
)
from nbrowser.mcp_server import McpServer, origin_of

# ============================================================================
# 1. nbrowser/mcp_server.py: lines [1010, 1011]
# ============================================================================


def test_mcp_server_interact_expected_origin_exception() -> None:
    """Cover lines 1010-1011: exception in origin_of/urlsplit on active_url."""
    server = McpServer()
    mock_session = unittest.mock.MagicMock()
    mock_session.closed = False  # Prevent get_session from replacing mock_session
    mock_session.tabs_list.return_value = ["tab-1"]
    # Port cannot be cast to integer in urlsplit/origin_of -> raises ValueError
    mock_session.evaluate.return_value = "http://example.com:not_a_port"
    server.session = mock_session
    server.seam = unittest.mock.MagicMock()
    server.seam.authorize_host_activation.return_value = unittest.mock.MagicMock(
        url="http://example.com"
    )

    with unittest.mock.patch("nbrowser.mcp_server.interact", return_value=True):
        res = server.handle_tool_call(
            "nbrowser_page_interact",
            {"verb": "click", "selector": "#button"},
        )
    assert res["status"] == "applied"


# ============================================================================
# 2. nbrowser/extract.py: lines [94, 123, 124, 146, 148, 152, 156, 158, 159, 165, 167]
#    branches: [93, 139, 143, 145, 147, 151, 155, 157, 164, 166, 176]
# ============================================================================


def test_extract_redact_multiline_empty_and_links() -> None:
    """Cover branch 93 and line 94: empty text returns unmodified."""
    assert _redact_multiline("") == ""
    redacted = _redact_multiline("[doc](http://user:pass@example.com/api)")
    assert "user:pass" not in redacted


def test_extract_scrape_markdown_live() -> None:
    """Cover lines 123-124: scrape_markdown_live calling evaluate and redacting."""
    mock_sess = unittest.mock.MagicMock()
    mock_sess.evaluate.return_value = (
        "Title\n\n[link](https://user:pass@example.com/item)"
    )
    res = scrape_markdown_live(mock_sess, "t1")
    mock_sess.evaluate.assert_called_once_with("t1", MARKDOWN_WALKER)
    assert "user:pass" not in res
    assert "# Title" not in res

    mock_sess.evaluate.return_value = None
    assert scrape_markdown_live(mock_sess, "t2") == ""


def test_extract_view_from_walker_full_branch_coverage() -> None:
    """Cover lines 146, 148, 152, 156, 158, 159, 165, 167 and all element/form branches."""
    el1 = {
        "id": 1,
        "selector": "token_0123456789abcdef0123456789abcdef",
        "label": "My Label",
        "name": "username",
        "placeholder": "Enter pass",
        "autocomplete": "current-password",
        "href": "https://user:pass@example.com/link",
        "context": "https://user:pass@example.com/ctx",
        "hint": "Hint here",
        "options": ["opt1", "opt2"],
    }
    el2 = {
        "id": 2,
        "selector": "#btn",
        "context": "/local/path",
    }
    el3 = {
        "id": 3,
        "selector": None,
        "label": None,
        "name": None,
        "placeholder": None,
        "autocomplete": None,
        "href": None,
        "context": "plain text context",
        "hint": None,
        "options": None,
    }
    el4 = {"id": 4, "context": None}

    forms = [
        {"index": 0, "action": "https://user:pass@example.com/post"},
        {"index": 1, "action": None},
        {"index": 2},
    ]

    payload = {"elements": [el1, el2, el3, el4], "forms": forms}
    view = view_from_walker(payload)

    assert view.elements[0].selector == ""
    assert view.elements[0].name == "username"
    assert "[REDACTED]" in str(view.elements[0].placeholder)
    assert "[REDACTED]" in str(view.elements[0].autocomplete)
    assert "user:pass" not in str(view.elements[0].href)
    assert "user:pass" not in str(view.elements[0].context)
    assert view.elements[0].hint == "Hint here"
    assert view.elements[0].options == ["opt1", "opt2"]

    assert view.elements[1].selector == "#btn"
    assert view.elements[1].context == "/local/path"
    assert view.elements[2].context == "plain text context"
    assert "user:pass" not in str(view.forms[0].action)
    assert view.forms[1].action is None


def test_origin_of() -> None:
    """Cover line 200 and branch 199: IPv6 hostname missing brackets."""
    parts_v6 = urlsplit("http://[::1]:8080")
    assert origin_of(parts_v6) == "http://[::1]:8080"

    parts_http_default = urlsplit("http://example.com:80")
    assert origin_of(parts_http_default) == "http://example.com"

    parts_https_default = urlsplit("https://example.com:443")
    assert origin_of(parts_https_default) == "https://example.com"

    parts_non_default = urlsplit("http://example.com:8080")
    assert origin_of(parts_non_default) == "http://example.com:8080"
