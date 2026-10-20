"""Durable @eN refs bound to (tab_id, doc_gen, node_uid) and snapshot delta diffs."""

from __future__ import annotations

import pytest

from nbrowser.errors import BrowserError, InputFailure
from nbrowser.extract import RefMap, diff_snapshots
from nbrowser.semantic import Element, SemanticView


def test_ref_map_preserves_identity_across_prepend_and_invalidates_on_doc_gen() -> None:
    rm = RefMap()
    v1 = SemanticView(
        url="https://example.com/app",
        doc_gen="dg-1",
        elements=[
            Element(
                id=0,
                ref="@e1",
                node_uid=10,
                selector="button:nth-of-type(1)",
                kind="button",
                label="Submit Order",
            )
        ],
    )
    rm.record_snapshot("t0", v1)
    assert [e.ref for e in v1.elements] == ["@e1"]

    # Prepending a new button before Submit Order shifts positional CSS selectors,
    # but node_uid=10 keeps @e1 and the new button receives @e2.
    v2 = SemanticView(
        url="https://example.com/app",
        doc_gen="dg-1",
        elements=[
            Element(
                id=0,
                ref="@e2",
                node_uid=11,
                selector="button:nth-of-type(1)",
                kind="button",
                label="Cancel",
            ),
            Element(
                id=1,
                ref="@e1",
                node_uid=10,
                selector="button:nth-of-type(2)",
                kind="button",
                label="Submit Order",
            ),
        ],
    )
    rm.record_snapshot("t0", v2)
    entry = rm.resolve("t0", "https://example.com/app", "dg-1", "@e1")
    assert entry.node_uid == 10
    assert entry.label == "Submit Order"
    assert entry.selector == "button:nth-of-type(2)"

    # Reloading the same URL produces a new doc_gen ("dg-2") or empty doc_gen ("")
    # before a fresh snapshot: old @e1 is refused in both cases.
    for live_gen in ("dg-2", ""):
        with pytest.raises(BrowserError) as exc:
            rm.resolve("t0", "https://example.com/app", live_gen, "@e1")
        assert exc.value.code is InputFailure.SELECTOR


def test_snapshot_digest_matches_remapped_view() -> None:
    from cdp_double import CdpDouble, FakePage

    from nbrowser.extract import compute_view_digest
    from nbrowser.mcp_server import McpServer
    from nbrowser.semantic import Element, FormMeta, SemanticView
    from nbrowser.session import BrowserLaunchConfig, BrowserSession

    page = FakePage("https://example.com/app", "App", "<button>Go</button>")
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: CdpDouble([page])
    )
    try:
        server.handle_tool_call("nbrowser_page_snapshot", {})
        page.url = "https://example.com/other"
        s2 = server.handle_tool_call("nbrowser_page_snapshot", {})
        v2_dict = s2["view"]
        rebuilt = SemanticView(
            url=v2_dict["url"],
            title=v2_dict["title"],
            page_hint=v2_dict["page_hint"],
            doc_gen=v2_dict["doc_gen"],
            elements=[Element(**el) for el in v2_dict["elements"]],
            forms=[FormMeta(**f) for f in v2_dict["forms"]],
            visible_text=v2_dict["visible_text"],
            text_blocks=v2_dict["text_blocks"],
            state=v2_dict["state"],
            http_status=v2_dict["http_status"],
            element_cap=v2_dict["element_cap"],
            blocked_reason=v2_dict["blocked_reason"],
            session_context=v2_dict["session_context"],
            cards=None,
            cards_truncated=v2_dict["cards_truncated"],
            frames_truncated=v2_dict["frames_truncated"],
            webmcp=v2_dict["webmcp"],
        )
        assert s2["digest"] == compute_view_digest(rebuilt)
    finally:
        server.close()


def test_diff_snapshots_computes_unified_diff_and_counts() -> None:
    before = SemanticView(
        url="https://example.com",
        title="Home",
        doc_gen="dg-1",
        elements=[
            Element(
                id=0,
                ref="@e1",
                node_uid=1,
                selector="#login",
                kind="button",
                label="Log in",
            )
        ],
        visible_text="Welcome",
    )
    after = SemanticView(
        url="https://example.com",
        title="Home",
        doc_gen="dg-1",
        elements=[
            Element(
                id=0,
                ref="@e1",
                node_uid=1,
                selector="#login",
                kind="button",
                label="Log in",
            ),
            Element(
                id=1,
                ref="@e2",
                node_uid=2,
                selector="#signup",
                kind="link",
                label="Sign up",
            ),
        ],
        visible_text="Welcome Sign up",
    )
    same = diff_snapshots(before, before)
    assert same["changed"] is False
    assert same["additions"] == 0
    assert same["removals"] == 0

    delta = diff_snapshots(before, after)
    assert delta["changed"] is True
    assert delta["additions"] >= 1
    assert "@e2" in delta["diff"]
