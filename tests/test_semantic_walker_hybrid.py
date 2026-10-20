"""Hybrid SEMANTIC_WALKER tests: doc_gen, node_uid, @eN refs, cursor:pointer,
hidden input promotion inside <label>, and bounded WebMCP discovery."""

from nbrowser.extract import view_from_walker
from nbrowser.semantic import Element, SemanticView
from nbrowser.semantic_walker import SEMANTIC_WALKER


def test_element_and_semantic_view_declare_hybrid_fields() -> None:
    el = Element(id=0, selector="#btn", kind="button", ref="@e1", node_uid=7)
    assert el.ref == "@e1"
    assert el.node_uid == 7

    view = SemanticView(
        url="https://example.com",
        doc_gen="dg-1",
        webmcp={"untrusted": True, "available": True, "toolCount": 1, "tools": []},
    )
    assert view.doc_gen == "dg-1"
    assert view.webmcp is not None
    assert view.webmcp["untrusted"] is True


def test_walker_script_registers_doc_gen_node_uid_cursor_and_webmcp() -> None:
    assert "Symbol.for('nbrowser.docGen')" in SEMANTIC_WALKER
    assert "Symbol.for('nbrowser.refs')" in SEMANTIC_WALKER
    assert "cursor === 'pointer'" in SEMANTIC_WALKER
    assert 'input[type="checkbox"], input[type="radio"]' in SEMANTIC_WALKER
    assert "modelContext" in SEMANTIC_WALKER
    assert "TextEncoder" in SEMANTIC_WALKER


def test_view_from_walker_preserves_doc_gen_node_uid_ref_and_webmcp() -> None:
    payload = {
        "url": "https://example.com/app",
        "title": "App",
        "page_hint": "content page",
        "doc_gen": "gen-abc123",
        "elements": [
            {
                "id": 0,
                "ref": "@e1",
                "node_uid": 1,
                "selector": "div:nth-of-type(1)",
                "kind": "button",
                "label": "Custom Card Action",
                "is_visible": True,
            },
            {
                "id": 1,
                "ref": "@e2",
                "node_uid": 2,
                "selector": "label:nth-of-type(1)",
                "kind": "checkbox",
                "label": "Accept terms",
                "checked": True,
                "is_visible": True,
            },
        ],
        "forms": [],
        "visible_text": "Custom Card Action Accept terms",
        "text_blocks": ["Custom Card Action"],
        "state": "ready",
        "webmcp": {
            "experimental": True,
            "untrusted": True,
            "status": "ready",
            "available": True,
            "toolCount": 1,
            "tools": [
                {
                    "name": "search_docs",
                    "description": "Search docs",
                    "origin": "https://example.com",
                    "frameId": "main",
                }
            ],
            "truncated": False,
        },
    }
    view = view_from_walker(payload)
    assert view.doc_gen == "gen-abc123"
    assert [e.ref for e in view.elements] == ["@e1", "@e2"]
    assert [e.node_uid for e in view.elements] == [1, 2]
    assert view.elements[1].checked is True
    assert view.webmcp is not None
    assert view.webmcp["untrusted"] is True
    assert view.webmcp["tools"][0]["name"] == "search_docs"
