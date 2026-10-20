import pytest

from nbrowser.interact import is_local_activation
from nbrowser.semantic import Element, SemanticView


def test_semantic_element_indexing() -> None:
    view = SemanticView(elements=[Element(id=1, kind="button", selector="#b")])
    assert len(view.elements) == 1
    assert view.elements[0].kind == "button"
    assert view.elements[0].selector == "#b"


def test_interaction_activation_gating() -> None:
    from nbrowser.interact import human_mouse_trajectory, named_key_info
    from nbrowser.types import EffectOperation

    class MockInteraction:
        def __init__(self, verb: str, key: str = ""):
            self.verb = verb
            self.key = key

    assert EffectOperation("auth_login") is EffectOperation.auth_login
    for verb in (
        "click",
        "hover",
        "scroll",
        "focus",
        "type",
        "fill_form",
        "clear",
        "select",
        "press_key",
        "submit",
        "auth_login",
    ):
        assert is_local_activation(MockInteraction(verb, key="Enter"))
    assert not is_local_activation(MockInteraction("drag"))

    # Playwright USKeyboardLayout VK_OEM_PERIOD = 190 (never ASCII 46 = VK_DELETE)
    assert named_key_info(".") == (".", "Period", 190, ".")
    assert named_key_info("Enter") == ("Enter", "Enter", 13, "\r")

    pts_a = human_mouse_trajectory(0.0, 0.0, 200.0, 100.0, seed=42)
    pts_b = human_mouse_trajectory(0.0, 0.0, 200.0, 100.0, seed=42)
    pts_c = human_mouse_trajectory(0.0, 0.0, 200.0, 100.0, seed=99)
    assert pts_a == pts_b
    assert pts_a != pts_c
    assert pts_a[-1] == (200.0, 100.0)
    assert len(pts_a) > 4


def test_md_url_fallback_appends_md_to_the_full_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser import extract

    asked: list[str] = []

    def fake_download(url: str) -> tuple[bytes, str, str, str | None]:
        asked.append(url)
        return b"# Guide\n\nBody", "text/markdown", "", None

    monkeypatch.setattr(extract, "download_host_page", fake_download)
    assert extract._try_md_url_fallback("https://docs.example.com/guide.html")
    assert extract._try_md_url_fallback("https://docs.example.com/guide")
    assert extract._try_md_url_fallback("https://docs.example.com/docs/")
    assert asked == [
        "https://docs.example.com/guide.html.md",
        "https://docs.example.com/guide.md",
        "https://docs.example.com/docs/index.html.md",
    ]
    assert extract._try_md_url_fallback("https://docs.example.com/a.md") is None


def test_live_markdown_walker_keeps_document_order() -> None:
    from nbrowser.extract import MARKDOWN_WALKER

    # Each text node belongs to its nearest block, walked in document order:
    # a nested heading opens its own section and a link is emitted once.
    assert "createTreeWalker" in MARKDOWN_WALKER
    assert "closest(BLOCKS)" in MARKDOWN_WALKER
    assert "querySelectorAll('a[href]')" not in MARKDOWN_WALKER
    # A link is emitted once per document, labelled by its text in that block.
    assert "emitted.has(a)" in MARKDOWN_WALKER
    # A whitespace-only piece of a link never spends its one emission.
    assert "if (!lt) continue;" in MARKDOWN_WALKER
    assert "a.textContent" not in MARKDOWN_WALKER
