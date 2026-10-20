"""Branch tests for mcp_server.py handlers no cluster file owns:
nbrowser_page_extract text branches, the retired research tool."""

from __future__ import annotations

from typing import Any

import pytest
from nott_spine import ReceiptRung, TaintClass

from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.extract import SnapshotEvidence
from nbrowser.mcp_server import McpServer
from nbrowser.semantic import SemanticView
from nbrowser.session import BrowserLaunchConfig, BrowserSession


class FakePatchClient:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any] | None, str | None]] = []
        self.targets: list[dict[str, Any]] = [
            {"targetId": "tab-1", "type": "page", "url": "https://example.com/p"}
        ]

    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        self.sent.append((method, params, session_id))
        if method == "Target.getTargets":
            return {"targetInfos": self.targets}
        if method == "Target.attachToTarget":
            return {"sessionId": "sess-tab-1"}
        if method == "Runtime.evaluate":
            return {
                "result": {
                    "value": {
                        "viewport": {"width": 1280, "height": 720, "dpr": 1.0},
                        "theme": {
                            "palette": ["#ffffff"],
                            "fonts": ["14px"],
                            "spacing": ["4px"],
                            "custom_properties": [{"name": "--c", "value": "#111"}],
                        },
                        "layout": [],
                        "assets": [],
                        "svgs": [],
                        "animations": {"animated": [], "keyframes": []},
                    }
                }
            }
        return {}

    def wait_event(
        self, event_name: str, session_id: str | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {}

    def close(self) -> None:
        pass


@pytest.fixture
def patch_server() -> McpServer:
    server = McpServer()
    client = FakePatchClient()
    sess = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: client
    )
    server.session = sess
    return server


def test_extract_branches(patch_server: McpServer) -> None:
    # 1. urls is None and self.last_snapshot is None -> snapshots automatically
    patch_server.last_snapshot = None
    res_snap = patch_server.handle_tool_call("nbrowser_page_extract", {"what": ""})
    assert "matches" in res_snap

    # 2. self.last_snapshot has view as None -> raises NO_ACTIVE_SESSION
    patch_server.last_snapshot = SnapshotEvidence(
        view=None,  # type: ignore[arg-type]
        digest="d",
        taint=TaintClass.PageDerived,
        rung=ReceiptRung.UnwitnessedLocal,
        instruction_policy="redact",
    )
    with pytest.raises(BrowserError) as exc_noview:
        patch_server.handle_tool_call("nbrowser_page_extract", {})
    assert exc_noview.value.code == FailureCode.NO_ACTIVE_SESSION

    # 3. matching what found in text_blocks
    view_match = SemanticView(
        url="https://example.com", text_blocks=["Target Alpha", "Beta"]
    )
    patch_server.last_snapshot = SnapshotEvidence(
        view=view_match,
        digest="d",
        taint=TaintClass.PageDerived,
        rung=ReceiptRung.UnwitnessedLocal,
        instruction_policy="redact",
    )
    res_m = patch_server.handle_tool_call("nbrowser_page_extract", {"what": "Alpha"})
    assert len(res_m["matches"]) == 1
    assert "Alpha" in res_m["matches"][0]

    # 4. what given but no matches in text_blocks, falls back to visible_text
    view_fb = SemanticView(
        url="https://example.com",
        text_blocks=["Alpha"],
        visible_text="Fallback Text Content",
    )
    patch_server.last_snapshot = SnapshotEvidence(
        view=view_fb,
        digest="d2",
        taint=TaintClass.PageDerived,
        rung=ReceiptRung.UnwitnessedLocal,
        instruction_policy="redact",
    )
    res_fb = patch_server.handle_tool_call("nbrowser_page_extract", {"what": "Gamma"})
    assert res_fb["matches"] == ["Fallback Text Content"]

    # 5. what given, no matches in text_blocks, and visible_text is empty
    view_novis = SemanticView(
        url="https://example.com", text_blocks=["Alpha"], visible_text=""
    )
    patch_server.last_snapshot = SnapshotEvidence(
        view=view_novis,
        digest="d3",
        taint=TaintClass.PageDerived,
        rung=ReceiptRung.UnwitnessedLocal,
        instruction_policy="redact",
    )
    res_novis = patch_server.handle_tool_call(
        "nbrowser_page_extract", {"what": "Gamma"}
    )
    assert res_novis["matches"] == []

    # 6. max_content_bytes provided
    res_art = patch_server.handle_tool_call(
        "nbrowser_page_extract", {"max_content_bytes": 1024}
    )
    assert "matches" in res_art


def test_research_is_no_longer_served(patch_server: McpServer) -> None:
    with pytest.raises(BrowserError) as exc_res:
        patch_server.handle_tool_call("nbrowser_web_research", {})
    assert exc_res.value.code == InputFailure.OPERATION
