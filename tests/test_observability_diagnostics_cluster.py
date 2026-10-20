"""Tests for observability and diagnostics tools cluster.

Tools covered:
- nbrowser_console_show  (frames the engine pushes, entering through the double's emit)
- nbrowser_network_show  (Fetch.requestPaused frames, entering through the double's emit)
- nbrowser_token_extract
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from cdp_double import CdpDouble, FakePage

from nbrowser.errors import BrowserError, FailureCode
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession


class FakeObsClient:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any] | None, str | None]] = []
        self.targets: list[dict[str, Any]] = [
            {"targetId": "tab-1", "type": "page", "url": "https://example.com"}
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
                            "palette": ["#ffffff", "#000000"],
                            "fonts": ["16px sans-serif"],
                            "spacing": ["8px", "16px"],
                            "custom_properties": [
                                {"name": "--primary", "value": "#0070f3"}
                            ],
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
def obs_server() -> McpServer:
    server = McpServer()
    client = FakeObsClient()
    sess = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: client
    )
    server.session = sess
    return server


def _double_server() -> tuple[McpServer, CdpDouble]:
    server = McpServer()
    double = CdpDouble(
        [FakePage("http://fixture.test/a", "T", "double text")],
        on_event=server.on_cdp_event,
    )
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    return server, double


def _console(kind: str, session_id: str | None = "s-t0") -> dict[str, Any]:
    event: dict[str, Any] = {
        "method": "Runtime.consoleAPICalled",
        "params": {
            "type": kind,
            "args": [{"type": "string", "value": "never-shown"}],
        },
    }
    if session_id is not None:
        event["sessionId"] = session_id
    return event


def _exception(session_id: str) -> dict[str, Any]:
    return {
        "method": "Runtime.exceptionThrown",
        "sessionId": session_id,
        "params": {"timestamp": 1.0, "exceptionDetails": {"text": "never-shown"}},
    }


def _paused(
    url: str, method: str = "GET", session_id: str | None = "s-t0"
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "method": "Fetch.requestPaused",
        "params": {"requestId": "r", "request": {"url": url, "method": method}},
    }
    if session_id is not None:
        event["sessionId"] = session_id
    return event


def test_nbrowser_console_reads_frames_the_engine_pushes() -> None:
    server, double = _double_server()
    for kind in (
        "log",
        "info",
        "warning",
        "error",
        "debug",
        "assert",
        "startGroup",
        "startGroupCollapsed",
        "endGroup",
        "table",
    ):
        double.emit(_console(kind))
    double.emit(
        {
            "method": "Runtime.exceptionThrown",
            "sessionId": "s-t0",
            "params": {"timestamp": 1.0, "exceptionDetails": {"text": "Uncaught"}},
        }
    )
    res = server.handle_tool_call("nbrowser_console_show", {})
    assert [(e["level"], e["category"]) for e in res["entries"]] == [
        ("info", "log"),
        ("info", "log"),
        ("warning", "log"),
        ("error", "log"),
        ("debug", "log"),
        ("error", "assertion"),
        ("info", "group"),
        ("info", "group"),
        ("info", "group"),
        ("info", "other"),
        ("error", "diagnostic"),
    ]
    assert res["taint"] == "page_derived"
    assert "never-shown" not in str(res)


def test_nbrowser_console_ring_holds_the_last_200() -> None:
    server, double = _double_server()
    for _ in range(201):
        double.emit(_console("log"))
    double.emit(_console("error"))
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    assert len(entries) == 200
    assert entries[-1] == {"level": "error", "category": "log"}


def test_console_ring_of_one_tab_does_not_evict_another_tab() -> None:
    server, double = _double_server()
    for _ in range(200):
        double.emit(_console("log", "s-tab-a"))
    for _ in range(200):
        double.emit(_console("error", "s-tab-b"))
    # Storage: each sessionId keeps its own full ring, so a busy tab does not
    # evict another tab's stored entries.
    assert len(server.console_buffer.rings["s-tab-a"]) == 200
    assert len(server.console_buffer.rings["s-tab-b"]) == 200
    # Read: capped at the console ceiling, newest last, and what the caller
    # sees holds both tabs: the merged read takes each tab's entries.
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    assert len(entries) == 200
    assert entries.count({"level": "info", "category": "log"}) == 100
    assert entries.count({"level": "error", "category": "log"}) == 100
    assert entries[-1] == {"level": "error", "category": "log"}


def test_console_read_represents_every_session_at_the_ring_ceiling() -> None:
    server, double = _double_server()
    # 32 sessions at the console ceiling each. The session attached first,
    # s-0, is the one a global newest cut would drop, so it carries the only
    # error/diagnostic entries in the read.
    for _ in range(200):
        double.emit(_exception("s-0"))
    for sid in range(1, 32):
        for _ in range(200):
            double.emit(_console("log", f"s-{sid}"))
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    assert len(entries) == 200
    assert entries.count({"level": "error", "category": "diagnostic"}) >= 6


def test_console_events_with_no_session_id_share_one_ring() -> None:
    server, double = _double_server()
    for _ in range(201):
        double.emit(_console("log", None))
    double.emit(_console("error", None))
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    assert len(entries) == 200
    assert entries[-1] == {"level": "error", "category": "log"}


def test_nbrowser_network_reads_paused_requests_and_skips_non_http() -> None:
    server, double = _double_server()
    double.emit(_paused("https://example.com/api/data?token=secret"))
    double.emit(_paused("data:text/plain,hi"))
    double.emit(_paused("blob:https://example.com/0f7b"))
    double.emit(_paused("about:blank"))
    double.emit(_paused("https://example.com/submit", "PROPFIND"))
    double.emit(_paused("http://[bad"))
    double.emit(
        {
            "method": "Fetch.requestPaused",
            "sessionId": "s-t0",
            "params": {"requestId": "r"},
        }
    )
    res = server.handle_tool_call("nbrowser_network_show", {})
    assert [r["method"] for r in res["requests"]] == ["get", "other"]
    assert res["requests"][0]["location"].startswith("https://example.com/api/data")
    assert "secret" not in res["requests"][0]["location"]
    assert "status" not in res["requests"][0]
    assert res["requests"][1]["location"] == "https://example.com/submit"
    assert res["taint"] == "network_metadata"


def test_nbrowser_network_ring_holds_the_last_500() -> None:
    server, double = _double_server()
    for i in range(501):
        double.emit(_paused(f"https://example.com/{i}"))
    requests = server.handle_tool_call("nbrowser_network_show", {})["requests"]
    assert len(requests) == 500
    assert requests[0]["location"] == "https://example.com/1"
    assert requests[-1]["location"] == "https://example.com/500"


def test_network_ring_of_one_tab_does_not_evict_another_tab() -> None:
    server, double = _double_server()
    for _ in range(500):
        double.emit(_paused("https://example.com/a", session_id="s-tab-a"))
    for i in range(500):
        double.emit(_paused(f"https://example.com/b{i}", session_id="s-tab-b"))
    # Storage: each sessionId keeps its own full ring, so a busy tab does not
    # evict another tab's stored entries.
    assert len(server.network_entries["s-tab-a"]) == 500
    assert len(server.network_entries["s-tab-b"]) == 500
    # Read: capped at the network ceiling, newest last, and what the caller
    # sees holds both tabs: 250 entries of each ring.
    requests = server.handle_tool_call("nbrowser_network_show", {})["requests"]
    assert len(requests) == 500
    assert sum(1 for r in requests if r["location"] == "https://example.com/a") == 250
    assert requests[0]["location"] == "https://example.com/a"
    assert requests[-1]["location"] == "https://example.com/b499"


def test_network_read_represents_every_session_at_the_ring_ceiling() -> None:
    server, double = _double_server()
    locations = [f"https://example.com/s{sid}" for sid in range(32)]
    for sid, location in enumerate(locations):
        for _ in range(500):
            double.emit(_paused(location, session_id=f"s-{sid}"))
    requests = server.handle_tool_call("nbrowser_network_show", {})["requests"]
    assert len(requests) == 500
    for location in locations:
        assert sum(1 for r in requests if r["location"] == location) >= 15


def test_console_read_is_capped_and_newest_last_across_sessions() -> None:
    server, double = _double_server()
    # Interleave two sessions: 300 events recorded, two rings, alternating
    # log on s-a and error on s-b.
    for _ in range(150):
        double.emit(_console("log", "s-a"))
        double.emit(_console("error", "s-b"))
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    # The read returns the merged ceiling, not the 300 stored events, and its
    # last entry is the newest event (the final error on s-b).
    assert len(entries) == 200
    assert entries[-1] == {"level": "error", "category": "log"}


def test_network_read_is_capped_and_newest_last_across_sessions() -> None:
    server, double = _double_server()
    for i in range(700):
        sid = "s-a" if i % 2 == 0 else "s-b"
        double.emit(_paused(f"https://example.com/{i}", session_id=sid))
    requests = server.handle_tool_call("nbrowser_network_show", {})["requests"]
    # 700 events recorded across two rings, but the read returns at most 500,
    # ordered so the last entry is the newest event.
    assert len(requests) == 500
    assert requests[-1]["location"] == "https://example.com/699"


def test_eviction_drops_the_ring_written_least_recently() -> None:
    server, double = _double_server()
    # The tab that attached first keeps working between short-lived sessions.
    for _ in range(10):
        double.emit(_console("error", "s-live"))
        double.emit(_paused("https://example.com/live", session_id="s-live"))
    for i in range(31):
        double.emit(_console("log", f"s-{i}"))
        double.emit(_paused(f"https://example.com/{i}", session_id=f"s-{i}"))
    # 32 rings held. The live tab writes last, so its ring is the freshest.
    double.emit(_console("error", "s-live"))
    double.emit(_paused("https://example.com/live", session_id="s-live"))
    # A 33rd session forces one ring out: the one written least recently.
    double.emit(_console("log", "s-last"))
    double.emit(_paused("https://example.com/last", session_id="s-last"))
    assert len(server.console_buffer.rings) == 32
    assert "s-live" in server.console_buffer.rings
    assert "s-0" not in server.console_buffer.rings
    assert "s-30" in server.console_buffer.rings
    assert server.network_entries.keys() == server.console_buffer.rings.keys()
    entries = server.handle_tool_call("nbrowser_console_show", {})["entries"]
    assert {"level": "error", "category": "log"} in entries
    requests = server.handle_tool_call("nbrowser_network_show", {})["requests"]
    assert any(r["location"] == "https://example.com/live" for r in requests)


def test_disposed_session_leaves_no_console_or_network_ring() -> None:
    server, double = _double_server()
    sess = server.session
    assert sess is not None
    ctx = sess.context_open()
    tab = sess.tabs_open("http://fixture.test/b", ctx)
    sid = f"s-{tab}"
    double.emit(_console("log", sid))
    double.emit(_paused("https://example.com/x", session_id=sid))
    assert server.handle_tool_call("nbrowser_console_show", {})["entries"] != []
    assert server.handle_tool_call("nbrowser_network_show", {})["requests"] != []
    sess.context_dispose(ctx)
    # Disposing the context detaches the tab's session; its rings are gone.
    assert server.console_buffer.rings.get(sid) is None
    assert server.network_entries.get(sid) is None
    assert server.handle_tool_call("nbrowser_console_show", {})["entries"] == []
    assert server.handle_tool_call("nbrowser_network_show", {})["requests"] == []


def test_on_cdp_event_drops_what_it_cannot_read_and_never_raises() -> None:
    server, double = _double_server()
    double.emit(
        {"method": "Runtime.consoleAPICalled", "sessionId": "s-t0", "params": "junk"}
    )
    double.emit(
        {
            "method": "Page.loadEventFired",
            "sessionId": "s-t0",
            "params": {"timestamp": 1.0},
        }
    )
    double.emit({"params": {"type": "log"}})
    assert server.handle_tool_call("nbrowser_console_show", {})["entries"] == []
    assert server.handle_tool_call("nbrowser_network_show", {})["requests"] == []


def test_get_session_wires_the_hook_into_the_real_session() -> None:
    server = McpServer()
    with patch("nbrowser.mcp_server.BrowserSession") as fake:
        server.get_session()
    assert fake.call_args.kwargs["on_event"] == server.on_cdp_event


def test_nbrowser_tokens(obs_server: McpServer) -> None:
    res = obs_server.handle_tool_call("nbrowser_token_extract", {})
    assert "palette" in res
    assert "#ffffff" in res["palette"]
    assert "fonts" in res
    assert "spacing" in res
    assert "custom_properties" in res
    assert res["custom_properties"][0]["name"] == "--primary"


def test_observability_edge_cases(obs_server: McpServer) -> None:
    # 1. nbrowser_token_extract without active tabs
    sess = obs_server.get_session()
    cast_client: Any = sess.client
    cast_client.targets = []
    with pytest.raises(BrowserError) as exc_notabs:
        obs_server.handle_tool_call("nbrowser_token_extract", {})
    assert exc_notabs.value.code == FailureCode.NO_ACTIVE_SESSION
