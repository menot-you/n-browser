"""Tests for the session and tab management cluster, over the CDP double.

Tools covered: nbrowser_tab_list, nbrowser_session_show.

Every assertion is about TRAFFIC — which CDP method, with which params, on
which session — or about a typed refusal that produced no traffic at all.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import patch

import pytest
from cdp_double import CdpDouble, FakePage

from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession, CdpPipeClient

HOME = FakePage("https://example.com/home", "Home", "home")


def test_navigate_waits_for_its_own_load_before_snapshot() -> None:
    class QueuedDouble(CdpDouble):
        def __init__(self) -> None:
            super().__init__([FakePage(HOME.url, HOME.title, HOME.text)])
            self.cond = threading.Condition()
            self.events: list[dict[str, Any]] = []
            self.loaded = False

        def send(
            self,
            method: str,
            params: dict[str, Any] | None = None,
            session_id: str | None = None,
            timeout: float = 30.0,
        ) -> dict[str, Any]:
            if method != "Page.navigate":
                return super().send(method, params, session_id, timeout)
            self.sent.append((method, params or {}, session_id))
            self.events.extend(
                [
                    {
                        "method": "Page.loadEventFired",
                        "sessionId": sid,
                        "params": {"timestamp": 1},
                    }
                    for sid in ("s-other", session_id)
                ]
                + [
                    {
                        "method": "Page.lifecycleEvent",
                        "sessionId": sid,
                        "params": {
                            "name": name,
                            "frameId": frame,
                            "loaderId": loader,
                            "timestamp": timestamp,
                        },
                    }
                    for sid, name, frame, loader, timestamp in (
                        ("s-other", "load", "frame", "current", 2),
                        (session_id, "load", "frame", "previous", 3),
                        (session_id, "load", "child", "current", 4),
                        (session_id, "DOMContentLoaded", "frame", "current", 5),
                        (session_id, "load", "frame", "current", 6),
                    )
                ]
            )
            return {"frameId": "frame", "loaderId": "current"}

        def wait_event(
            self,
            method: str,
            session_id: str | None = None,
            timeout: float = 15.0,
            **kwargs: Any,
        ) -> dict[str, Any]:
            result = CdpPipeClient.wait_event(
                self, method, session_id, timeout=0.1, **kwargs
            )
            self.loaded = result.get("timestamp") == 6
            if self.loaded:
                self.targets["t0"] = FakePage("https://example.com/a", "A", "a")
            return result

    server = McpServer()
    double = QueuedDouble()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: double
    )
    server.session.navigate("t0", "https://example.com/a")
    assert double.loaded, "navigate returned on an earlier or unrelated load event"
    view = server.handle_tool_call("nbrowser_page_snapshot", {})["view"]
    assert (view["url"], view["title"]) == ("https://example.com/a", "A")


def test_failed_navigation_preserves_the_selected_page() -> None:
    server, double = _double_server(
        [HOME, FakePage("https://example.com/other", "Other", "other")]
    )
    session = server.get_session()
    send = double.send

    def fail_navigation(
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        if method == "Page.navigate":
            return {"errorText": "net::ERR_FAILED"}
        return send(method, params, session_id, timeout)

    with (
        patch.object(double, "send", side_effect=fail_navigation),
        pytest.raises(BrowserError, match="CDP navigation failed") as error,
    ):
        session.navigate("t1", "https://example.com/unreachable")
    assert error.value.code == ClosedFailure.PROTOCOL
    view = server.handle_tool_call("nbrowser_page_snapshot", {})["view"]
    assert (view["url"], view["title"]) == (HOME.url, HOME.title)


def _double_server(
    pages: list[FakePage] | None = None,
) -> tuple[McpServer, CdpDouble]:
    server = McpServer()
    double = CdpDouble([HOME] if pages is None else pages, on_event=server.on_cdp_event)
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    return server, double


def _methods(double: CdpDouble) -> list[str]:
    return [m for m, _, _ in double.sent]


def test_nbrowser_tabs_list_projects_origin_only() -> None:
    server, double = _double_server(
        [
            FakePage("https://example.com/home?token=secret", "Home", "home"),
            FakePage("https://auth.example.com/login", "Login", "login"),
        ]
    )
    res = server.handle_tool_call("nbrowser_tab_list", {})
    assert res == {
        "tabs": [
            {"tab_id": "t0", "origin": "https://example.com"},
            {"tab_id": "t1", "origin": "https://auth.example.com"},
        ]
    }
    assert _methods(double) == ["Target.getTargets"]


def test_nbrowser_session_get_counts_tabs_and_lets_the_error_travel() -> None:
    server, double = _double_server()
    assert server.handle_tool_call("nbrowser_session_show", {}) == {
        "active": True,
        "tabs_count": 1,
    }
    assert _methods(double) == ["Target.getTargets"]
    assert McpServer().handle_tool_call("nbrowser_session_show", {}) == {
        "active": False,
        "tabs_count": 0,
    }
    server.get_session().client = None
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_session_show", {})
    assert exc.value.code == ClosedFailure.BROWSER_CLOSED


def test_closed_session_context_operations_refuse_without_cdp_traffic() -> None:
    server, double = _double_server()
    session = server.get_session()
    context = session.context_open()
    session.context_dispose(context)
    assert double.contexts == []
    session.close_session()
    sent = list(double.sent)
    for operation in (session.context_open, lambda: session.context_dispose(context)):
        with pytest.raises(BrowserError) as exc:
            operation()
        assert exc.value.code == ClosedFailure.BROWSER_CLOSED
        assert exc.value.message == "No client"
    assert double.sent == sent
    assert session.client is None and session.closed
