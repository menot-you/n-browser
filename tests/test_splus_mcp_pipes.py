"""MCP consumers of native pipe evidence and provider preflight."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from test_ssrf_runtime import _Engine

from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession


def test_provider_tools_without_credentials_never_open_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "ZAI_API_KEY",
        "MINIMAX_API_KEY",
        "TAVILY_API_KEY",
        "FIRECRAWL_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    server = McpServer()
    try:
        result = server.handle_tool_call(
            "nbrowser_web_search", {"query": "fixture", "max_results": 999}
        )
        assert result["hits"] == []
        assert result["estimated_tokens"] == 0
        assert len(result["lanes"]) == 4
        assert {lane["status"] for lane in result["lanes"]} == {"skipped_no_key"}
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("nbrowser_web_search", {})
        assert exc.value.code is InputFailure.QUERY
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("unknown-tool", {})
        assert exc.value.code is InputFailure.OPERATION
    finally:
        server.close()


@pytest.mark.parametrize("fmt", ["prompt", "markdown", "design", "components", "lost"])
def test_scrape_formats_consume_correlated_pipe_evidence(fmt: str) -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    view = {
        "url": "https://fixture.test",
        "title": "Fixture",
        "visible_text": "hello",
        "elements": [],
        "text_blocks": ["hello"],
    }
    evaluated: object = "# Fixture\n\nhello" if fmt == "markdown" else {"layout": []}
    replies: list[tuple[str, dict[str, Any]]] = [
        ("Target.getTargets", {"targetInfos": [{"targetId": "t1", "type": "page"}]}),
        ("Target.attachToTarget", {"sessionId": "s1"}),
        ("Fetch.enable", {}),
        ("Runtime.enable", {}),
        ("Runtime.evaluate", {"result": {"value": view}}),
        (
            "Target.getTargets",
            {
                "targetInfos": []
                if fmt == "lost"
                else [{"targetId": "t1", "type": "page"}]
            },
        ),
    ]
    if fmt not in ("prompt", "lost"):
        replies.append(("Runtime.evaluate", {"result": {"value": evaluated}}))

    def respond() -> None:
        for method, result in replies:
            frame = engine.frame()
            assert frame["method"] == method
            engine.emit({"id": frame["id"], "result": result})

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(respond)
            if fmt == "lost":
                with pytest.raises(BrowserError) as exc:
                    server.handle_tool_call(
                        "nbrowser_page_scrape", {"format": "prompt"}
                    )
                assert exc.value.code is FailureCode.NO_ACTIVE_SESSION
                future.result(timeout=5)
                return
            result = server.handle_tool_call("nbrowser_page_scrape", {"format": fmt})
            future.result(timeout=5)
        if fmt == "prompt":
            assert result == {
                "format": "prompt",
                "prompt": "hello",
                "estimated_tokens": {"prompt": 2},
                "truncated": False,
            }
        elif fmt == "markdown":
            assert result["markdown"] == "# Fixture\n\nhello"
            assert result["truncated"] is False
        elif fmt == "design":
            assert result["schema"] == "nbrowser.design.v1"
            assert result["layout"] == []
        else:
            assert result["schema"] == "nbrowser.components.v1"
            assert result["components"] == []
        assert server.last_snapshot is not None
        assert server.last_snapshot.view.title == "Fixture"
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize(
    "params",
    [
        {"urls": [], "mode": "auto"},
        {"urls": ["https://fixture.test"], "mode": "invalid"},
        {"urls": ["https://fixture.test"] * 51},
        {"urls": "https://fixture.test"},
    ],
)
def test_extract_invalid_batch_refuses_before_transport(
    params: dict[str, object],
) -> None:
    server = McpServer()
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("nbrowser_page_extract", params)
        assert exc.value.code is InputFailure.OPERATION
        assert server.session is None
    finally:
        server.close()


@pytest.mark.parametrize("large", [False, True])
def test_document_browser_mode_closes_context_and_spills_large_text(
    large: bool,
) -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    markdown = "m" * (2000 if large else 5)
    replies = [
        ("Target.createBrowserContext", {"browserContextId": "c1"}),
        ("Target.createTarget", {"targetId": "t1"}),
        ("Target.attachToTarget", {"sessionId": "s1"}),
        ("Fetch.enable", {}),
        ("Runtime.enable", {}),
        ("Page.enable", {}),
        ("Page.setLifecycleEventsEnabled", {}),
        ("Page.addScriptToEvaluateOnNewDocument", {"identifier": "1"}),
        ("Page.navigate", {"frameId": "f1", "loaderId": "l1"}),
        ("Runtime.evaluate", {"result": {"value": markdown}}),
        ("Target.disposeBrowserContext", {}),
        ("Target.getTargets", {"targetInfos": []}),
    ]

    def respond() -> None:
        for method, result in replies:
            frame = engine.frame()
            assert frame["method"] == method
            if method == "Target.createTarget":
                assert frame["params"] == {
                    "url": "about:blank",
                    "browserContextId": "c1",
                }
            engine.emit({"id": frame["id"], "result": result})
            if method == "Page.navigate":
                engine.emit(
                    {
                        "method": "Page.lifecycleEvent",
                        "sessionId": "s1",
                        "params": {"name": "load", "frameId": "f1", "loaderId": "l1"},
                    }
                )

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(respond)
            result = server.handle_tool_call(
                "nbrowser_page_extract",
                {
                    "urls": ["https://fixture.test/a"],
                    "mode": "browser",
                    "max_content_bytes": 1024 if large else None,
                },
            )
            future.result(timeout=5)
        if large:
            assert "documents" not in result
            assert result["artifacts"]["documents"]["bytes"] > 2000
            assert (
                result["artifacts"]["documents"]["ref"]
                == result["artifacts"]["documents"]["sha256"]
            )
        else:
            assert result["documents"] == [
                {
                    "url": "https://fixture.test/a",
                    "mode_used": "browser",
                    "markdown": markdown,
                }
            ]
        assert server.session._tab_sessions == {}
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize(
    "tool,params",
    [
        ("nbrowser_page_snapshot", {}),
        ("nbrowser_page_interact", {"verb": "click"}),
        ("nbrowser_page_scrape", {}),
    ],
)
def test_observation_consumers_refuse_empty_native_target_list(
    tool: str, params: dict[str, object]
) -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    engine.emit({"id": 1, "result": {"targetInfos": []}})
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(tool, params)
        assert exc.value.code is FailureCode.NO_ACTIVE_SESSION
        assert engine.frame()["method"] == "Target.getTargets"
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)


def test_tabs_list_filters_nonpages_and_preserves_redacted_origin() -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    engine.emit(
        {
            "id": 1,
            "result": {
                "targetInfos": [
                    {"type": "worker", "targetId": "w1"},
                    {
                        "type": "page",
                        "targetId": "t1",
                        "url": "https://user:secret@fixture.test/a?token=secret",
                    },
                    {"type": "page", "targetId": "t2", "url": ""},
                ]
            },
        }
    )
    try:
        assert server.handle_tool_call("nbrowser_tab_list", {}) == {
            "tabs": [
                {"tab_id": "t1", "origin": "https://fixture.test"},
                {"tab_id": "t2", "origin": ""},
            ]
        }
        assert engine.frame()["method"] == "Target.getTargets"
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)


def test_scrape_unsupported_format_refuses_before_session_creation() -> None:
    server = McpServer()
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("nbrowser_page_scrape", {"format": "unsupported"})
        assert exc.value.code is InputFailure.OPERATION
        assert server.session is None
    finally:
        server.close()


def test_pipe_interaction_false_result_is_a_selector_refusal() -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    replies = [
        ("Target.getTargets", {"targetInfos": [{"targetId": "t1", "type": "page"}]}),
        ("Target.attachToTarget", {"sessionId": "s1"}),
        ("Fetch.enable", {}),
        ("Runtime.enable", {}),
        ("Runtime.evaluate", {"result": {"value": "https://fixture.test/a"}}),
        ("Runtime.evaluate", {"result": {"value": False}}),
    ]

    def respond() -> None:
        for method, result in replies:
            frame = engine.frame()
            assert frame["method"] == method
            engine.emit({"id": frame["id"], "result": result})

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(respond)
            with pytest.raises(BrowserError) as exc:
                server.handle_tool_call(
                    "nbrowser_page_interact", {"verb": "click", "selector": "#absent"}
                )
            assert exc.value.code is InputFailure.SELECTOR
            future.result(timeout=5)
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("existing", [False, True])
def test_navigate_dispatch_uses_active_tab_or_creates_blank_tab(existing: bool) -> None:
    engine = _Engine()
    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(), client_factory=lambda: engine.client
    )
    replies = [
        (
            "Target.getTargets",
            {"targetInfos": [{"targetId": "t1", "type": "page"}] if existing else []},
        )
    ]
    if not existing:
        replies.append(("Target.createTarget", {"targetId": "t1"}))
    replies.extend(
        [
            ("Target.attachToTarget", {"sessionId": "s1"}),
            ("Fetch.enable", {}),
            ("Runtime.enable", {}),
            ("Page.enable", {}),
            ("Page.setLifecycleEventsEnabled", {}),
            ("Page.addScriptToEvaluateOnNewDocument", {"identifier": "1"}),
            ("Page.navigate", {"frameId": "f1", "loaderId": "l1"}),
        ]
    )

    def respond() -> None:
        for method, result in replies:
            frame = engine.frame()
            assert frame["method"] == method
            if method == "Target.createTarget":
                assert frame["params"] == {"url": "about:blank"}
            if method == "Page.navigate":
                assert frame["params"] == {"url": "https://fixture.test/a"}
            engine.emit({"id": frame["id"], "result": result})
            if method == "Page.navigate":
                engine.emit(
                    {
                        "method": "Page.lifecycleEvent",
                        "sessionId": "s1",
                        "params": {"name": "load", "frameId": "f1", "loaderId": "l1"},
                    }
                )

    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("nbrowser_page_navigate", {})
        assert exc.value.code is InputFailure.OPERATION
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(respond)
            assert server.handle_tool_call(
                "nbrowser_page_navigate", {"host_url": "https://fixture.test/a"}
            ) == {"status": "navigated", "url": "https://fixture.test/a"}
            future.result(timeout=5)
    finally:
        server.close()
        engine.close()
        engine.client.reader_thread.join(timeout=2)
