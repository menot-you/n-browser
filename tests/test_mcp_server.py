import pytest

from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.mcp_server import TOOL_NAMES, McpServer


def test_all_14_tools_callable() -> None:
    server = McpServer()
    assert len(server.tools) == 14
    # The tools with a real dispatch branch; the loop below is the ratchet for
    # the next declared-but-unbuilt name.
    implemented = (
        "nbrowser_page_capture",
        "nbrowser_console_show",
        "nbrowser_content_show",
        "nbrowser_site_crawl",
        "nbrowser_page_extract",
        "nbrowser_page_interact",
        "nbrowser_page_navigate",
        "nbrowser_network_show",
        "nbrowser_page_scrape",
        "nbrowser_session_show",
        "nbrowser_page_snapshot",
        "nbrowser_tab_list",
        "nbrowser_token_extract",
        "nbrowser_web_search",
    )
    for t in server.tools:
        if t["name"] in implemented:
            continue
        with pytest.raises(BrowserError) as exc_info:
            server.handle_tool_call(str(t["name"]), {})
        assert exc_info.value.code == FailureCode.NOT_IMPLEMENTED


def test_undeclared_tool_is_refused_by_name() -> None:
    server = McpServer()
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_ghost", {})
    assert exc.value.code is InputFailure.OPERATION
    assert exc.value.message == "Tool nbrowser_ghost not found"


def test_declared_tool_without_a_branch_refuses_not_implemented(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every declared name has a branch today; declaring one the dispatch does
    # not know is the only way to reach its exhaustive refusal.
    monkeypatch.setattr(
        "nbrowser.mcp_server.TOOL_NAMES", [*TOOL_NAMES, "nbrowser_ghost"]
    )
    server = McpServer()
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_ghost", {})
    assert exc.value.code is FailureCode.NOT_IMPLEMENTED
    assert exc.value.message == "Tool nbrowser_ghost is not implemented yet"


def test_nbrowser_navigate_ssrf_guard_rejection() -> None:
    server = McpServer()

    # Pass a private IP (IMDS or RFC1918)
    with pytest.raises(BrowserError) as exc_info:
        server.handle_tool_call(
            "nbrowser_page_navigate",
            {"host_url": "http://169.254.169.254/latest/meta-data"},
        )
    assert exc_info.value.code == FailureCode.GRANT_REQUIRED

    with pytest.raises(BrowserError) as exc_info:
        server.handle_tool_call(
            "nbrowser_page_navigate", {"host_url": "http://192.168.1.1/"}
        )
    assert exc_info.value.code == FailureCode.GRANT_REQUIRED


def test_nbrowser_snapshot() -> None:
    """Snapshot over the §31 protocol double: the walker payload rides the
    same path the real CDP answers, on any host."""
    from cdp_double import CdpDouble, FakePage

    from nbrowser.session import BrowserLaunchConfig, BrowserSession

    server = McpServer()
    pages = [FakePage("http://fixture.test/a", "T", "double text")]
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True),
        client_factory=lambda: CdpDouble(pages),
    )
    res = server.handle_tool_call("nbrowser_page_snapshot", {"include_cards": False})
    assert "view" in res
    assert "digest" in res
    assert server.last_snapshot is not None


@pytest.mark.parametrize("params", [{}, {"ref": ""}], ids=["missing", "empty"])
def test_content_get_requires_nonempty_ref(params: dict[str, str]) -> None:
    server = McpServer()
    try:
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call("nbrowser_content_show", params)
        assert exc.value.code is InputFailure.CONTENT_REF
        assert exc.value.message == "ref is required"
    finally:
        server.close()


def test_content_get_pages_text_and_consumes_only_at_end() -> None:
    server = McpServer()
    text = "é🦉" * 25000
    ref = server._stage_artifact(text)
    first = server.handle_tool_call("nbrowser_content_show", {"ref": ref})
    assert len(first.get("content", "")) == 20000
    assert first["content"] == text[:20000]
    assert first["offset"] == 0
    assert first["next_offset"] == 20000
    assert first["total_chars"] == 50000
    assert server.resolver.holds(ref)
    last = server.handle_tool_call(
        "nbrowser_content_show", {"ref": ref, "offset": 20000, "max_chars": 50000}
    )
    assert last["content"] == text[20000:]
    assert last["offset"] == 20000
    assert last["next_offset"] is None
    assert last["total_chars"] == 50000
    assert not server.resolver.holds(ref)
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_content_show", {"ref": ref})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE


def test_content_get_clamps_max_chars() -> None:
    server = McpServer()
    ref = server._stage_artifact("x" * 200001)
    page = server.handle_tool_call(
        "nbrowser_content_show", {"ref": ref, "max_chars": 999999}
    )
    assert len(page.get("content", "")) == 200000
    assert page["next_offset"] == 200000
    assert page["total_chars"] == 200001


def test_content_get_default_applies_to_later_pages() -> None:
    server = McpServer()
    ref = server._stage_artifact("x" * 50000)
    page = server.handle_tool_call(
        "nbrowser_content_show", {"ref": ref, "offset": 20000}
    )
    assert len(page.get("content", "")) == 20000
    assert page["offset"] == 20000
    assert page["next_offset"] == 40000


@pytest.mark.parametrize("offset", [0, 5])
def test_content_get_end_offset_returns_empty_text(offset: int) -> None:
    server = McpServer()
    ref = server._stage_artifact("x" * offset)
    page = server.handle_tool_call(
        "nbrowser_content_show", {"ref": ref, "offset": offset}
    )
    assert page.get("content") == ""
    assert page["offset"] == offset
    assert page["next_offset"] is None
    assert page["total_chars"] == offset


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("offset", 6),
        ("offset", -1),
        ("offset", True),
        ("offset", 1.5),
        ("offset", "1"),
        ("offset", None),
        ("max_chars", 0),
        ("max_chars", -1),
        ("max_chars", True),
        ("max_chars", 1.5),
        ("max_chars", "1"),
        ("max_chars", None),
    ],
)
def test_content_get_invalid_paging_preserves_ref(field: str, value: object) -> None:
    import json

    server = McpServer()
    ref = server._stage_artifact("hello")
    reply = {
        "result": server.call_tool("nbrowser_content_show", {"ref": ref, field: value})
    }
    assert reply["result"].get("isError") is True
    assert json.loads(reply["result"]["content"][0]["text"])["code"] == "invalid_input"
    assert server.resolver.holds(ref)


def test_content_get_refuses_capture_without_inlining_bytes() -> None:
    import json

    from cdp_double import CdpDouble, FakePage

    from nbrowser.session import BrowserLaunchConfig, BrowserSession

    server = McpServer()
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True),
        client_factory=lambda: CdpDouble(
            [FakePage("http://fixture.test/a", "T", "text")]
        ),
    )
    try:
        shot = server.handle_tool_call(
            "nbrowser_page_capture", {"retention": "no_store"}
        )
        reply = {
            "result": server.call_tool("nbrowser_content_show", {"ref": shot["ref"]})
        }
        assert reply["result"].get("isError") is True
        payload = json.loads(reply["result"]["content"][0]["text"])
        assert payload["code"] == "content_unavailable"
        assert "PNG" not in json.dumps(reply)
        assert not server.resolver.holds(shot["ref"])
        with pytest.raises(BrowserError, match="capture"):
            server.handle_tool_call("nbrowser_content_show", {"ref": shot["ref"]})
    finally:
        server.close()


@pytest.mark.parametrize("urls", ["http://127.0.0.1/", {}, 7])
def test_extract_refuses_non_list_urls_before_starting_a_session(urls: object) -> None:
    from nbrowser.errors import InputFailure

    server = McpServer()
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_page_extract", {"urls": urls})
    assert exc.value.code == InputFailure.OPERATION
    assert exc.value.message == "urls must be a list"
    assert server.session is None


def test_web_search_schema_advertises_integer_max_results() -> None:
    from nbrowser.mcp_server import INPUT_SCHEMAS

    spec = INPUT_SCHEMAS["nbrowser_web_search"]["properties"]["max_results"]
    assert spec["type"] == "integer"
    assert spec["default"] == 10


def test_web_search_null_and_zero_max_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser.providers.base import LaneReport, LaneStatus, SearchHit

    seen: list[int] = []

    def fake_fan_out(
        query: str, max_results: int
    ) -> tuple[list[SearchHit], list[LaneReport]]:
        seen.append(max_results)
        hits = [
            SearchHit(title=f"t{i}", url=f"https://e.com/{i}")
            for i in range(max_results)
        ]
        return hits, [
            LaneReport(provider="tavily", status=LaneStatus.OK, results=len(hits))
        ]

    monkeypatch.setattr("nbrowser.mcp_server.fan_out_search", fake_fan_out)
    server = McpServer()

    # An explicit JSON null means the advertised default, not a crash.
    out = server.handle_tool_call(
        "nbrowser_web_search", {"query": "x", "max_results": None}
    )
    assert seen == [10]
    assert len(out["hits"]) == 10

    # 0 clamps to 1 hit, never to the default 10.
    out = server.handle_tool_call(
        "nbrowser_web_search", {"query": "x", "max_results": 0}
    )
    assert seen == [10, 1]
    assert len(out["hits"]) == 1


@pytest.mark.parametrize("bad", ["ten", True, 3.9, "3"])
def test_web_search_refuses_a_non_integer_max_results(bad: object) -> None:
    import json

    server = McpServer()
    # A bad max_results must reach the client as the typed refusal, not as a
    # bare ValueError that escapes call_tool as a JSON-RPC internal error.
    reply = server.call_tool("nbrowser_web_search", {"query": "x", "max_results": bad})
    assert reply.get("isError") is True
    assert json.loads(reply["content"][0]["text"])["code"] == "invalid_input"


def test_web_search_estimated_tokens_counts_utf8_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser.providers.base import LaneReport, SearchHit

    def fake_fan_out(
        query: str, max_results: int
    ) -> tuple[list[SearchHit], list[LaneReport]]:
        return [SearchHit(title="t", url="https://e.com/a", snippet="é" * 100)], []

    monkeypatch.setattr("nbrowser.mcp_server.fan_out_search", fake_fan_out)
    server = McpServer()
    out = server.handle_tool_call("nbrowser_web_search", {"query": "x"})
    assert out["estimated_tokens"] == 200 // 4
