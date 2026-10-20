"""The extraction and crawl cluster.

- nbrowser_page_extract: the text path over the latest snapshot (urls[] is A5)
- nbrowser_site_crawl: one isolated context, same-origin BFS, off-origin recorded,
  cursor minted and resumed through the capture authority — on the double
- the Campaign B refusals are gone: CAMPAIGN_B_TOOLS is empty and stays a symbol
"""

from __future__ import annotations

import base64
import http.server
import json
import threading
from typing import Any

import pytest
from cdp_double import CdpDouble, FakePage
from nott_spine import ReceiptRung, TaintClass

from nbrowser import crawl as cr
from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.extract import BROWSER_SCRAPE, MARKDOWN_WALKER, SnapshotEvidence
from nbrowser.mcp_server import CAMPAIGN_B_TOOLS, McpServer
from nbrowser.sanitize import redact_url_keep_path
from nbrowser.semantic import SemanticView
from nbrowser.session import BrowserLaunchConfig, BrowserSession

SEED = "http://127.0.0.1:8765/"


def _page(url: str, text: str, title: str = "T") -> FakePage:
    return FakePage(url, title, text)


class CrawlDouble(CdpDouble):
    """Links (LINKS_WALKER) and markdown (MARKDOWN_WALKER) are keyed by the url
    a tab has NAVIGATED to: the walk opens its tab through Target.createTarget,
    which the double answers with a fresh FakePage of empty text, so the seeded
    t0 never speaks. A Page.navigate whose url is in `redirects` lands on the
    mapped url, the way a 302 lands in Chromium; the text of the landed url is
    then the page's text."""

    def __init__(
        self,
        pages: list[FakePage],
        links: dict[str, list[str]],
        redirects: dict[str, str] | None = None,
        texts: dict[str, str] | None = None,
    ) -> None:
        super().__init__(pages)
        self.links = links
        self.redirects = redirects or {}
        self.texts = texts or {}

    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        out = super().send(method, params, session_id, timeout)
        if method == "Page.navigate":
            page = self._page_for_session(session_id)
            if page is not None:
                if page.url in self.redirects:
                    page.url = self.redirects[page.url]
                page.text = self.texts.get(page.url, "")
        return out

    def _evaluate(self, expression: str) -> Any:
        page = self._page_for_expression(expression)
        if page is None:
            return None
        if expression == cr.LINKS_WALKER:
            return list(self.links.get(page.url, []))
        if expression == MARKDOWN_WALKER:
            return page.text
        if expression == BROWSER_SCRAPE:
            return {"href": page.url, "markdown": page.text}
        return super()._evaluate(expression)


TEXTS = {SEED: "seed text"}
# One page past the 1024-byte floor bytes_ceiling enforces: 300 repetitions, one line.
LONG_TEXT = " ".join(["seed text"] * 300)


def _crawl_server(
    links: dict[str, list[str]],
    redirects: dict[str, str] | None = None,
    texts: dict[str, str] | None = None,
) -> tuple[McpServer, CrawlDouble]:
    server = McpServer()
    double = CrawlDouble(
        [_page(SEED, "seed text")], links, redirects, TEXTS if texts is None else texts
    )
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    return server, double


def _no_robots(url: str) -> bytes:
    raise BrowserError(FailureCode.CONTENT_UNAVAILABLE, "http_404")


@pytest.fixture(autouse=True)
def _robots_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cr, "download_host", _no_robots)


def _seed(server: McpServer, view: SemanticView) -> None:
    server.last_snapshot = SnapshotEvidence(
        view=view,
        digest="snap",
        taint=TaintClass.PageDerived,
        rung=ReceiptRung.UnwitnessedLocal,
        instruction_policy="redact",
    )


def _methods(double: CdpDouble) -> list[str]:
    return [m for m, _, _ in double.sent]


THREE = {
    SEED: [SEED + "a", SEED + "b", SEED + "a#dup", "http://localhost:8765/x"],
    SEED + "a": [SEED + "c", "javascript:void(0)"],
    SEED + "b": ["http://127.0.0.1:9222/json", SEED],
    SEED + "c": [],
}


def test_nbrowser_extract_filters_the_latest_snapshot() -> None:
    server, double = _crawl_server({})
    _seed(
        server,
        SemanticView(
            url="https://example.com",
            title="Page",
            visible_text="Summary info paragraph",
            text_blocks=["Header 1", "Section paragraph with keywords", "Footer notes"],
        ),
    )
    res = server.handle_tool_call(
        "nbrowser_page_extract", {"what": "keyword", "limit": 10}
    )
    assert res["count"] == 1
    assert "keywords" in res["matches"][0]
    assert res["taint"] == "page_derived"
    assert double.sent == []


def test_campaign_b_tools_is_empty_and_stays_a_symbol() -> None:
    assert CAMPAIGN_B_TOOLS == frozenset()
    server, _ = _crawl_server({})
    for tool in ("nbrowser_site_crawl",):
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(tool, {})
        assert exc.value.code == InputFailure.OPERATION


def test_crawl_walks_three_linked_pages_in_one_isolated_context_and_disposes() -> None:
    server, double = _crawl_server(THREE)
    res = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert [p["url"] for p in res["pages"]] == [
        SEED,
        SEED + "a",
        SEED + "b",
        SEED + "c",
    ]
    assert res["pages"][0]["markdown"] == "seed text"
    assert res["stop_reason"] == "exhausted"
    assert res["cursor"] is None
    assert res["taint"] == "page_derived" and res["rung"] == "un_witnessed_local"
    methods = _methods(double)
    assert methods.index("Target.createBrowserContext") < methods.index(
        "Target.createTarget"
    )
    assert (
        "Target.createTarget",
        {"url": "about:blank", "browserContextId": "bc1"},
        None,
    ) in double.sent
    assert methods.count("Page.navigate") == 4
    assert methods[-2:] == ["Target.disposeBrowserContext", "Target.getTargets"]
    assert double.contexts == []
    assert server.session is not None and server.session._tab_sessions == {}
    assert server.cursor_digests == []


def test_crawl_max_pages_none_is_25_zero_is_invalid_and_ceiling_is_100() -> None:
    links = {SEED + (f"p{i}" if i else ""): [SEED + f"p{i + 1}"] for i in range(130)}
    links[SEED] = [SEED + "p1"]
    server, double = _crawl_server(links)
    res = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert len(res["pages"]) == 25 and res["stop_reason"] == "max_pages"
    assert isinstance(res["cursor"], str)
    server, double = _crawl_server(links)
    res = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 500}
    )
    assert len(res["pages"]) == 100
    for bad in (0, -3, "7", 1.5, True):
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(
                "nbrowser_site_crawl", {"host_url": SEED, "max_pages": bad}
            )
        assert exc.value.code == InputFailure.OPERATION
    assert _methods(double).count("Target.createBrowserContext") == 1


def test_crawl_cursor_resumes_once_and_content_get_never_resolves_it() -> None:
    server, _ = _crawl_server(THREE)
    first = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 2}
    )
    assert [p["url"] for p in first["pages"]] == [SEED, SEED + "a"]
    assert first["stop_reason"] == "max_pages"
    cursor = first["cursor"]
    assert isinstance(cursor, str) and len(cursor) < cr.CURSOR_WIRE_CAP
    digest = json.loads(base64.urlsafe_b64decode(cursor))["digest"].removeprefix(
        "sha256:"
    )
    assert server.cursor_digests == [digest]
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_content_show", {"ref": digest})
    assert exc.value.code == InputFailure.CONTENT_REF
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call(
            "nbrowser_site_crawl",
            {"cursor": cursor, "host_url": "http://localhost:8765/"},
        )
    assert exc.value.code == InputFailure.CONTENT_REF
    second = server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert [p["url"] for p in second["pages"]] == [SEED + "b", SEED + "c"]
    assert second["stop_reason"] == "exhausted" and second["cursor"] is None
    assert server.cursor_digests == []
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE


def test_consumed_cursor_stays_consumed_after_identical_new_crawl() -> None:
    server, _ = _crawl_server({SEED: [SEED + "next"], SEED + "next": []})
    first = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )
    cursor = first["cursor"]
    resumed = server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert [page["url"] for page in resumed["pages"]] == [SEED + "next"]
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
    fresh = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )["cursor"]
    assert fresh != cursor
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
    resumed = server.handle_tool_call("nbrowser_site_crawl", {"cursor": fresh})
    assert [page["url"] for page in resumed["pages"]] == [SEED + "next"]


def test_cursor_minted_by_another_process_and_malformed_wires_are_refused() -> None:
    a, _ = _crawl_server(THREE)
    b, _ = _crawl_server(THREE)
    cursor = a.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )["cursor"]
    with pytest.raises(BrowserError) as exc:
        b.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == InputFailure.CONTENT_REF
    assert exc.value.message == "cursor minted by another process"
    wire = json.loads(base64.urlsafe_b64decode(cursor))
    forged = dict(wire, binding="0" * 64)
    forged_cursor = base64.urlsafe_b64encode(json.dumps(forged).encode()).decode()
    with pytest.raises(BrowserError) as exc:
        a.handle_tool_call("nbrowser_site_crawl", {"cursor": forged_cursor})
    assert exc.value.code == InputFailure.CONTENT_REF
    for bad in ("x" * (cr.CURSOR_WIRE_CAP + 1), "not-base64!", "", 7, "aGk=", "W10="):
        with pytest.raises(BrowserError) as exc:
            a.handle_tool_call("nbrowser_site_crawl", {"cursor": bad})
        assert exc.value.code == InputFailure.CONTENT_REF
    assert a.cursor_digests != []
    resumed = a.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert resumed["pages"][0]["url"] == SEED + "a"


def test_cursor_kind_and_outstanding_cap() -> None:
    server, _ = _crawl_server(THREE)
    map_state = {
        "kind": "map",
        "invocation": "review-fix-custody",
        "seed": SEED,
        "queue": [SEED + "z"],
        "seen": [SEED],
        "saturation": None,
        "stale": 0,
    }
    wire = cr.mint_cursor(server, map_state)
    with pytest.raises(BrowserError) as exc:
        cr.resume_cursor(server, wire, "crawl", None)
    assert exc.value.code == InputFailure.CONTENT_REF
    assert "map" in exc.value.message
    assert cr.resume_cursor(server, wire, "map", None) == map_state
    for i in range(cr.MAX_OUTSTANDING_CURSORS + 3):
        cr.mint_cursor(server, dict(map_state, queue=[SEED + f"q{i}"]))
    assert len(server.cursor_digests) == cr.MAX_OUTSTANDING_CURSORS
    assert len(server.resolver.store) == cr.MAX_OUTSTANDING_CURSORS


@pytest.mark.parametrize(
    "tool,budget",
    [("nbrowser_site_crawl", "max_pages")],
)
def test_cursor_invocation_changes_on_resumption(tool: str, budget: str) -> None:
    server, _ = _crawl_server(THREE)
    first = server.handle_tool_call(tool, {"host_url": SEED, budget: 1})
    original = json.loads(server.resolver.store[server.cursor_digests[0]])
    resumed = server.handle_tool_call(tool, {"cursor": first["cursor"], budget: 1})
    assert resumed["cursor"] != first["cursor"]
    current = json.loads(server.resolver.store[server.cursor_digests[0]])
    assert current["invocation"] != original["invocation"]


def test_off_origin_landing_is_recorded_not_harvested() -> None:
    other = "http://127.0.0.1:9/"
    server, double = _crawl_server(
        {SEED: [SEED + "r"], other: [other + "evil"]}, redirects={SEED + "r": other}
    )
    res = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert res["pages"] == [
        {"url": SEED, "markdown": "seed text"},
        {"url": SEED + "r", "markdown": "", "off_origin": "http://127.0.0.1:9"},
    ]
    assert res["stop_reason"] == "exhausted"
    navigated = [p.get("url") for m, p, _ in double.sent if m == "Page.navigate"]
    assert navigated == [SEED, SEED + "r"]


def test_robots_disallow_all_visits_nothing_and_a_dead_robots_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(url: str) -> bytes:
        raise BrowserError(FailureCode.CONTENT_UNAVAILABLE, "http_403")

    monkeypatch.setattr(cr, "download_host", forbidden)
    server, double = _crawl_server(THREE)
    res = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert res["pages"] == [] and res["stop_reason"] == "exhausted"
    assert "Page.navigate" not in _methods(double)

    def dead(url: str) -> bytes:
        raise BrowserError(FailureCode.CONTENT_UNAVAILABLE, "transport: refused")

    monkeypatch.setattr(cr, "download_host", dead)
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
    assert "robots.txt" in exc.value.message


def test_engine_failure_mid_walk_disposes_and_restages_the_cursor() -> None:
    from nbrowser.errors import ClosedFailure

    class Dies(CrawlDouble):
        """Dies on the SECOND Page.navigate of the process, whatever the
        session: the first call (max_pages 1) navigates once, so the resumed
        call dies on its first page, inside a fresh context."""

        def wait_event(
            self,
            method: str,
            session_id: str | None = None,
            timeout: float = 15.0,
            *,
            params: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            if _methods(self).count("Page.navigate") >= 2:
                raise BrowserError(ClosedFailure.PROTOCOL, "CDP event timeout")
            return super().wait_event(method, session_id, timeout, params=params)

    server = McpServer()
    double = Dies([_page(SEED, "seed text")], THREE, texts=TEXTS)
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    first = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )
    cursor = first["cursor"]
    assert server.cursor_digests != []
    held = list(server.cursor_digests)
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == ClosedFailure.PROTOCOL
    assert double.contexts == []
    assert server.cursor_digests == held
    assert server.resolver.holds(held[0])


def _assert_cursor_preparation_failure(
    monkeypatch: pytest.MonkeyPatch, tool: str, cause: str
) -> None:
    from nbrowser.errors import ClosedFailure

    server, double = _crawl_server(THREE)
    budget = {"max_pages": 1} if tool == "nbrowser_site_crawl" else {"max_urls": 1}
    cursor = server.handle_tool_call(tool, {"host_url": SEED, **budget})["cursor"]
    held = list(server.cursor_digests)
    original_state = server.resolver.store[held[0]]
    calls = _methods(double).count("Page.navigate")
    failed = False

    def dead_robots(url: str) -> bytes:
        nonlocal failed
        assert server.cursor_digests == []  # failure is AFTER consumption
        failed = True
        raise BrowserError(FailureCode.CONTENT_UNAVAILABLE, "transport: refused")

    def dead_session() -> str:
        nonlocal failed
        assert server.cursor_digests == []  # failure is AFTER consumption
        failed = True
        raise BrowserError(ClosedFailure.LAUNCH, "session start refused")

    with monkeypatch.context() as patch:
        if cause == "robots":
            patch.setattr(cr, "download_host", dead_robots)
        else:
            assert cause == "session"
            patch.setattr(server.get_session(), "context_open", dead_session)
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(tool, {"cursor": cursor})
        expected = (
            FailureCode.CONTENT_UNAVAILABLE
            if cause == "robots"
            else ClosedFailure.LAUNCH
        )
        assert exc.value.code == expected
    assert failed
    assert _methods(double).count("Page.navigate") == calls
    assert server.cursor_digests == held
    assert server.resolver.store[held[0]] == original_state
    resumed = server.handle_tool_call(tool, {"cursor": cursor})
    urls = (
        [page["url"] for page in resumed["pages"]]
        if tool == "nbrowser_site_crawl"
        else resumed["urls"]
    )
    assert urls == [SEED + "a", SEED + "b", SEED + "c"]
    assert resumed["cursor"] is None and resumed["stop_reason"] == "exhausted"


def test_cursor_robots_fetch_failure_after_consumption_preserves_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_cursor_preparation_failure(monkeypatch, "nbrowser_site_crawl", "robots")


def test_cursor_context_open_failure_after_consumption_preserves_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_cursor_preparation_failure(monkeypatch, "nbrowser_site_crawl", "session")


def test_cursor_wire_bound_refuses_before_decoder_is_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, _ = _crawl_server(THREE)

    def forbidden_decoder(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("oversized cursor reached decoder")

    monkeypatch.setattr(cr.base64, "urlsafe_b64decode", forbidden_decoder)
    with pytest.raises(BrowserError) as exc:
        cr.resume_cursor(server, "x" * (cr.CURSOR_WIRE_CAP + 1), "crawl", None)
    assert exc.value.code == InputFailure.CONTENT_REF
    assert exc.value.message == f"cursor exceeds {cr.CURSOR_WIRE_CAP} bytes"


def test_crawl_walk_clock_deadline_returns_partial_cursor_and_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    server, double = _crawl_server(THREE)
    ticks = iter((0.0, 0.0, cr.CRAWL_DEADLINE_S + 1.0))
    with monkeypatch.context() as patch:
        patch.setattr(cr, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
        first = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert [page["url"] for page in first["pages"]] == [SEED]
    assert first["stop_reason"] == "deadline"
    assert isinstance(first["cursor"], str)
    assert _methods(double).count("Page.navigate") == 1
    assert double.contexts == []
    resumed = server.handle_tool_call(
        "nbrowser_site_crawl", {"cursor": first["cursor"]}
    )
    assert [page["url"] for page in resumed["pages"]] == [
        SEED + "a",
        SEED + "b",
        SEED + "c",
    ]
    assert resumed["stop_reason"] == "exhausted" and resumed["cursor"] is None


def test_crawl_pages_spill_into_an_artifact_under_max_content_bytes() -> None:
    # THREE with "seed text" serialises to ~216 bytes and bytes_ceiling floors
    # at 1024: nothing would spill. The seed page carries 2999 bytes here.
    server, _ = _crawl_server(THREE, texts={SEED: LONG_TEXT})
    res = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_content_bytes": 1024}
    )
    assert "pages" not in res
    assert res["artifacts"]["pages"]["bytes"] > 1024
    assert res["estimated_tokens"]["pages"] > 256
    got = server.handle_tool_call(
        "nbrowser_content_show", {"ref": res["artifacts"]["pages"]["ref"]}
    )
    pages = json.loads(got["content"])
    assert [p["url"] for p in pages] == [SEED, SEED + "a", SEED + "b", SEED + "c"]
    assert len(pages[0]["markdown"]) > 1024


def _static_site(
    pages: dict[str, tuple[int, str, bytes]],
) -> tuple[http.server.HTTPServer, str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, ctype, body = pages.get(
                self.path, (404, "text/html", b"<p>missing</p>")
            )
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_extract_static_mode_sends_zero_cdp_frames_and_404_never_falls_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser import transfer

    monkeypatch.setattr(cr, "download_host", transfer.download_host)
    site, base = _static_site(
        {
            "/plain": (
                200,
                "text/html; charset=utf-8",
                b"<h1>T</h1><p>a</p><a href='/n'>N</a>",
            ),
            "/guide.md": (
                200,
                "text/markdown; charset=utf-8",
                b"# Guide\n\n## Auth\n\nUse tokens.\n\n## Billing\n\nPlans.",
            ),
            "/data.json": (200, "application/json", b'{"a": 1}'),
            "/large": (200, "text/html", b"<p>" + b"x" * 1500 + b"</p>"),
        }
    )
    server, double = _crawl_server({})
    try:
        md_res = server.handle_tool_call(
            "nbrowser_page_extract",
            {
                "urls": [base + "/guide.md"],
                "mode": "static",
                "outline": False,
                "filter": "auth",
                "content_boundaries": True,
            },
        )
        assert "## Auth" in md_res["documents"][0]["markdown"]
        assert "## Billing" not in md_res["documents"][0]["markdown"]
        assert "NBROWSER_PAGE_CONTENT nonce=" in md_res["documents"][0]["markdown"]
        res = server.handle_tool_call(
            "nbrowser_page_extract",
            {"urls": [base + "/plain", base + "/data.json"], "mode": "static"},
        )
        assert res["documents"] == [
            {
                "url": base + "/plain",
                "mode_used": "static",
                "markdown": "# T\n\na\n\n[N](" + base + "/n)",
            },
            {
                "url": base + "/data.json",
                "mode_used": "static",
                "markdown": "",
                "skipped": "content_type",
            },
        ]
        assert res["taint"] == "page_derived" and res["rung"] == "un_witnessed_local"
        assert double.sent == []
        for mode in ("auto", "static"):
            with pytest.raises(BrowserError) as exc:
                server.handle_tool_call(
                    "nbrowser_page_extract", {"urls": [base + "/missing"], "mode": mode}
                )
            assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
        assert double.sent == []
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(
                "nbrowser_page_extract", {"urls": [base + "/plain"], "mode": "fast"}
            )
        assert exc.value.code == InputFailure.OPERATION
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(
                "nbrowser_page_extract", {"urls": [base + "/plain"] * 51}
            )
        assert exc.value.code == InputFailure.OPERATION
        inline = server.handle_tool_call(
            "nbrowser_page_extract",
            {"urls": [base + "/plain"], "mode": "static", "max_content_bytes": 1024},
        )
        assert len(json.dumps(inline["documents"], ensure_ascii=False)) < 1024
        assert inline["documents"] == res["documents"][:1]
        assert "artifacts" not in inline
        expected = [
            {"url": base + "/large", "mode_used": "static", "markdown": "x" * 1500}
        ]
        serialized = json.dumps(expected, ensure_ascii=False)
        assert len(serialized) > 1024
        spilled = server.handle_tool_call(
            "nbrowser_page_extract",
            {"urls": [base + "/large"], "mode": "static", "max_content_bytes": 1024},
        )
        assert "documents" not in spilled
        assert spilled["artifacts"]["documents"]["bytes"] == len(serialized)
        recovered = server.handle_tool_call(
            "nbrowser_content_show", {"ref": spilled["artifacts"]["documents"]["ref"]}
        )
        assert recovered["content"] == serialized
        assert json.loads(recovered["content"]) == expected
        assert double.sent == []
    finally:
        site.shutdown()


@pytest.mark.parametrize(
    ("tool", "with_cursor"),
    [
        ("nbrowser_site_crawl", False),
        ("nbrowser_site_crawl", True),
    ],
)
def test_crawl_family_judges_engine_before_network_egress(
    monkeypatch: pytest.MonkeyPatch, tool: str, with_cursor: bool
) -> None:
    from nbrowser.errors import ClosedFailure, failure_envelope

    server, _ = _crawl_server(THREE)
    params: dict[str, Any] = {"host_url": "http://127.0.0.1:1/"}
    if with_cursor:
        budget = {"max_pages": 1} if tool == "nbrowser_site_crawl" else {"max_urls": 1}
        first = server.handle_tool_call(tool, {"host_url": SEED, **budget})
        params = {"cursor": first["cursor"]}
    held = list(server.cursor_digests)
    original_state = {digest: server.resolver.store[digest] for digest in held}
    fetched: list[str] = []

    def no_engine() -> BrowserSession:
        raise BrowserError(ClosedFailure.LAUNCH, "no engine")

    def unavailable(url: str) -> bytes:
        fetched.append(url)
        raise BrowserError(FailureCode.CONTENT_UNAVAILABLE, "transport: refused")

    with monkeypatch.context() as patch:
        patch.setattr(server, "get_session", no_engine)
        patch.setattr(cr, "download_host", unavailable)
        with pytest.raises(BrowserError) as exc:
            server.handle_tool_call(tool, params)
        assert (failure_envelope(exc.value)["code"], fetched) == ("engine_failure", [])
    assert server.cursor_digests == held
    assert {digest: server.resolver.store[digest] for digest in held} == original_state
    if with_cursor:
        assert held
        resumed = server.handle_tool_call(tool, params)
        urls = (
            [page["url"] for page in resumed["pages"]]
            if tool == "nbrowser_site_crawl"
            else resumed["urls"]
        )
        assert urls == [SEED + "a", SEED + "b", SEED + "c"]
        assert resumed["stop_reason"] == "exhausted" and resumed["cursor"] is None
        assert server.cursor_digests == []


@pytest.mark.parametrize(
    "tool,budget",
    [("nbrowser_site_crawl", "max_pages")],
)
def test_cursor_deadline_reissue_never_revives_consumed_token(
    monkeypatch: pytest.MonkeyPatch, tool: str, budget: str
) -> None:
    server, double = _crawl_server({SEED: [SEED + "a"], SEED + "a": []})
    original = server.handle_tool_call(tool, {"host_url": SEED, budget: 1})["cursor"]
    assert isinstance(original, str)
    session = server.get_session()
    open_context = session.context_open
    now = 0.0

    def delayed_context() -> str:
        nonlocal now
        context = open_context()
        now = cr.CRAWL_DEADLINE_S + 1.0
        return context

    navigations = _methods(double).count("Page.navigate")
    with monkeypatch.context() as patch:
        patch.setattr(session, "context_open", delayed_context)
        patch.setattr(cr.time, "monotonic", lambda: now)
        result = server.handle_tool_call(tool, {"cursor": original})
    assert result["stop_reason"] == "deadline"
    assert _methods(double).count("Page.navigate") == navigations
    assert double.contexts == []
    assert isinstance(result["cursor"], str)
    assert result["cursor"] != original
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call(tool, {"cursor": original})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
    resumed = server.handle_tool_call(tool, {"cursor": result["cursor"]})
    assert resumed["stop_reason"] == "exhausted" and resumed["cursor"] is None
    urls = (
        [page["url"] for page in resumed["pages"]]
        if tool == "nbrowser_site_crawl"
        else resumed["urls"]
    )
    assert urls == [SEED + "a"]


def test_crawl_non_list_link_reply_is_an_exhausted_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, double = _crawl_server(THREE)
    evaluate = double._evaluate

    def no_links(expression: str) -> Any:
        return None if expression == cr.LINKS_WALKER else evaluate(expression)

    monkeypatch.setattr(double, "_evaluate", no_links)
    result = server.handle_tool_call("nbrowser_site_crawl", {"host_url": SEED})
    assert result["pages"] == [{"url": SEED, "markdown": "seed text"}]
    assert result["stop_reason"] == "exhausted" and result["cursor"] is None
    assert double.contexts == []


def test_cursor_invalid_contract_and_non_derived_ref_refuse_before_navigation() -> None:
    from nott_spine import (
        CaptureFrame,
        OriginMetadata,
        RetentionPolicy,
        SourceCapability,
    )

    server, double = _crawl_server({})
    invalid = base64.urlsafe_b64encode(b"{}").decode()
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": invalid})
    assert exc.value.code == InputFailure.CONTENT_REF
    assert exc.value.message.startswith("cursor fields invalid:")
    source = server.content_authority.issuer(SourceCapability.NBrowser).issue(
        "sha256:" + "a" * 64,
        OriginMetadata.browser_capture(
            "fixture://cursor-test", None, CaptureFrame(1, 1, 1.0, "frame")
        ),
        RetentionPolicy.NoStore,
        TaintClass.PixelDerived,
    )
    wire = base64.urlsafe_b64encode(source.to_json().encode()).decode()
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": wire})
    assert exc.value.code == InputFailure.CONTENT_REF
    assert exc.value.message == "ref is not a crawl cursor"
    assert double.sent == [] and server.cursor_digests == []


def test_cursor_missing_bytes_refuse_and_clear_stale_custody() -> None:
    server, double = _crawl_server(THREE)
    cursor = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )["cursor"]
    digest = server.cursor_digests[0]
    server.resolver.resolve_once(digest)
    sent = list(double.sent)
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
    assert exc.value.message == "cursor already resumed or unknown"
    assert server.cursor_digests == []
    assert double.sent == sent


def test_cursor_restage_is_idempotent_and_resumes_only_once() -> None:
    server, _ = _crawl_server(THREE)
    cursor = server.handle_tool_call(
        "nbrowser_site_crawl", {"host_url": SEED, "max_pages": 1}
    )["cursor"]
    held = list(server.cursor_digests)
    state = json.loads(server.resolver.store[held[0]])
    assert cr.mint_cursor(server, state) == cursor
    assert server.cursor_digests == held
    result = server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert [page["url"] for page in result["pages"]] == [
        SEED + "a",
        SEED + "b",
        SEED + "c",
    ]
    assert result["cursor"] is None and server.cursor_digests == []
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_site_crawl", {"cursor": cursor})
    assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE


@pytest.mark.parametrize("tool", ["nbrowser_site_crawl"])
def test_fresh_walk_context_failure_never_mints_a_recovery_cursor(
    monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    from nbrowser.errors import ClosedFailure

    server, double = _crawl_server(THREE)

    def refuse() -> str:
        raise BrowserError(ClosedFailure.LAUNCH, "context refused")

    monkeypatch.setattr(server.get_session(), "context_open", refuse)
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call(tool, {"host_url": SEED})
    assert exc.value.code == ClosedFailure.LAUNCH
    assert exc.value.message == "context refused"
    assert double.sent == [] and double.contexts == []
    assert server.cursor_digests == [] and server.resolver.store == {}


@pytest.mark.parametrize(
    "mode,path", [("browser", "/plain"), ("auto", "/shell"), ("auto", "/redirect")]
)
def test_extract_browser_modes_return_rendered_text_and_dispose_context(
    mode: str,
    path: str,
) -> None:
    site, base = _static_site(
        {
            "/plain": (200, "text/html", b"<p>static text</p>"),
            "/shell": (200, "text/html", b"<div id='root'></div>"),
            "/redirect": (302, "text/html", b"redirect"),
        }
    )
    url = base + path
    server, double = _crawl_server({}, texts={url: "rendered text"})
    try:
        result = server.handle_tool_call(
            "nbrowser_page_extract", {"urls": [url], "mode": mode}
        )
        assert result["documents"] == [
            {"url": url, "mode_used": "browser", "markdown": "rendered text"}
        ]
        assert _methods(double).count("Target.createBrowserContext") == 1
        assert _methods(double).count("Page.navigate") == 1
        assert _methods(double)[-2:] == [
            "Target.disposeBrowserContext",
            "Target.getTargets",
        ]
        assert double.contexts == []
    finally:
        site.shutdown()
        site.server_close()


def test_text_artifact_ceiling_measures_utf8_bytes() -> None:
    from nbrowser.transfer import TextArtifactCandidate, apply_text_artifacts

    body = "é" * 600  # 600 characters, 1200 UTF-8 bytes
    payload: dict[str, Any] = {"documents": body}
    staged: list[str] = []
    apply_text_artifacts(
        payload,
        [TextArtifactCandidate(format="documents", body=body)],
        1024,
        stage=staged.append,
    )
    assert staged == [body]
    assert "documents" not in payload
    assert payload["artifacts"]["documents"]["bytes"] == 1200
    assert payload["estimated_tokens"]["documents"] == 300


def test_download_host_returns_exact_bytes_from_the_http_response() -> None:
    from nbrowser.transfer import download_host

    body = b"\x00\xffdownload bytes\n"
    site, base = _static_site({"/file": (200, "application/octet-stream", body)})
    try:
        assert download_host(base + "/file", timeout=1.0) == body
    finally:
        site.shutdown()
        site.server_close()


def test_extract_browser_reports_the_landing_url_after_a_redirect() -> None:
    landing = SEED + "landed"
    server, _ = _crawl_server(
        {}, redirects={SEED: landing}, texts={landing: "landed text"}
    )
    result = server.handle_tool_call(
        "nbrowser_page_extract", {"urls": [SEED], "mode": "browser"}
    )
    assert result["documents"] == [
        {"url": landing, "mode_used": "browser", "markdown": "landed text"}
    ]


def test_extract_browser_landing_url_drops_query_credentials() -> None:
    landing = SEED + "landed?access_token=supersecretvalue"
    server, _ = _crawl_server(
        {}, redirects={SEED: landing}, texts={landing: "landed text"}
    )
    result = server.handle_tool_call(
        "nbrowser_page_extract", {"urls": [SEED], "mode": "browser"}
    )
    document = result["documents"][0]
    assert "supersecretvalue" not in document["url"]
    assert document["url"] == redact_url_keep_path(landing)


@pytest.mark.parametrize(
    "content_type", ["text/plain", "text/markdown", "text/x-markdown"]
)
def test_static_html_request_preserves_default_text_reads(content_type: str) -> None:
    site, base = _static_site({"/document": (200, content_type, b"# Readable text")})
    server, double = _crawl_server({})
    try:
        params = {"urls": [base + "/document"], "mode": "static"}
        before = server.handle_tool_call("nbrowser_page_extract", params)
        restricted = server.handle_tool_call(
            "nbrowser_page_extract", {**params, "html_only": True}
        )
        after = server.handle_tool_call(
            "nbrowser_page_extract", {**params, "html_only": False}
        )
        assert before["documents"][0]["markdown"] == "# Readable text"
        assert restricted["documents"] == [
            {
                "url": base + "/document",
                "mode_used": "static",
                "markdown": "",
                "skipped": "content_type",
            }
        ]
        assert after == before
        assert double.sent == []
    finally:
        server.close()
        site.shutdown()
        site.server_close()


@pytest.mark.parametrize(
    "params",
    [
        {"urls": [SEED], "mode": "static", "html_only": "true"},
        {"urls": [SEED], "mode": "static", "html_only": 1},
        {"urls": [SEED], "mode": "static", "html_only": 0},
        {"urls": [SEED], "mode": "static", "html_only": None},
        {"urls": [SEED], "mode": "auto", "html_only": True},
        {"urls": [SEED], "mode": "browser", "html_only": True},
        {"mode": "static", "html_only": True},
    ],
)
def test_html_only_requires_a_boolean_and_static_urls(
    monkeypatch: pytest.MonkeyPatch, params: dict[str, Any]
) -> None:
    from nbrowser import extract

    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("The invalid request reached document extraction")

    server, double = _crawl_server({})
    monkeypatch.setattr(extract, "_extract_static", unexpected)
    monkeypatch.setattr(extract, "_extract_browser", unexpected)
    monkeypatch.setattr(server, "get_session", unexpected)
    try:
        with pytest.raises(BrowserError) as error:
            server.handle_tool_call("nbrowser_page_extract", params)
        assert error.value.code is InputFailure.OPERATION
        assert double.sent == []
    finally:
        server.close()


def test_static_html_request_does_not_read_document_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nbrowser import extract

    asked: list[str] = []

    def download(url: str, **kwargs: Any) -> tuple[bytes, str, str, str | None]:
        asked.append(url)
        if url == SEED:
            return (
                b"<html><body><script>load()</script></body></html>",
                "text/html",
                "",
                None,
            )
        return b"# Markdown fallback", "text/markdown", "", "utf-8"

    monkeypatch.setattr(extract, "download_host_page", download)
    server, double = _crawl_server({})
    try:
        params = {"urls": [SEED], "mode": "static"}
        restricted = server.handle_tool_call(
            "nbrowser_page_extract", {**params, "html_only": True}
        )
        assert restricted["documents"] == [
            {"url": SEED, "mode_used": "static", "markdown": ""}
        ]
        assert asked == [SEED]
        asked.clear()
        default = server.handle_tool_call("nbrowser_page_extract", params)
        assert default["documents"][0]["markdown"] == "# Markdown fallback"
        assert asked == [SEED, SEED + "index.html.md"]
        assert double.sent == []
    finally:
        server.close()
