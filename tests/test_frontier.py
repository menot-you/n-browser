"""The crawl frontier is pure: strings in, strings out, one injected fetch.
Property-tested because every URL it yields is a socket the driver will open."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nbrowser import frontier as fr
from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.frontier import Frontier, StopReason

SEED = "http://127.0.0.1:8765/"
PATHS = ["/", "/a", "/b", "/c", "/d", "/e", "/f", "/g"]
LINKS = [
    "http://127.0.0.1:8765/a",
    "http://127.0.0.1:8765/b",
    "http://127.0.0.1:8765/c#frag",
    "http://127.0.0.1:8765/d?b=1&a=2",
    "http://127.0.0.1:8765/e",
    "http://127.0.0.1:8765/f",
    "http://127.0.0.1:8765/g",
    "HTTP://127.0.0.1:8765/a",
    "http://localhost:8765/x",
    "http://127.0.0.1:9222/json",
    "https://example.com/",
    "http://[::1]:8765/",
    "http://0.0.0.0:8765/",
    "javascript:void(0)",
    "data:text/html,hi",
    "file:///etc/passwd",
    "//evil.com/x",
    "/relative",
    "http://127.0.0.1:8765:bad/",
]
BANNED_MODULES = {"urllib.request", "socket", "http.client", "nbrowser.session"}


def _fetch_html(url: str) -> bytes:
    return b"<html><body>missing</body></html>"


def _fetch_refusing(message: str, code: FailureCode = FailureCode.CONTENT_UNAVAILABLE):
    def fetch(url: str) -> bytes:
        raise BrowserError(code, message)

    return fetch


def test_frontier_module_opens_no_socket() -> None:
    source = Path(fr.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    named: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            named.update(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            named.add(("." * node.level) + (node.module or ""))
    assert not (named & BANNED_MODULES), named
    assert ".session" not in named
    assert "urlopen" not in source
    assert ".read(" not in source
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, nbrowser.frontier; print('nbrowser.session' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert probe.stdout.strip() == "False"


def test_normalize_and_origin_key_pin_the_port_and_the_alias() -> None:
    assert fr.normalize("http://127.0.0.1:8765/a#f") == "http://127.0.0.1:8765/a"
    assert (
        fr.normalize("HTTP://127.0.0.1:8765/a?b=1&a=2")
        == "http://127.0.0.1:8765/a?a=2&b=1"
    )
    assert fr.normalize("http://example.com:80") == "http://example.com/"
    assert fr.normalize("https://Example.com:443/x") == "https://example.com/x"
    assert fr.origin_key("http://127.0.0.1:8765/a") == "http://127.0.0.1:8765"
    assert fr.origin_key("https://example.com/") == "https://example.com:443"
    assert fr.origin_key("http://localhost:8765/") != fr.origin_key(SEED)
    assert not fr.same_origin("http://localhost:8765/x", SEED)
    assert not fr.same_origin("http://127.0.0.1:9222/json", SEED)
    assert fr.same_origin("http://127.0.0.1:8765/deep/path?q=1", SEED)
    assert fr.root_url("http://127.0.0.1:8765/a/b", "/robots.txt") == (
        "http://127.0.0.1:8765/robots.txt"
    )
    for bad in ("javascript:void(0)", "//evil.com/x", "/relative", "http://h:bad/"):
        assert not fr.is_web_url(bad), bad
    assert fr.is_web_url("http://[::1]:8765/")


@settings(max_examples=200, deadline=None)
@given(
    graph=st.dictionaries(
        keys=st.sampled_from(PATHS),
        values=st.lists(st.sampled_from(LINKS), max_size=6),
        max_size=8,
    ),
    max_pages=st.integers(min_value=1, max_value=8),
    blocked=st.sets(st.sampled_from(PATHS[1:]), max_size=3),
)
def test_every_yielded_url_is_same_origin_allowed_and_unique(
    graph: dict[str, list[str]], max_pages: int, blocked: set[str]
) -> None:
    def allowed(url: str) -> bool:
        return urlsplit(url).path not in blocked

    f = Frontier(SEED, allowed, max_pages)
    yielded: list[str] = []
    while (url := f.next()) is not None:
        yielded.append(url)
        f.record(url, graph.get(urlsplit(url).path, []))
    assert len(yielded) <= max_pages
    assert len(set(yielded)) == len(yielded)
    for url in yielded:
        assert fr.same_origin(url, SEED)
        assert allowed(url)
        assert url == fr.normalize(url)
        assert "localhost" not in url and ":9222" not in url
    assert f.stop_reason in (StopReason.EXHAUSTED, StopReason.MAX_PAGES)
    if f.stop_reason is StopReason.MAX_PAGES:
        assert f.queue


def test_state_round_trips_and_resumes_without_revisiting() -> None:
    f = Frontier(SEED, lambda u: True, 2)
    first = f.next()
    assert first == SEED
    f.record(first, ["http://127.0.0.1:8765/a", "http://127.0.0.1:8765/b"])
    second = f.next()
    assert second == "http://127.0.0.1:8765/a"
    f.record(second, ["http://127.0.0.1:8765/c", SEED])
    assert f.next() is None
    assert f.stop_reason is StopReason.MAX_PAGES
    wire = fr.canonical_state_bytes(f.state())
    assert wire == fr.canonical_state_bytes(json.loads(wire))
    g = Frontier.from_state(json.loads(wire), lambda u: True, 5)
    assert g.next() == "http://127.0.0.1:8765/b"
    g.record("http://127.0.0.1:8765/b", [SEED, "http://127.0.0.1:8765/a"])
    assert g.next() == "http://127.0.0.1:8765/c"
    g.record("http://127.0.0.1:8765/c", [])
    assert g.next() is None
    assert g.stop_reason is StopReason.EXHAUSTED
    assert g.visited == ["http://127.0.0.1:8765/b", "http://127.0.0.1:8765/c"]


def test_landed_url_is_marked_seen_and_a_deadline_keeps_the_queue() -> None:
    f = Frontier(SEED, lambda u: True, 9)
    url = f.next()
    assert url is not None
    f.record(url, ["http://127.0.0.1:8765/b"], landed="http://127.0.0.1:8765/a")
    f.record("http://127.0.0.1:8765/b", ["http://127.0.0.1:8765/a"])
    assert f.queue == ["http://127.0.0.1:8765/b"]
    f.deadline()
    assert f.stop_reason is StopReason.DEADLINE
    assert f.next() is None
    empty = Frontier(SEED, lambda u: True, 9)
    empty.record(empty.next() or "", [])
    empty.deadline()
    assert empty.stop_reason is StopReason.EXHAUSTED


def test_constructor_validates() -> None:
    for bad in (0, -1):
        with pytest.raises(BrowserError) as exc:
            Frontier(SEED, lambda u: True, bad)
        assert exc.value.code == InputFailure.OPERATION
    with pytest.raises(BrowserError) as exc:
        Frontier("javascript:void(0)", lambda u: True, 1)
    assert exc.value.code == InputFailure.OPERATION
    with pytest.raises(BrowserError) as exc:
        Frontier(SEED, lambda u: True, 1, kind="poll")
    assert exc.value.code == InputFailure.OPERATION
    with pytest.raises(BrowserError) as exc:
        Frontier.from_state({"seed": SEED}, lambda u: True, 1)
    assert exc.value.code == InputFailure.CONTENT_REF


def test_robots_via_parse_never_read() -> None:
    parser = fr.load_robots(_fetch_html, SEED)
    assert parser.can_fetch("*", "http://127.0.0.1:8765/anything")
    parser = fr.load_robots(_fetch_refusing("http_404"), SEED)
    assert parser.can_fetch("*", "http://127.0.0.1:8765/a")
    for forbidden in ("http_401", "http_403"):
        parser = fr.load_robots(_fetch_refusing(forbidden), SEED)
        assert not parser.can_fetch("*", "http://127.0.0.1:8765/a")
    for dead in ("http_503", "transport: [Errno 111] refused"):
        with pytest.raises(BrowserError) as exc:
            fr.load_robots(_fetch_refusing(dead), SEED)
        assert exc.value.code == FailureCode.CONTENT_UNAVAILABLE
        assert "robots.txt" in exc.value.message
    with pytest.raises(BrowserError) as exc:
        fr.load_robots(
            _fetch_refusing("redirect refused: 302", FailureCode.GRANT_REQUIRED), SEED
        )
    assert exc.value.code == FailureCode.GRANT_REQUIRED
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        return b"User-agent: *\nDisallow: /private\n"

    parser = fr.load_robots(fetch, "http://127.0.0.1:8765/deep/page")
    assert seen == ["http://127.0.0.1:8765/robots.txt"]
    assert not parser.can_fetch("*", "http://127.0.0.1:8765/private/x")
    assert parser.can_fetch("*", "http://127.0.0.1:8765/public")
