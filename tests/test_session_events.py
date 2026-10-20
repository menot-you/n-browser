"""The reader-thread hook and the double's traffic record, both new in U1."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

import pytest
from cdp_double import CdpDouble, FakePage

from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.session import BrowserLaunchConfig, BrowserSession, CdpPipeClient


def _frame(method: str, params: dict[str, Any]) -> bytes:
    return (
        json.dumps({"method": method, "sessionId": "s1", "params": params}).encode()
        + b"\0"
    )


def test_read_loop_hands_consumed_frames_to_the_hook_and_never_to_events() -> None:
    engine_to_client_r, engine_to_client_w = os.pipe()
    client_to_engine_r, client_to_engine_w = os.pipe()
    seen: list[dict[str, Any]] = []
    client = CdpPipeClient(
        fd_in=engine_to_client_r, fd_out=client_to_engine_w, on_event=seen.append
    )
    try:
        os.write(
            engine_to_client_w,
            _frame("Runtime.consoleAPICalled", {"type": "log", "args": []}),
        )
        os.write(
            engine_to_client_w,
            _frame(
                "Fetch.requestPaused",
                {
                    "requestId": "r1",
                    "request": {"url": "https://example.com/x", "method": "GET"},
                },
            ),
        )
        os.write(
            engine_to_client_w, _frame("Runtime.exceptionThrown", {"timestamp": 1.0})
        )
        os.write(engine_to_client_w, _frame("Page.loadEventFired", {"timestamp": 2.0}))
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with client.lock:
                landed = len(client.events)
            if len(seen) >= 3 and landed >= 1:
                break
            time.sleep(0.01)
        assert [e["method"] for e in seen] == [
            "Runtime.consoleAPICalled",
            "Fetch.requestPaused",
            "Runtime.exceptionThrown",
        ]
        reply = json.loads(os.read(client_to_engine_r, 4096).split(b"\0")[0])
        assert reply["method"] == "Fetch.continueRequest"
        assert reply["params"] == {"requestId": "r1"}
        with client.lock:
            assert [e["method"] for e in client.events] == ["Page.loadEventFired"]
    finally:
        os.close(engine_to_client_w)
        client.close()
        os.close(client_to_engine_r)


def test_read_loop_hands_a_detached_frame_to_the_hook_and_never_to_events() -> None:
    """Chromium fires Target.detachedFromTarget when a flattened session closes
    or its context is disposed. The reader must hand it to the hook, which drops
    that session's rings, and must not leave it in `events`."""
    engine_to_client_r, engine_to_client_w = os.pipe()
    client_to_engine_r, client_to_engine_w = os.pipe()
    seen: list[dict[str, Any]] = []
    client = CdpPipeClient(
        fd_in=engine_to_client_r, fd_out=client_to_engine_w, on_event=seen.append
    )
    try:
        os.write(
            engine_to_client_w,
            _frame("Target.detachedFromTarget", {"sessionId": "s1", "targetId": "t1"}),
        )
        os.write(engine_to_client_w, _frame("Page.loadEventFired", {"timestamp": 2.0}))
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with client.lock:
                landed = len(client.events)
            if len(seen) >= 1 and landed >= 1:
                break
            time.sleep(0.01)
        assert [e["method"] for e in seen] == ["Target.detachedFromTarget"]
        with client.lock:
            assert [e["method"] for e in client.events] == ["Page.loadEventFired"]
    finally:
        os.close(engine_to_client_w)
        client.close()
        os.close(client_to_engine_r)


def test_read_loop_without_a_hook_still_consumes_and_still_answers() -> None:
    engine_to_client_r, engine_to_client_w = os.pipe()
    client_to_engine_r, client_to_engine_w = os.pipe()
    client = CdpPipeClient(fd_in=engine_to_client_r, fd_out=client_to_engine_w)
    try:
        assert client.on_event is None
        os.write(
            engine_to_client_w,
            _frame("Runtime.consoleAPICalled", {"type": "log", "args": []}),
        )
        os.write(
            engine_to_client_w,
            _frame(
                "Fetch.requestPaused",
                {
                    "requestId": "r2",
                    "request": {"url": "https://example.com/y", "method": "GET"},
                },
            ),
        )
        os.write(engine_to_client_w, _frame("Page.loadEventFired", {"timestamp": 3.0}))
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with client.lock:
                landed = len(client.events)
            if landed >= 1:
                break
            time.sleep(0.01)
        reply = json.loads(os.read(client_to_engine_r, 4096).split(b"\0")[0])
        assert reply["method"] == "Fetch.continueRequest"
        assert reply["params"] == {"requestId": "r2"}
        with client.lock:
            assert [e["method"] for e in client.events] == ["Page.loadEventFired"]
    finally:
        os.close(engine_to_client_w)
        client.close()
        os.close(client_to_engine_r)


def test_a_call_waiting_when_the_pipe_ends_is_refused_at_once() -> None:
    """The pipe ends from inside the call's own wait, with the lock held, so the
    reader can end only once the call is waiting, and no other thread's
    schedule sits between the two. Only the reader's notify then wakes the
    wait; without it the wait runs out its timeout, and what `wait` returns
    tells the two apart."""
    engine_to_client_r, engine_to_client_w = os.pipe()
    client_to_engine_r, client_to_engine_w = os.pipe()
    client = CdpPipeClient(fd_in=engine_to_client_r, fd_out=client_to_engine_w)
    engine = open(engine_to_client_w, "wb", buffering=0)  # noqa: SIM115
    woken: list[bool] = []

    class EndingOnWait(threading.Condition):
        def wait(self, timeout: float | None = None) -> bool:
            engine.close()
            notified = super().wait(timeout)
            woken.append(notified)
            return notified

    client.cond = EndingOnWait(client.lock)
    try:
        with pytest.raises(BrowserError) as refusal:
            client.send("Target.getTargets", timeout=30)
    finally:
        engine.close()
        client.reader_thread.join(timeout=10)
        client.close()
        os.close(client_to_engine_r)
    assert refusal.value.code is ClosedFailure.BROWSER_CLOSED
    assert woken == [True], "the wait ran out its timeout: nothing woke it"
    assert not client.reader_thread.is_alive()


def test_session_for_arms_runtime_right_after_attach() -> None:
    double = CdpDouble([FakePage("http://fixture.test/a", "T", "text")])
    sess = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    sess.navigate("t0", "http://fixture.test/b")
    assert [(m, s) for m, _, s in double.sent] == [
        ("Target.attachToTarget", None),
        ("Runtime.enable", "s-t0"),
        ("Page.enable", "s-t0"),
        ("Page.navigate", "s-t0"),
    ]
    assert double.targets["t0"].url == "http://fixture.test/b"
    assert sess.evaluate("t0", "location.href") == "http://fixture.test/b"
    assert double.sent[-1][0] == "Runtime.evaluate"
    assert double.sent[-1][1]["awaitPromise"] is False
    sess.evaluate("t0", "fetch('/robots.txt').then(r => r.text())", await_promise=True)
    assert double.sent[-1][1]["awaitPromise"] is True


def test_double_publishes_target_urls_and_answers_the_new_methods() -> None:
    double = CdpDouble([FakePage("http://fixture.test/a", "T", "text")])
    targets = double.send("Target.getTargets")["targetInfos"]
    assert targets == [
        {"targetId": "t0", "type": "page", "url": "http://fixture.test/a"}
    ]
    for method, params in (
        ("Runtime.enable", {}),
        ("Input.dispatchMouseEvent", {"type": "mousePressed", "x": 1, "y": 1}),
        ("Storage.clearDataForOrigin", {"origin": "*", "storageTypes": "all"}),
        ("Network.clearBrowserCookies", {}),
    ):
        assert double.send(method, params, "s-t0") == {}
    shot = double.send("Page.captureScreenshot", {"format": "png"}, "s-t0")
    assert shot["data"].startswith("iVBORw0KGgo")
    ctx = double.send("Target.createBrowserContext")["browserContextId"]
    assert ctx in double.contexts
    assert double.send("Target.disposeBrowserContext", {"browserContextId": ctx}) == {}
    assert ctx not in double.contexts
    with pytest.raises(
        AssertionError, match="unhandled method Emulation.setDeviceMetricsOverride"
    ):
        double.send("Emulation.setDeviceMetricsOverride", {})


def test_double_emit_feeds_the_hook_it_was_built_with() -> None:
    seen: list[dict[str, Any]] = []
    double = CdpDouble(
        [FakePage("http://fixture.test/a", "T", "text")], on_event=seen.append
    )
    frame = {
        "method": "Runtime.consoleAPICalled",
        "sessionId": "s-t0",
        "params": {"type": "log"},
    }
    double.emit(frame)
    assert seen == [frame]
    bare = CdpDouble([FakePage("http://fixture.test/a", "T", "text")])
    with pytest.raises(AssertionError, match="emit without an on_event hook"):
        bare.emit(frame)


def test_double_evaluates_against_the_session_it_was_asked_on() -> None:
    double = CdpDouble(
        [
            FakePage("http://fixture.test/a", "A", "a"),
            FakePage("http://fixture.test/b", "B", "b"),
        ]
    )
    a = double.send("Runtime.evaluate", {"expression": "location.href"}, "s-t0")
    b = double.send("Runtime.evaluate", {"expression": "location.href"}, "s-t1")
    assert a["result"]["value"] == "http://fixture.test/a"
    assert b["result"]["value"] == "http://fixture.test/b"
    probe = double.send(
        "Runtime.evaluate",
        {
            "expression": "({w: window.innerWidth, h: window.innerHeight, dpr: window.devicePixelRatio, href: location.href})"
        },
        "s-t1",
    )
    assert probe["result"]["value"] == {
        "w": 800,
        "h": 600,
        "dpr": 1,
        "href": "http://fixture.test/b",
    }


def test_context_open_tabs_open_in_it_and_dispose_evicts() -> None:
    double = CdpDouble([FakePage("http://fixture.test/a", "T", "text")])
    sess = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    ctx = sess.context_open()
    assert ctx == "bc1"
    assert double.contexts == ["bc1"]
    tab = sess.tabs_open("http://fixture.test/b", ctx)
    assert (
        "Target.createTarget",
        {"url": "about:blank", "browserContextId": "bc1"},
        None,
    ) in double.sent
    assert double.target_context[tab] == "bc1"
    assert tab in sess._tab_sessions
    assert tab in sess.tabs_list()
    assert double.targets[tab].url == "http://fixture.test/b"
    sess.context_dispose(ctx)
    assert [m for m, _, _ in double.sent][-2:] == [
        "Target.disposeBrowserContext",
        "Target.getTargets",
    ]
    assert double.contexts == []
    assert tab not in sess._tab_sessions
    assert tab not in sess.tabs_list()
    assert "t0" in sess.tabs_list()
    plain = sess.tabs_open("http://fixture.test/c")
    assert ("Target.createTarget", {"url": "about:blank"}, None) in double.sent
    assert plain not in double.target_context
    with pytest.raises(AssertionError, match="unknown browserContextId"):
        sess.tabs_open("http://fixture.test/d", "bc-never")


def test_context_dispose_in_finally_runs_even_when_the_navigation_raises() -> None:
    from nbrowser.errors import BrowserError, ClosedFailure

    class Stalls(CdpDouble):
        def wait_event(
            self,
            method: str,
            session_id: str | None = None,
            timeout: float = 15.0,
            *,
            params: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            raise BrowserError(ClosedFailure.PROTOCOL, f"CDP event timeout: {method}")

    double = Stalls([FakePage("http://fixture.test/a", "T", "text")])
    sess = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    ctx = sess.context_open()
    with pytest.raises(BrowserError) as exc:
        try:
            sess.tabs_open("http://fixture.test/b", ctx)
        finally:
            sess.context_dispose(ctx)
    assert exc.value.code == ClosedFailure.PROTOCOL
    assert double.contexts == []
    assert sess._tab_sessions == {}
    assert [m for m, _, _ in double.sent][-2:] == [
        "Target.disposeBrowserContext",
        "Target.getTargets",
    ]


def test_same_document_navigation_skips_the_load_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = FakePage("http://fixture.test/a", "T", "text")
    double = CdpDouble([page])
    sess = BrowserSession(BrowserLaunchConfig(), client_factory=lambda: double)
    send = double.send

    def same_document(
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        if method == "Page.navigate":
            assert params == {"url": "http://fixture.test/a#section"}
            page.url = params["url"]
            return {"frameId": f"f-{session_id}"}
        return send(method, params, session_id, timeout)

    def unexpected_wait(*args: Any, **kwargs: Any) -> dict[str, Any]:
        pytest.fail("same-document navigation has no new load event")

    monkeypatch.setattr(double, "send", same_document)
    monkeypatch.setattr(double, "wait_event", unexpected_wait)
    sess.navigate("t0", "http://fixture.test/a#section")
    assert sess.evaluate("t0", "location.href") == "http://fixture.test/a#section"
