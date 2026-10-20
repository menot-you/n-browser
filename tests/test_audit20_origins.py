"""Frame origins and repeated navigation at the browser boundary."""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from cdp_double import CdpDouble, FakePage
from test_audit20_targets import _decision, _opener, _request
from test_ssrf_runtime import _Engine

from nbrowser.egress_proxy import EgressProxy
from nbrowser.errors import BrowserError, FailureCode
from nbrowser.session import BrowserLaunchConfig, BrowserSession


def _attached(engine: _Engine, session: str, frame: str, parent: str) -> None:
    engine.emit(
        {
            "method": "Page.frameAttached",
            "sessionId": session,
            "params": {"frameId": frame, "parentFrameId": parent},
        }
    )


def _committed(
    engine: _Engine, session: str, frame: str, url: str, origin: str
) -> None:
    engine.emit(
        {
            "method": "Page.frameNavigated",
            "sessionId": session,
            "params": {
                "frame": {
                    "id": frame,
                    "parentId": "parent",
                    "url": url,
                    "securityOrigin": origin,
                }
            },
        }
    )


@pytest.mark.parametrize("url", ["http://public.example/", "about:blank"])
@pytest.mark.parametrize("effect", ["image", "blank-child", "popup"])
def test_committed_public_frame_cannot_inherit_local_ancestor_permission(
    url: str, effect: str
) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://127.0.0.1:8000/")
        _attached(engine, "parent-session", "public-frame", "parent")
        _committed(
            engine, "parent-session", "public-frame", url, "http://public.example"
        )
        session, frame = "parent-session", "public-frame"
        if effect == "blank-child":
            _attached(engine, session, "blank-child", frame)
            frame = "blank-child"
        elif effect == "popup":
            engine.emit(
                {
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "popup-session",
                        "waitingForDebugger": True,
                        "targetInfo": {
                            "targetId": "popup",
                            "type": "page",
                            "url": "about:blank",
                            "openerId": "parent",
                            "openerFrameId": frame,
                        },
                    },
                }
            )
            session, frame = "popup-session", "popup"
        engine.emit(_request(session, frame, "http://127.0.0.1:8000/landing", "Image"))
        assert _decision(engine) == "Fetch.failRequest"
        engine.emit(_request(session, frame, "http://other.example/control", "Image"))
        assert _decision(engine) == "Fetch.continueRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("target_url", ["", "about:blank", "http://public.example/"])
def test_frame_origin_survives_target_transfer_before_child_request(
    target_url: str,
) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://127.0.0.1:8000/")
        _attached(engine, "parent-session", "public-frame", "parent")
        engine.emit(
            _request("parent-session", "public-frame", "http://public.example/")
        )
        assert _decision(engine) == "Fetch.continueRequest"
        engine.emit(
            {
                "method": "Page.frameDetached",
                "sessionId": "parent-session",
                "params": {"frameId": "public-frame", "reason": "swap"},
            }
        )
        engine.emit(
            {
                "method": "Target.attachedToTarget",
                "sessionId": "parent-session",
                "params": {
                    "sessionId": "child-session",
                    "waitingForDebugger": True,
                    "targetInfo": {
                        "targetId": "public-frame",
                        "type": "iframe",
                        "url": target_url,
                    },
                },
            }
        )
        _attached(engine, "child-session", "blank-child", "public-frame")
        engine.emit(
            _request(
                "child-session", "blank-child", "http://127.0.0.1:8000/landing", "Image"
            )
        )
        assert _decision(engine) == "Fetch.failRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


def test_unknown_frame_cannot_borrow_local_main_frame_permission() -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://127.0.0.1:8000/")
        engine.emit(
            _request(
                "parent-session",
                "unknown-frame",
                "http://127.0.0.1:8000/landing",
                "Image",
            )
        )
        assert _decision(engine) == "Fetch.failRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize(
    ("requested", "actual"),
    [
        ("http://127.0.0.1:8000/a/../preview", "http://127.0.0.1:8000/preview"),
        ("http://LOCALHOST:80/a/../preview", "http://localhost/preview"),
        ("http://[0:0:0:0:0:0:0:1]:8000/a/../preview", "http://[::1]:8000/preview"),
        ("http://localhost:8000/a/../preview#owner", "http://localhost:8000/preview"),
    ],
)
def test_explicit_navigation_matches_the_canonical_origin_once(
    requested: str, actual: str
) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        with ThreadPoolExecutor(max_workers=1) as pool:
            navigation = pool.submit(
                engine.client.send,
                "Page.navigate",
                {"url": requested},
                "parent-session",
                5.0,
            )
            command = engine.frame()
            try:
                engine.emit(_request("parent-session", "parent", actual))
                assert _decision(engine) == "Fetch.continueRequest"
                engine.emit(_request("parent-session", "parent", actual, "Image"))
                assert _decision(engine) == "Fetch.failRequest"
            finally:
                engine.emit({"id": command["id"], "result": {"frameId": "parent"}})
                navigation.result(timeout=5)
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("redirect", [False, True])
def test_local_navigation_permission_does_not_change_the_uncommitted_frame(
    redirect: bool,
) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        with ThreadPoolExecutor(max_workers=1) as pool:
            navigation = pool.submit(
                engine.client.send,
                "Page.navigate",
                {"url": "http://127.0.0.1:8000/preview"},
                "parent-session",
                5.0,
            )
            command = engine.frame()
            try:
                engine.emit(
                    _request(
                        "parent-session", "parent", "http://127.0.0.1:8000/preview"
                    )
                )
                assert _decision(engine) == "Fetch.continueRequest"
                if redirect:
                    hop = _request(
                        "parent-session", "parent", "http://127.0.0.1:8000/next"
                    )
                    hop["params"]["redirectedRequestId"] = "request"
                    hop["params"]["requestId"] = "redirect"
                    engine.emit(hop)
                    assert _decision(engine) == "Fetch.continueRequest"
                engine.emit(
                    _request(
                        "parent-session",
                        "parent",
                        "http://127.0.0.1:8000/landing",
                        "Image",
                    )
                )
                assert _decision(engine) == "Fetch.failRequest"
            finally:
                engine.emit({"id": command["id"], "result": {"frameId": "parent"}})
                navigation.result(timeout=5)
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "http://public.example"])
def test_committed_frame_keeps_admitted_requests(origin: str) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        _attached(engine, "parent-session", "child", "parent")
        _committed(engine, "parent-session", "child", origin + "/", origin)
        _attached(engine, "parent-session", "blank-child", "child")
        engine.emit(
            _request("parent-session", "blank-child", origin + "/control", "Image")
        )
        assert _decision(engine) == "Fetch.continueRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize(
    "answers", [["10.0.0.5"], ["93.184.216.34", "10.0.0.5"], ["127.0.0.1"]]
)
def test_navigation_rechecks_dns_before_reusing_browser_transport(
    monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    current = ["93.184.216.34"]
    lookups: list[str] = []

    def resolve(host: str, port: int, **kwargs: Any) -> list[Any]:
        lookups.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
            for ip in current
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    client = CdpDouble([FakePage("about:blank", "", "")])
    session = BrowserSession(BrowserLaunchConfig(), client_factory=lambda: client)
    # The protocol peer returns success without opening another connection.
    session.egress_proxy = object.__new__(EgressProxy)
    try:
        session.navigate("t0", "http://rebind.example/")
        current[:] = answers
        before = list(client.sent)
        with pytest.raises(BrowserError) as error:
            session.navigate("t0", "http://rebind.example/secret")
        assert error.value.code is FailureCode.GRANT_REQUIRED
        assert client.sent == before
        assert lookups == ["rebind.example", "rebind.example"]
    finally:
        session.egress_proxy = None
        session.close_session()
