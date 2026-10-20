"""Target admission through the real CDP pipe and request policy."""

import select
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from test_ssrf_runtime import _Engine

from nbrowser.errors import BrowserError


def _request(
    session: str, frame: str, url: str, resource: str = "Document"
) -> dict[str, Any]:
    return {
        "method": "Fetch.requestPaused",
        "sessionId": session,
        "params": {
            "requestId": "request",
            "frameId": frame,
            "resourceType": resource,
            "request": {"url": url, "method": "GET", "headers": {}},
        },
    }


def _decision(engine: _Engine) -> str:
    while True:
        frame = engine.frame()
        engine.emit({"id": frame["id"], "result": {}})
        if frame["method"] in ("Fetch.continueRequest", "Fetch.failRequest"):
            return str(frame["method"])


def _opener(engine: _Engine, url: str) -> None:
    engine.emit({"id": 1, "result": {"sessionId": "parent-session"}})
    engine.emit({"id": 2, "result": {}})
    engine.client.send("Target.attachToTarget", {"targetId": "parent", "flatten": True})
    assert engine.frame()["method"] == "Target.attachToTarget"
    assert engine.frame()["method"] == "Fetch.enable"
    with ThreadPoolExecutor(max_workers=1) as pool:
        navigation = pool.submit(
            engine.client.send, "Page.navigate", {"url": url}, "parent-session", 5.0
        )
        command = engine.frame()
        assert command["method"] == "Page.navigate"
        engine.emit(_request("parent-session", "parent", url))
        try:
            assert _decision(engine) == "Fetch.continueRequest"
        finally:
            engine.emit(
                {
                    "method": "Page.frameNavigated",
                    "sessionId": "parent-session",
                    "params": {"frame": {"id": "parent", "url": url}},
                }
            )
            engine.emit({"id": command["id"], "result": {"frameId": "parent"}})
            navigation.result(timeout=5)


def _popup(engine: _Engine) -> None:
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
                    "openerFrameId": "parent",
                },
            },
        }
    )


@pytest.mark.parametrize("resource", ["Document", "Image"])
@pytest.mark.parametrize("frame", ["popup", "child-frame"])
@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("http://public.example/", "Fetch.failRequest"),
        ("http://127.0.0.1:8000/", "Fetch.continueRequest"),
    ],
)
def test_popup_keeps_its_initiating_origin(
    resource: str, frame: str, origin: str, expected: str
) -> None:
    engine = _Engine()
    try:
        _opener(engine, origin)
        _popup(engine)
        if frame == "child-frame":
            engine.emit(
                {
                    "method": "Page.frameAttached",
                    "sessionId": "popup-session",
                    "params": {"frameId": frame, "parentFrameId": "popup"},
                }
            )
        engine.emit(
            _request("popup-session", frame, "http://127.0.0.1:8000/secret", resource)
        )
        assert _decision(engine) == expected
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("unrelated_requests", [False, True])
@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8000/preview", "http://127.0.0.1:8000#preview"]
)
def test_explicit_local_navigation_has_one_main_document_permission(
    unrelated_requests: bool,
    url: str,
) -> None:
    engine = _Engine()
    request_url = url.split("#")[0]
    if "#" in url:
        request_url += "/"
    try:
        _opener(engine, "http://public.example/")
        with ThreadPoolExecutor(max_workers=1) as pool:
            navigation = pool.submit(
                engine.client.send,
                "Page.navigate",
                {"url": url},
                "parent-session",
                5.0,
            )
            command = engine.frame()
            assert command["method"] == "Page.navigate"
            try:
                requests = (
                    (("Image", "parent"), ("Document", "child"))
                    if unrelated_requests
                    else ()
                )
                for resource, frame in requests:
                    engine.emit(
                        _request(
                            "parent-session",
                            frame,
                            request_url,
                            resource,
                        )
                    )
                    assert _decision(engine) == "Fetch.failRequest"
                engine.emit(_request("parent-session", "parent", request_url))
                assert _decision(engine) == "Fetch.continueRequest"
                engine.emit(
                    _request("parent-session", "parent", "http://public.example/")
                )
                assert _decision(engine) == "Fetch.continueRequest"
                engine.emit(_request("parent-session", "parent", request_url))
                assert _decision(engine) == "Fetch.failRequest"
            finally:
                engine.emit({"id": command["id"], "result": {"frameId": "parent"}})
                navigation.result(timeout=5)
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("failure", ["timeout", "error"])
def test_failed_navigation_leaves_no_local_permission(failure: str) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        with ThreadPoolExecutor(max_workers=1) as pool:
            navigation = pool.submit(
                engine.client.send,
                "Page.navigate",
                {"url": "http://127.0.0.1:8000/preview"},
                "parent-session",
                0.1,
            )
            command = engine.frame()
            if failure == "error":
                engine.emit(
                    {
                        "id": command["id"],
                        "error": {"code": -1, "message": "Fixture refusal"},
                    }
                )
            with pytest.raises(BrowserError):
                navigation.result(timeout=5)
        engine.emit(
            _request("parent-session", "parent", "http://127.0.0.1:8000/preview")
        )
        assert _decision(engine) == "Fetch.failRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("refuse_gate", [False, True])
def test_new_target_stays_paused_until_its_gate_is_ready(refuse_gate: bool) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        _popup(engine)
        first = engine.frame()
        assert first["method"] == "Fetch.enable"
        assert first["sessionId"] == "popup-session"
        engine.emit({"method": "Test.barrier", "params": {}})
        engine.client.wait_event("Test.barrier", timeout=5)
        assert b"\0" not in engine.buf
        assert not select.select([engine.from_client], [], [], 0)[0]
        engine.emit(
            {"id": first["id"], "error": {"code": -1, "message": "Fixture refusal"}}
            if refuse_gate
            else {"id": first["id"], "result": {}}
        )
        methods = []
        while True:
            frame = engine.frame()
            methods.append(frame["method"])
            engine.emit({"id": frame["id"], "result": {}})
            if frame["method"] in (
                "Runtime.runIfWaitingForDebugger",
                "Target.closeTarget",
            ):
                break
        if refuse_gate:
            assert methods == ["Target.closeTarget"]
            assert frame["params"]["targetId"] == "popup"
        else:
            assert "Target.setAutoAttach" in methods
            assert "Page.addScriptToEvaluateOnNewDocument" in methods
            assert methods[-1] == "Runtime.runIfWaitingForDebugger"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


def test_session_reuses_the_guarded_auto_attachment() -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://public.example/")
        with ThreadPoolExecutor(max_workers=1) as pool:
            enable = pool.submit(
                engine.client.send,
                "Target.setAutoAttach",
                {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
            )
            command = engine.frame()
            engine.emit({"id": command["id"], "result": {}})
            enable.result(timeout=5)
            _popup(engine)
            attached = pool.submit(
                engine.client.send,
                "Target.attachToTarget",
                {"targetId": "popup", "flatten": True},
                None,
                5.0,
            )
            while True:
                command = engine.frame()
                assert command["method"] != "Target.attachToTarget"
                assert not attached.done()
                engine.emit({"id": command["id"], "result": {}})
                if command["method"] == "Runtime.runIfWaitingForDebugger":
                    break
            assert attached.result(timeout=5) == {"sessionId": "popup-session"}
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize("separate_target", [False, True])
def test_public_subframe_cannot_inherit_local_main_frame_permission(
    separate_target: bool,
) -> None:
    engine = _Engine()
    try:
        _opener(engine, "http://127.0.0.1:8000/")
        if separate_target:
            engine.emit(
                {
                    "method": "Target.attachedToTarget",
                    "sessionId": "parent-session",
                    "params": {
                        "sessionId": "child-session",
                        "waitingForDebugger": True,
                        "targetInfo": {
                            "targetId": "child",
                            "type": "iframe",
                            "url": "http://public.example/",
                        },
                    },
                }
            )
            session, frame = "child-session", "child"
        else:
            engine.emit(
                _request("parent-session", "public-frame", "http://public.example/")
            )
            assert _decision(engine) == "Fetch.continueRequest"
            engine.emit(
                {
                    "method": "Page.frameAttached",
                    "sessionId": "parent-session",
                    "params": {
                        "frameId": "blank-child",
                        "parentFrameId": "public-frame",
                    },
                }
            )
            session, frame = "parent-session", "blank-child"
        engine.emit(_request(session, frame, "http://127.0.0.1:8000/secret", "Image"))
        assert _decision(engine) == "Fetch.failRequest"
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
