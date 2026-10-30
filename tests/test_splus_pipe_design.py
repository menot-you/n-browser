"""Python CDP decoding over real OS pipes; no claim of browser JavaScript execution."""

from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from cdp_double import CdpDouble, FakePage
from test_ssrf_runtime import _Engine

from nbrowser.design import DESIGN_PROBE, read_design_blueprint
from nbrowser.errors import BrowserError, ClosedFailure
from nbrowser.mcp_server import McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession


def _evaluate_frames(engine: _Engine, value: object) -> None:
    for index, result in enumerate(
        [{"sessionId": "s1"}, {}, {}, {"result": {"value": value}}], 1
    ):
        engine.emit({"id": index, "result": result})


def test_design_wire_preserves_shapes_and_scrubs_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _Engine()
    try:
        session = BrowserSession(
            BrowserLaunchConfig(), client_factory=lambda: engine.client
        )
        raw: dict[str, Any] = {
            "viewport": {"width": 900, "height": 600, "dpr": 2},
            "theme": {
                "palette": ["red"],
                "fonts": ["Inter", "Café"],
                "spacing": ["4px"],
                "custom_properties": [{"name": "--paint", "value": "red"}, None],
            },
            "layout": [
                None,
                {"tag": "main", "role": "main", "parent": None},
                {"tag": "p", "parent": 0, "text": "hello", "text_trailing": True},
            ],
            "assets": [
                None,
                {"src": "[inline-data-redacted]"},
                {
                    "kind": "image",
                    "src": "https://fixture.test/a?token=secret",
                    "width": 10,
                    "height": 20,
                    "truncated": True,
                },
            ],
            "svgs": [
                None,
                {
                    "view_box": "0 0 10 20",
                    "width": 10,
                    "height": 20,
                    "truncated": True,
                    "shapes": [
                        None,
                        {
                            "tag": "path",
                            "geometry": {"d": "M0 0L10 20", "fill": "url(#paint)"},
                        },
                    ],
                },
                {"shapes": []},
            ],
            "animations": {
                "animated": [
                    None,
                    {
                        "tag": "p",
                        "transition": "all 1s",
                        "animation_name": "pulse",
                        "animation_duration": "1s",
                    },
                ],
                "keyframes": ["pulse"],
            },
            "truncated": True,
        }
        _evaluate_frames(engine, raw)
        blueprint = read_design_blueprint(session, "t1")
        evidence = asdict(blueprint)
        frames = [engine.frame() for _ in range(4)]
        assert [frame["method"] for frame in frames] == [
            "Target.attachToTarget",
            "Fetch.enable",
            "Runtime.enable",
            "Runtime.evaluate",
        ]
        assert frames[-1]["params"]["expression"] == DESIGN_PROBE
        assert frames[-1]["sessionId"] == "s1"
        assert evidence["viewport"] == {"width": 900.0, "height": 600.0, "dpr": 2.0}
        assert evidence["theme"]["custom_properties"] == [
            {"name": "--paint", "value": "red"}
        ]
        assert len(evidence["layout"]) == 2
        assert evidence["layout"][0]["role"] == "main"
        assert evidence["layout"][1]["parent"] == 0
        assert evidence["layout"][1]["text"] == "hello"
        assert evidence["assets"] == [
            {
                "kind": "image",
                "src": "[inline-data-redacted]",
                "width": None,
                "height": None,
                "truncated": None,
            },
            {
                "kind": "image",
                "src": "https://fixture.test/a?token=%5Bredacted%5D",
                "width": 10,
                "height": 20,
                "truncated": True,
            },
        ]
        assert evidence["svgs"] == [
            {
                "view_box": "0 0 10 20",
                "width": 10,
                "height": 20,
                "truncated": True,
                "shapes": [
                    {
                        "tag": "path",
                        "geometry": {"d": "M0 0L10 20", "fill": "url(#paint)"},
                    }
                ],
            },
            {"view_box": "", "width": 0, "height": 0, "shapes": [], "truncated": None},
        ]
        assert evidence["animations"] == {
            "animated": [
                {
                    "tag": "p",
                    "transition": "all 1s",
                    "animation_name": "pulse",
                    "animation_duration": "1s",
                }
            ],
            "keyframes": ["pulse"],
        }
        assert evidence["truncated"] is True
        server = McpServer()
        server.session = BrowserSession(
            BrowserLaunchConfig(),
            client_factory=lambda: CdpDouble(
                [FakePage("https://fixture.test", "T", "")]
            ),
        )
        monkeypatch.setattr(
            "nbrowser.mcp_server.read_design_blueprint", lambda *_: blueprint
        )
        try:
            reply = server.call_tool("nbrowser_page_scrape", {"format": "design"})
            wire = reply["content"][0]["text"].encode("utf-8")
            fixture = Path(__file__).parent / "fixtures" / "design-wire.json"
            assert wire == fixture.read_bytes()
            assert reply == {
                "content": [{"type": "text", "text": wire.decode("utf-8")}]
            }
        finally:
            server.close()
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()


def test_design_nonobject_wire_reply_is_empty_evidence() -> None:
    engine = _Engine()
    try:
        session = BrowserSession(
            BrowserLaunchConfig(), client_factory=lambda: engine.client
        )
        _evaluate_frames(engine, None)
        evidence = read_design_blueprint(session, "t1")
        assert evidence.layout == evidence.assets == evidence.svgs == []
        assert evidence.viewport.width == 0
        assert evidence.viewport.dpr == 1
        assert not evidence.truncated
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)


@pytest.mark.parametrize(
    "method,args",
    [
        ("tabs_list", ()),
        ("tabs_open", ("https://fixture.test",)),
        ("context_open", ()),
        ("context_dispose", ("c1",)),
        ("navigate", ("t1", "https://fixture.test")),
        ("evaluate", ("t1", "1")),
        ("_session_for", ("t1",)),
        ("mark_active", ()),
    ],
)
def test_permanently_closed_pipe_session_refuses_operations(
    method: str, args: tuple[str, ...]
) -> None:
    engine = _Engine()
    try:
        session = BrowserSession(
            BrowserLaunchConfig(), client_factory=lambda: engine.client
        )
        session.close_session()
        session.close_session()
        with pytest.raises(BrowserError) as exc:
            getattr(session, method)(*args)
        assert exc.value.code is ClosedFailure.BROWSER_CLOSED
        assert session.client is None
    finally:
        engine.close()
        engine.client.reader_thread.join(timeout=2)
        assert not engine.client.reader_thread.is_alive()
