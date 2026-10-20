"""nbrowser_page_capture emits a ContentRef this process signed, taken on the
tab's own CDP session; the bytes stay in custody and never ride the text door."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

import nott_database
import pytest
from cdp_double import PNG_1X1_BASE64, CdpDouble, FakePage
from nott_spine import (
    UntrustedContentRef,
)

from nbrowser.errors import BrowserError, FailureCode, InputFailure
from nbrowser.mcp_server import TOOL_DESCRIPTIONS, McpServer
from nbrowser.session import BrowserLaunchConfig, BrowserSession


def _page() -> FakePage:
    """A fresh page per server: a test that moves its page must not move the next one's.

    A shared module-level page did, and the capture test failed whenever the
    other-origin test ran first (mutmut's clean run on 2026-09-26)."""
    return FakePage("http://fixture.test/a", "T", "double text")


PNG_BYTES = base64.b64decode(PNG_1X1_BASE64)
PNG_DIGEST = hashlib.sha256(PNG_BYTES).hexdigest()


def _double_server(
    pages: list[FakePage] | None = None,
) -> tuple[McpServer, CdpDouble]:
    server = McpServer()
    double = CdpDouble(
        [_page()] if pages is None else pages, on_event=server.on_cdp_event
    )
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    return server, double


def test_capture_emits_a_source_bound_to_the_real_frame_on_the_tabs_session() -> None:
    server, double = _double_server()
    res = server.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    assert res["ref"] == "capture:" + PNG_DIGEST
    assert res["sha256"] == PNG_DIGEST
    assert res["bytes"] == len(PNG_BYTES)
    assert res["taint"] == "pixel_derived"
    assert res["retention"] == "no_store"
    source = res["source"]
    assert source["digest"] == "sha256:" + PNG_DIGEST
    assert source["source_capability"] == "nbrowser"
    assert source["retention"] == "no_store"
    assert source["taint"] == "pixel_derived"
    assert source["origin"]["kind"] == "browser_capture"
    assert source["origin"]["locator"] == "http://fixture.test"
    assert source["origin"]["captured_at"].endswith("Z")
    assert source["origin"]["capture_frame"] == {
        "viewport_width_css_px": 800,
        "viewport_height_css_px": 600,
        "device_pixel_ratio": 1.0,
        "freshness_marker": PNG_DIGEST,
    }
    resolved = server.content_authority.resolver().resolve(
        UntrustedContentRef.from_dict(source)
    )
    assert resolved.digest == "sha256:" + PNG_DIGEST
    assert [(m, s) for m, _, s in double.sent] == [
        ("Target.getTargets", None),
        ("Target.attachToTarget", None),
        ("Runtime.enable", "s-t0"),
        ("Runtime.evaluate", "s-t0"),
        ("Page.captureScreenshot", "s-t0"),
    ]
    assert double.sent[3][1]["expression"].startswith("({w: window.innerWidth")
    ephemeral = server.handle_tool_call(
        "nbrowser_page_capture", {"retention": "ephemeral_session"}
    )
    assert ephemeral["source"]["retention"] == "ephemeral_session"
    assert [m for m, _, _ in double.sent].count("Target.attachToTarget") == 1


def test_capture_refusals() -> None:
    server, _ = _double_server()
    with pytest.raises(BrowserError) as exc_bad:
        server.handle_tool_call("nbrowser_page_capture", {"retention": "forever"})
    assert exc_bad.value.code == InputFailure.OPERATION

    empty, _ = _double_server([])
    with pytest.raises(BrowserError) as exc_notab:
        empty.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    assert exc_notab.value.code == FailureCode.NO_ACTIVE_SESSION

    sess = server.get_session()
    sess.tabs_list = lambda: ["t0"]  # type: ignore[method-assign]
    sess.client = None
    with pytest.raises(BrowserError) as exc_noclient:
        server.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    assert exc_noclient.value.code == FailureCode.NO_ACTIVE_SESSION

    class MuteProbe(CdpDouble):
        def _evaluate(self, expression: str) -> Any:
            if "window.innerWidth" in expression:
                return None
            return super()._evaluate(expression)

    mute_server = McpServer()
    mute = MuteProbe([_page()], on_event=mute_server.on_cdp_event)
    mute_server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: mute
    )
    with pytest.raises(BrowserError) as exc_probe:
        mute_server.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    assert exc_probe.value.code == FailureCode.CAPTURE_EXPORT_FAILED


def test_content_show_refuses_a_capture_and_no_capture_bytes_are_stored() -> None:
    server, _ = _double_server()
    res = server.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    with pytest.raises(BrowserError) as text_refusal:
        server.handle_tool_call("nbrowser_content_show", {"ref": res["ref"]})
    assert text_refusal.value.code == FailureCode.CONTENT_UNAVAILABLE
    assert "capture" in text_refusal.value.message
    # The digest is the ref: no capture blob is kept in the resolver store.
    assert res["ref"] not in server.resolver.store


def test_capture_refuses_a_non_numeric_viewport_probe() -> None:
    class StringProbe(CdpDouble):
        def _evaluate(self, expression: str) -> Any:
            if "window.innerWidth" in expression:
                return {
                    "w": "x",
                    "h": 600,
                    "dpr": 1,
                    "href": "http://fixture.test/home",
                }
            return super()._evaluate(expression)

    server = McpServer()
    double = StringProbe([_page()], on_event=server.on_cdp_event)
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call("nbrowser_page_capture", {"retention": "no_store"})
    assert exc.value.code is FailureCode.CAPTURE_EXPORT_FAILED
    assert "Page.captureScreenshot" not in [m for m, _, _ in double.sent]


def _bad_probe_server(probe: dict[str, Any]) -> tuple[McpServer, CdpDouble]:
    class BadProbe(CdpDouble):
        def _evaluate(self, expression: str) -> Any:
            if "window.innerWidth" in expression:
                return probe
            return super()._evaluate(expression)

    server = McpServer()
    double = BadProbe([_page()], on_event=server.on_cdp_event)
    server.session = BrowserSession(
        BrowserLaunchConfig(headless=True), client_factory=lambda: double
    )
    return server, double


def test_capture_refuses_a_scaled_dpr_before_keeping_the_png(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dpr the spine rejects must be a typed export failure with nothing kept."""
    monkeypatch.setenv("NOTT_NBROWSER_CAPTURE_KEEP", "1")
    server, _ = _bad_probe_server(
        {"w": 800, "h": 600, "dpr": 0.75, "href": "http://fixture.test/a"}
    )
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call(
            "nbrowser_page_capture", {"retention": "managed_purgeable"}
        )
    assert exc.value.code == FailureCode.CAPTURE_EXPORT_FAILED
    root = nott_database.directory().parent / "captures"
    assert not (root / f"{PNG_DIGEST}.png").exists()


def test_capture_refuses_an_oversized_viewport_axis_before_keeping_the_png(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An axis over 8192 css px must be a typed export failure with nothing kept."""
    monkeypatch.setenv("NOTT_NBROWSER_CAPTURE_KEEP", "1")
    server, _ = _bad_probe_server(
        {"w": 8193, "h": 600, "dpr": 1, "href": "http://fixture.test/a"}
    )
    with pytest.raises(BrowserError) as exc:
        server.handle_tool_call(
            "nbrowser_page_capture", {"retention": "managed_purgeable"}
        )
    assert exc.value.code == FailureCode.CAPTURE_EXPORT_FAILED
    root = nott_database.directory().parent / "captures"
    assert not (root / f"{PNG_DIGEST}.png").exists()


def test_managed_purgeable_keeps_the_png_only_where_a_nott_host_names_the_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTT_NBROWSER_CAPTURE_KEEP", "1")
    root = nott_database.directory().parent / "captures"
    server, _ = _double_server()
    res = server.handle_tool_call(
        "nbrowser_page_capture", {"retention": "managed_purgeable"}
    )
    assert res["ref"] == "capture:" + PNG_DIGEST
    assert res["sha256"] == PNG_DIGEST
    assert res["retention"] == "managed_purgeable"
    assert res["source"]["retention"] == "managed_purgeable"
    assert (root / f"{PNG_DIGEST}.png").read_bytes() == PNG_BYTES
    assert [p.name for p in root.iterdir()] == [f"{PNG_DIGEST}.png"]

    # A database directory alone does not grant capture retention.
    parent = root.parent
    (root / f"{PNG_DIGEST}.png").unlink()
    monkeypatch.delenv("NOTT_NBROWSER_CAPTURE_KEEP")
    plain, _ = _double_server()
    with pytest.raises(BrowserError) as refused:
        plain.handle_tool_call(
            "nbrowser_page_capture", {"retention": "managed_purgeable"}
        )
    assert refused.value.code == FailureCode.GRANT_REQUIRED
    assert [p for p in parent.rglob("*") if p.is_file()] == []


def test_a_capture_root_that_is_refused_is_a_typed_export_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTT_NBROWSER_CAPTURE_KEEP", "1")
    root = nott_database.directory().parent / "captures"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.symlink_to(elsewhere)
    server, _ = _double_server()
    with pytest.raises(BrowserError) as refused:
        server.handle_tool_call(
            "nbrowser_page_capture", {"retention": "managed_purgeable"}
        )
    assert refused.value.code == FailureCode.CAPTURE_EXPORT_FAILED
    assert "link" in refused.value.message
    assert os.listdir(elsewhere) == []


def test_the_capture_description_names_when_managed_purgeable_is_refused() -> None:
    text = TOOL_DESCRIPTIONS["nbrowser_page_capture"]
    assert "always refused" not in text
    assert "no_store and ephemeral_session keep no bytes" in text
    assert "managed_purgeable keeps one copy in the owner's capture cache" in text
    assert "refused (grant_required) when a NOTT host did not start this server" in text
