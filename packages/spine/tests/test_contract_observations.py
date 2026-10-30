"""Observable value, diagnostic and refusal contracts for spine consumers."""

import json
from typing import Any

import pytest

from nott_spine.errors import (
    ContractError,
)
from nott_spine.types import (
    CaptureFrame,
    OriginKind,
    OriginMetadata,
)


def test_typed_error_messages() -> None:
    assert str(ContractError()) == "contract violation"
    assert str(ContractError("")) == "contract violation"
    assert str(ContractError("context")) == "context"


@pytest.mark.parametrize("kind", list(OriginKind))
def test_origin_value_roundtrip_and_diagnostics(kind: OriginKind) -> None:
    frame = CaptureFrame(1280, 720, 2, "fresh")
    origin = OriginMetadata(kind, "fixture://page", "now", frame)
    decoded = OriginMetadata.from_dict(json.loads(json.dumps(origin.to_dict())))
    assert decoded == origin
    assert origin != object()
    assert (
        repr(origin)
        == f"OriginMetadata(kind={kind!r}, locator='fixture://page', captured_at='now', capture_frame={frame!r})"
    )
    assert (
        repr(frame)
        == "CaptureFrame(viewport_width_css_px=1280, viewport_height_css_px=720, device_pixel_ratio=2.0, freshness_marker='fresh')"
    )
    assert frame != object()


@pytest.mark.parametrize(
    "replacement",
    [
        {"kind": "derived_content"},
        {"locator": "fixture://other"},
        {"captured_at": "later"},
        {"capture_frame": None},
    ],
)
def test_origin_equality_distinguishes_trace_metadata(
    replacement: dict[str, Any],
) -> None:
    origin = OriginMetadata(
        "fixture", "fixture://page", "now", CaptureFrame(1280, 720, 2, "fresh")
    )
    changed = origin.to_dict() | replacement
    assert OriginMetadata.from_dict(changed) != origin


@pytest.mark.parametrize(
    "replacement",
    [
        {"viewport_width_css_px": 100},
        {"viewport_height_css_px": 100},
        {"device_pixel_ratio": 1.0},
        {"freshness_marker": "later"},
    ],
)
def test_frame_equality_distinguishes_capture_identity(
    replacement: dict[str, Any],
) -> None:
    frame = CaptureFrame(1280, 720, 2, "fresh")
    assert CaptureFrame.from_dict(frame.to_dict() | replacement) != frame
