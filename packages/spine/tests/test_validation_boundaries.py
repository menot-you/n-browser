"""Public numeric boundaries must refuse malformed input with typed errors."""

from typing import Any

import pytest

from nott_spine.errors import (
    EmptyViewport,
    InvalidDevicePixelRatio,
    InvalidOrigin,
    MissingCaptureFrame,
)
from nott_spine.types import (
    CaptureFrame,
    OriginKind,
    OriginMetadata,
)


@pytest.mark.parametrize("axis", ["viewport_width_css_px", "viewport_height_css_px"])
@pytest.mark.parametrize(
    "value", [-1, -8192, True, False, 1.0, float("nan"), float("inf"), "1", None]
)
@pytest.mark.parametrize("wire", [False, True])
def test_capture_dimensions_are_positive_integers(
    axis: str, value: Any, wire: bool
) -> None:
    fields: dict[str, Any] = {
        "viewport_width_css_px": 1280,
        "viewport_height_css_px": 720,
        "device_pixel_ratio": 1.0,
        "freshness_marker": "x",
    }
    fields[axis] = value
    with pytest.raises(EmptyViewport):
        if wire:
            CaptureFrame.from_dict(fields)
        else:
            CaptureFrame(**fields)


@pytest.mark.parametrize(
    "value",
    [True, False, "1", None, float("nan"), float("inf"), -float("inf"), 10**400],
)
def test_capture_dpr_is_a_finite_number_not_a_boolean(value: Any) -> None:
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(1280, 720, value, "x")


@pytest.mark.parametrize("kind", [True, 1, 1.0, None, [], {}])
def test_origin_kind_refuses_non_enums(kind: Any) -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata(kind, "fixture://page")


@pytest.mark.parametrize(
    "kind", [OriginKind.AllowedRootFile, OriginKind.BrowserCapture]
)
def test_direct_origin_constructor_requires_capture_frame(kind: OriginKind) -> None:
    with pytest.raises(MissingCaptureFrame):
        OriginMetadata(kind, "fixture://page")


@pytest.mark.parametrize("frame", [True, 1, {}, "frame"])
def test_origin_refuses_non_frame_objects(frame: Any) -> None:
    with pytest.raises(MissingCaptureFrame):
        OriginMetadata("fixture", "fixture://page", capture_frame=frame)


@pytest.mark.parametrize("text", ["\ud800", "valid\udfff"])
def test_origin_refuses_non_utf8_text_with_contract_error(text: str) -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata("fixture", text)
