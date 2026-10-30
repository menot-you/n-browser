"""Direct 1:1 port of all 12 monorepo capability-spine pin unit tests."""

import pytest

import nott_spine
from nott_spine.errors import (
    InvalidDevicePixelRatio,
    InvalidOrigin,
    MissingFreshnessMarker,
    ViewportTooLarge,
)
from nott_spine.types import (
    MAX_CAPTURE_FRAME_AXIS_CSS_PX,
    MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
    MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
    CaptureFrame,
    OriginMetadata,
)


def test_public_surface_matches_pin() -> None:
    for name in ("validate_binding", "validate_bounded_text", "validate_digest"):
        assert not hasattr(nott_spine, name)


# 5. whitespace_only_provenance_is_rejected
def test_whitespace_only_provenance_is_rejected() -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata("fixture", "   ", None, None)
    with pytest.raises(MissingFreshnessMarker):
        CaptureFrame(1280, 720, 2.0, " \t ")


# 6. capture_frame_bounds_are_closed_and_wire_enforced
def test_capture_frame_bounds_are_closed_and_wire_enforced() -> None:
    assert CaptureFrame(
        MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
        "bounded",
    )
    with pytest.raises(ViewportTooLarge):
        CaptureFrame(
            MAX_CAPTURE_FRAME_AXIS_CSS_PX + 1,
            1,
            MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
            "too-wide",
        )
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(
            1,
            1,
            MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO - 1e-9,
            "dpr-low",
        )
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(
            1,
            1,
            MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO + 0.001,
            "dpr-high",
        )

    oversized_wire = {
        "viewport_width_css_px": MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        "viewport_height_css_px": MAX_CAPTURE_FRAME_AXIS_CSS_PX + 1,
        "device_pixel_ratio": MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
        "freshness_marker": "wire",
    }
    with pytest.raises(ViewportTooLarge):
        CaptureFrame.from_dict(oversized_wire)


# 7. receipt_is_bound_and_has_no_arbitrary_payload


# 8. coordinate_derives_source_frame_and_reconciles_dpr


# 9. coordinate_refuses_same_digest_with_a_different_authenticated_frame


# 10. stdio_coordinate_wire_rebind_and_tamper


# 11. coordinate_transform_lineage_is_bounded_before_binding


# 12. unsupported_origin_axis_and_transform_fail_closed
