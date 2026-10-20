"""Public numeric boundaries must refuse malformed input with typed errors."""

from typing import Any

import pytest

from nott_spine.authority import ContentAuthority, UntrustedContentRef
from nott_spine.errors import (
    EmptyViewport,
    InvalidAuthorityKey,
    InvalidDevicePixelRatio,
    InvalidOrigin,
    MissingCaptureFrame,
)
from nott_spine.types import (
    CaptureFrame,
    OriginKind,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)


def source_ref() -> Any:
    return (
        ContentAuthority.from_secret(bytes(range(32)))
        .issuer(SourceCapability.NBrowser)
        .issue(
            "sha256:" + "a" * 64,
            OriginMetadata.browser_capture(
                "fixture://page", capture_frame=CaptureFrame(1280, 720, 2, "x")
            ),
            RetentionPolicy.NoStore,
            TaintClass.PixelDerived,
        )
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


@pytest.mark.parametrize("axis", ["x", "y"])
@pytest.mark.parametrize(
    "value", [True, False, "1", None, 10**400, float("nan"), float("inf"), -1]
)
def test_source_points_refuse_malformed_values(axis: str, value: Any) -> None:
    point = {"x": 1, "y": 2}
    point[axis] = value


@pytest.mark.parametrize("field", ["source_capability", "retention", "taint"])
@pytest.mark.parametrize("value", [True, 1, 1.0, None, [], {}])
def test_content_enum_fields_refuse_non_enums(field: str, value: Any) -> None:
    fields = source_ref().to_dict()
    fields[field] = value
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef.from_dict(fields)


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


@pytest.mark.parametrize(
    "secret", [True, 32, None, "x" * 32, [True] * 32, [256] * 32, [-1] * 32, [1.0] * 32]
)
def test_authority_key_refuses_non_byte_values(secret: Any) -> None:
    with pytest.raises(InvalidAuthorityKey):
        ContentAuthority.from_secret(secret)


@pytest.mark.parametrize("text", ["\ud800", "valid\udfff"])
def test_origin_refuses_non_utf8_text_with_contract_error(text: str) -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata("fixture", text)
