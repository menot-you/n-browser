"""Tests for nott_spine types, enums, frames, origin metadata, and error families."""

import json

import pytest

from nott_spine.errors import (
    AuthorityError,
    BindingMismatch,
    ContractError,
    EmptyViewport,
    InvalidBinding,
    InvalidDevicePixelRatio,
    InvalidDigest,
    InvalidOrigin,
    MissingCaptureFrame,
    MissingFreshnessMarker,
    ViewportTooLarge,
)
from nott_spine.types import (
    MAX_CAPTURE_FRAME_AXIS_CSS_PX,
    MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
    MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
    CaptureFrame,
    OriginKind,
    OriginMetadata,
    ReceiptRung,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
    validate_binding,
    validate_bounded_text,
    validate_digest,
)


def test_enums_wire_names_and_codes() -> None:
    # SourceCapability
    assert list(SourceCapability) == [
        SourceCapability.NBrowser,
        SourceCapability.NVision,
    ]
    assert SourceCapability.NBrowser.value == "nbrowser"
    assert SourceCapability.NVision.value == "nvision"
    assert SourceCapability.NBrowser.code() == 1
    assert SourceCapability.NVision.code() == 2
    assert not hasattr(SourceCapability, "NBROWSER")
    assert not hasattr(SourceCapability, "NVISION")

    # OriginKind
    assert list(OriginKind) == [
        OriginKind.Fixture,
        OriginKind.AllowedRootFile,
        OriginKind.BrowserCapture,
        OriginKind.DerivedContent,
    ]
    assert OriginKind.Fixture.value == "fixture"
    assert OriginKind.AllowedRootFile.value == "allowed_root_file"
    assert OriginKind.BrowserCapture.value == "browser_capture"
    assert OriginKind.DerivedContent.value == "derived_content"
    assert not hasattr(OriginKind, "FIXTURE")
    assert not hasattr(OriginKind, "ALLOWED_ROOT_FILE")

    # TaintClass
    assert list(TaintClass) == [
        TaintClass.PageDerived,
        TaintClass.PixelDerived,
        TaintClass.OcrDerived,
        TaintClass.NetworkMetadata,
        TaintClass.HostFileDerived,
        TaintClass.ThirdPartyText,
        TaintClass.OwnerStated,
        TaintClass.BodyObserved,
        TaintClass.ExecClaimed,
        TaintClass.ThirdParty,
    ]
    assert TaintClass.PageDerived.value == "page_derived"
    assert TaintClass.PixelDerived.value == "pixel_derived"
    assert TaintClass.OcrDerived.value == "ocr_derived"
    assert TaintClass.NetworkMetadata.value == "network_metadata"
    assert TaintClass.HostFileDerived.value == "host_file_derived"
    assert TaintClass.ThirdPartyText.value == "third_party_text"
    assert TaintClass.PageDerived.code() == 1
    assert TaintClass.PixelDerived.code() == 2
    assert TaintClass.OcrDerived.code() == 3
    assert TaintClass.NetworkMetadata.code() == 4
    assert TaintClass.HostFileDerived.code() == 5
    assert TaintClass.ThirdPartyText.value == "third_party_text"
    assert TaintClass.ThirdPartyText.code() == 6
    assert TaintClass.OwnerStated.value == "owner_stated"
    assert TaintClass.BodyObserved.value == "body_observed"
    assert TaintClass.ExecClaimed.value == "exec_claimed"
    assert TaintClass.ThirdParty.value == "third_party"
    assert TaintClass.OwnerStated.code() == 7
    assert TaintClass.BodyObserved.code() == 8
    assert TaintClass.ExecClaimed.code() == 9
    assert TaintClass.ThirdParty.code() == 10
    assert not hasattr(TaintClass, "PAGE_DERIVED")

    # RetentionPolicy
    assert list(RetentionPolicy) == [
        RetentionPolicy.ManagedPurgeable,
        RetentionPolicy.EphemeralSession,
        RetentionPolicy.NoStore,
    ]
    assert RetentionPolicy.ManagedPurgeable.value == "managed_purgeable"
    assert RetentionPolicy.EphemeralSession.value == "ephemeral_session"
    assert RetentionPolicy.NoStore.value == "no_store"
    assert RetentionPolicy.ManagedPurgeable.code() == 1
    assert RetentionPolicy.EphemeralSession.code() == 2
    assert RetentionPolicy.NoStore.code() == 3
    assert not hasattr(RetentionPolicy, "MANAGED_PURGEABLE")

    # ReceiptRung
    assert list(ReceiptRung) == [ReceiptRung.UnwitnessedLocal]
    assert ReceiptRung.UnwitnessedLocal.value == "un_witnessed_local"
    assert not hasattr(ReceiptRung, "UNWITNESSED_LOCAL")

    # OperationKind

    # ObservedState

    # CoordinateSpace

    # CoordinateOrigin

    # AxisOrientation


def test_bounded_text_validation() -> None:
    # Valid
    validate_bounded_text("valid-text", 64, InvalidOrigin)

    # Empty and trim-empty
    with pytest.raises(InvalidOrigin):
        validate_bounded_text("", 64, InvalidOrigin)
    with pytest.raises(InvalidOrigin):
        validate_bounded_text("   ", 64, InvalidOrigin)
    with pytest.raises(InvalidOrigin):
        validate_bounded_text(" \t \n ", 64, InvalidOrigin)

    # Byte length over max
    with pytest.raises(InvalidOrigin):
        validate_bounded_text("a" * 65, 64, InvalidOrigin)
    # Multibyte character exceeding byte length limit
    with pytest.raises(InvalidOrigin):
        validate_bounded_text("🦀" * 17, 64, InvalidOrigin)  # 17 * 4 = 68 bytes > 64

    # Control chars (Unicode Cc)
    for ctrl in ["\x00", "\x1f", "\x7f", "\x80", "\x9f", "\n", "\t", "\r"]:
        with pytest.raises(InvalidOrigin):
            validate_bounded_text(f"hello{ctrl}world", 64, InvalidOrigin)


def test_digest_and_binding_validation() -> None:
    valid_hex = "a" * 64
    validate_digest(f"sha256:{valid_hex}")
    validate_binding(valid_hex)

    # Invalid digest
    with pytest.raises(InvalidDigest):
        validate_digest("bad")
    with pytest.raises(InvalidDigest):
        validate_digest("sha256:")
    with pytest.raises(InvalidDigest):
        validate_digest(f"sha256:{'A' * 64}")  # Uppercase forbidden
    with pytest.raises(InvalidDigest):
        validate_digest(f"sha256:{'a' * 63}")  # Short
    with pytest.raises(InvalidDigest):
        validate_digest(f"sha256:{'a' * 65}")  # Long
    with pytest.raises(InvalidDigest):
        validate_digest(f"sha256:{'g' * 64}")  # Non-hex

    # Invalid binding
    with pytest.raises(InvalidBinding):
        validate_binding("bad")
    with pytest.raises(InvalidBinding):
        validate_binding("A" * 64)  # Uppercase forbidden
    with pytest.raises(InvalidBinding):
        validate_binding("a" * 63)
    with pytest.raises(InvalidBinding):
        validate_binding("a" * 65)


def test_capture_frame_bounds_and_wire() -> None:
    # Valid exact boundary limits
    frame_max = CaptureFrame(
        viewport_width_css_px=MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        viewport_height_css_px=MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        device_pixel_ratio=MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
        freshness_marker="bounded",
    )
    assert frame_max.viewport_width_css_px == 8192
    assert frame_max.viewport_height_css_px == 8192
    assert frame_max.device_pixel_ratio == 3.0
    assert frame_max.freshness_marker == "bounded"

    frame_min = CaptureFrame(
        viewport_width_css_px=1,
        viewport_height_css_px=1,
        device_pixel_ratio=MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
        freshness_marker="min",
    )
    assert frame_min.device_pixel_ratio == 1.0

    # Viewport 0 refused
    with pytest.raises(EmptyViewport):
        CaptureFrame(0, 100, 1.0, "f")
    with pytest.raises(EmptyViewport):
        CaptureFrame(100, 0, 1.0, "f")

    # Viewport too large (> 8192)
    with pytest.raises(ViewportTooLarge):
        CaptureFrame(MAX_CAPTURE_FRAME_AXIS_CSS_PX + 1, 1, 1.0, "too-wide")
    with pytest.raises(ViewportTooLarge):
        CaptureFrame(1, MAX_CAPTURE_FRAME_AXIS_CSS_PX + 1, 1.0, "too-tall")

    # DPR out of bounds
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(1, 1, MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO - 1e-9, "dpr-low")
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(1, 1, MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO + 1e-9, "dpr-high")
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(1, 1, float("nan"), "dpr-nan")
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame(1, 1, float("inf"), "dpr-inf")

    # Freshness marker empty
    with pytest.raises(MissingFreshnessMarker):
        CaptureFrame(1280, 720, 2.0, " \t ")

    # Wire round-trip and validation
    frame_dict = frame_max.to_dict()
    assert CaptureFrame.from_dict(frame_dict) == frame_max

    oversized_wire = {
        "viewport_width_css_px": MAX_CAPTURE_FRAME_AXIS_CSS_PX,
        "viewport_height_css_px": MAX_CAPTURE_FRAME_AXIS_CSS_PX + 1,
        "device_pixel_ratio": MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO,
        "freshness_marker": "wire",
    }
    with pytest.raises(ViewportTooLarge):
        CaptureFrame.from_dict(oversized_wire)


def test_origin_metadata_constructors_and_wire() -> None:
    frame = CaptureFrame(1280, 720, 2.0, "capture-1")

    # 1. Fixture
    orig_fixture = OriginMetadata("fixture", "fixture://page", None, None)
    assert orig_fixture.kind == OriginKind.Fixture
    assert orig_fixture.locator == "fixture://page"
    assert orig_fixture.captured_at is None
    assert orig_fixture.capture_frame is None

    # Whitespace-only locator refused
    with pytest.raises(InvalidOrigin):
        OriginMetadata("fixture", "   ", None, None)

    # 2. AllowedRootFile (requires frame)
    orig_file = OriginMetadata(
        "allowed_root_file", "file:///tmp/img.png", "2026-08-26T12:00:00Z", frame
    )
    assert orig_file.kind == OriginKind.AllowedRootFile
    assert orig_file.capture_frame == frame

    with pytest.raises(MissingCaptureFrame):
        OriginMetadata("allowed_root_file", "file:///tmp/img.png", None, None)

    # 3. BrowserCapture (requires frame)
    orig_browser = OriginMetadata.browser_capture(
        "https://example.com", "2026-08-26T12:00:00Z", frame
    )
    assert orig_browser.kind == OriginKind.BrowserCapture
    assert orig_browser.capture_frame == frame

    with pytest.raises(MissingCaptureFrame):
        OriginMetadata.browser_capture("https://example.com", None, None)

    # 4. DerivedContent
    orig_derived = OriginMetadata.derived_content("fixture://derived", None, None)
    assert orig_derived.kind == OriginKind.DerivedContent

    # Serialization order and null encoding
    dict_repr = orig_fixture.to_dict()
    assert list(dict_repr.keys()) == ["kind", "locator", "captured_at", "capture_frame"]
    json_bytes = json.dumps(dict_repr, separators=(",", ":"), ensure_ascii=False)
    assert (
        json_bytes
        == '{"kind":"fixture","locator":"fixture://page","captured_at":null,"capture_frame":null}'
    )

    # Wire parsing
    assert OriginMetadata.from_dict(dict_repr) == orig_fixture

    # Missing frame on wire for browser_capture
    wire_bad = orig_browser.to_dict()
    wire_bad["capture_frame"] = None
    with pytest.raises(MissingCaptureFrame):
        OriginMetadata.from_dict(wire_bad)


def test_error_families_and_hierarchy() -> None:
    # ContractError
    assert issubclass(InvalidDigest, ContractError)
    assert issubclass(MissingCaptureFrame, ContractError)
    err = InvalidDigest()
    assert isinstance(err, ContractError)

    # AuthorityError
    assert issubclass(BindingMismatch, AuthorityError)
    auth_err = BindingMismatch()
    assert isinstance(auth_err, AuthorityError)

    # CoordinateError

    # CoordinateWireError

    # CoordinateReconcileError


def test_digest_refuses_non_string_before_parsing() -> None:
    with pytest.raises(InvalidDigest):
        validate_digest(5)  # type: ignore[arg-type]


def test_enum_code_fallthrough_refuses_unknown_members() -> None:
    with pytest.raises(ValueError):
        SourceCapability.code("unknown")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TaintClass.code("unknown")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RetentionPolicy.code("unknown")  # type: ignore[arg-type]


def test_capture_frame_refuses_non_integer_axis() -> None:
    with pytest.raises(EmptyViewport):
        CaptureFrame(1.0, 1, 1.0, "frame")  # type: ignore[arg-type]


def test_capture_frame_from_dict_refuses_non_object_payload() -> None:
    with pytest.raises(EmptyViewport):
        CaptureFrame.from_dict(5)  # type: ignore[arg-type]


def test_capture_frame_from_dict_refuses_missing_fields() -> None:
    with pytest.raises(EmptyViewport):
        CaptureFrame.from_dict(
            {
                "viewport_height_css_px": 1,
                "device_pixel_ratio": 1.0,
                "freshness_marker": "frame",
            }
        )
    with pytest.raises(InvalidDevicePixelRatio):
        CaptureFrame.from_dict(
            {
                "viewport_width_css_px": 1,
                "viewport_height_css_px": 1,
                "freshness_marker": "frame",
            }
        )
    with pytest.raises(MissingFreshnessMarker):
        CaptureFrame.from_dict(
            {
                "viewport_width_css_px": 1,
                "viewport_height_css_px": 1,
                "device_pixel_ratio": 1.0,
            }
        )


def test_origin_constructor_refuses_unknown_kind() -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata("unknown", "fixture://source")


def test_origin_from_dict_refuses_non_object_payload() -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata.from_dict(5)  # type: ignore[arg-type]


def test_origin_from_dict_refuses_missing_kind() -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata.from_dict({"locator": "fixture://source"})


def test_origin_from_dict_translates_unknown_kind() -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata.from_dict({"kind": "unknown", "locator": "fixture://source"})


@pytest.mark.parametrize("kind", ["allowed_root_file", "browser_capture"])
def test_origin_from_dict_refuses_a_missing_required_frame(kind: str) -> None:
    with pytest.raises(MissingCaptureFrame):
        OriginMetadata.from_dict(
            {"kind": kind, "locator": "fixture://source", "capture_frame": None}
        )
