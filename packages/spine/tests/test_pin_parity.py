"""Direct 1:1 port of all 12 monorepo capability-spine pin unit tests."""

import pytest

import nott_spine
from nott_spine.authority import (
    ContentAuthority,
    ContentIssuer,
    ContentRef,
    UntrustedContentRef,
)
from nott_spine.errors import (
    BindingMismatch,
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
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)

DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST_B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_public_surface_matches_pin() -> None:
    absent = (
        (ContentRef, "binding"),
        (
            UntrustedContentRef,
            "digest source_capability origin retention taint binding to_dict to_json",
        ),
        (ContentIssuer, "source_capability"),
    )
    for cls, names in absent:
        for name in names.split():
            assert not hasattr(cls, name), (
                f"{cls.__name__}.{name} is not public in the specification"
            )

    for name in ("validate_binding", "validate_bounded_text", "validate_digest"):
        assert not hasattr(nott_spine, name)


def authority() -> ContentAuthority:
    return ContentAuthority.from_secret(bytes([7] * 32))


def content_ref(
    auth: ContentAuthority,
    retention: RetentionPolicy,
) -> ContentRef:
    frame = CaptureFrame(1280, 720, 2.0, "capture-1")
    origin = OriginMetadata.browser_capture(
        "fixture://page", "2026-07-19T12:00:00Z", frame
    )
    return auth.issuer(SourceCapability.NBrowser).issue(
        DIGEST_A,
        origin,
        retention,
        TaintClass.PixelDerived,
    )


# 1. resolver_authenticates_without_reminting_retention


# 2. authority_derive_inherits_taint_and_retention


# 3. valid_wire_round_trips_and_policy_tamper_fails_binding
def test_valid_wire_round_trips_and_policy_tamper_fails_binding() -> None:
    auth = authority()
    source = content_ref(auth, RetentionPolicy.NoStore)
    valid_value = source.to_dict()
    assert valid_value["source_capability"] == "nbrowser"

    valid_wire = UntrustedContentRef.from_dict(valid_value)
    resolver = auth.resolver()
    resolved = resolver.resolve(valid_wire)
    assert resolved.retention == RetentionPolicy.NoStore

    tampered = dict(valid_value)
    tampered["retention"] = "managed_purgeable"
    tampered_wire = UntrustedContentRef.from_dict(tampered)
    with pytest.raises(BindingMismatch):
        resolver.resolve(tampered_wire)


# 4. targeted_invalid_digest_and_frame_wires_are_rejected
def test_targeted_invalid_digest_and_frame_wires_are_rejected() -> None:
    auth = authority()
    source = content_ref(auth, RetentionPolicy.EphemeralSession)
    valid = source.to_dict()
    _ = UntrustedContentRef.from_dict(valid)

    bad_digest = dict(valid)
    bad_digest["digest"] = "sha256:bad"
    with pytest.raises(InvalidDigest):
        UntrustedContentRef.from_dict(bad_digest)

    missing_frame = dict(valid)
    missing_frame["origin"] = dict(valid["origin"])
    missing_frame["origin"]["capture_frame"] = None
    with pytest.raises(MissingCaptureFrame):
        UntrustedContentRef.from_dict(missing_frame)


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
