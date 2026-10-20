"""Observable value, diagnostic and refusal contracts for spine consumers."""

import json
from typing import Any

import pytest

from nott_spine.authority import ContentAuthority, ContentRef, UntrustedContentRef
from nott_spine.errors import (
    ContractError,
)
from nott_spine.types import (
    CaptureFrame,
    OriginKind,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)


def reference() -> ContentRef:
    return (
        ContentAuthority.from_secret(bytes(range(32)))
        .issuer(SourceCapability.NBrowser)
        .issue(
            "sha256:" + "a" * 64,
            OriginMetadata(
                "fixture", "fixture://page", "now", CaptureFrame(1280, 720, 2, "fresh")
            ),
            RetentionPolicy.NoStore,
            TaintClass.PixelDerived,
        )
    )


def test_typed_error_messages() -> None:
    assert str(ContractError()) == "contract violation"
    assert str(ContractError("")) == "contract violation"
    assert str(ContractError("context")) == "context"


@pytest.mark.parametrize(
    "secret", [bytes(range(32)), bytearray(range(32)), list(range(32))]
)
def test_all_supported_secret_containers_issue_the_same_binding(secret: Any) -> None:
    authority = ContentAuthority.from_secret(secret)
    expected = reference()
    actual = authority.issuer(expected.source_capability).issue(
        expected.digest, expected.origin, expected.retention, expected.taint
    )
    assert actual.to_dict() == expected.to_dict()
    authority.close()
    authority.close()
    assert authority._key._secret == bytearray(32)
    assert authority._key._closed is True


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
    origin = reference().origin
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


@pytest.mark.parametrize(
    "replacement",
    [
        {"digest": "sha256:" + "b" * 64},
        {"source_capability": SourceCapability.NVision},
        {"origin": OriginMetadata("fixture", "other")},
        {"retention": RetentionPolicy.ManagedPurgeable},
        {"taint": TaintClass.OwnerStated},
        {"binding": "0" * 64},
    ],
)
def test_content_value_identity_includes_policy_and_authentication(
    replacement: dict[str, Any],
) -> None:
    ref = reference()
    fields = {
        "digest": ref.digest,
        "source_capability": ref.source_capability,
        "origin": ref.origin,
        "retention": ref.retention,
        "taint": ref.taint,
        "binding": ref.to_dict()["binding"],
    }
    assert ref != ContentRef(**(fields | replacement))
    wire = UntrustedContentRef(**fields)
    assert wire == UntrustedContentRef.from_dict(json.loads(ref.to_json()))
    assert wire != UntrustedContentRef(**(fields | replacement))
    assert wire != object()
    assert ref != object()
    detail = f"digest={ref.digest!r}, source_capability={ref.source_capability!r}, origin={ref.origin!r}, retention={ref.retention!r}, taint={ref.taint!r}, binding={fields['binding']!r}"
    assert repr(ref) == f"ContentRef({detail})"
    assert repr(wire) == f"UntrustedContentRef({detail})"
