"""Independent byte oracle and single-field regressions from the S+ review."""

import enum
import hashlib
import hmac
import json

import pytest

from nott_spine.authority import ContentAuthority, ContentRef, UntrustedContentRef
from nott_spine.errors import (
    InvalidBinding,
    InvalidCaptureTime,
    InvalidDigest,
    InvalidOrigin,
    MissingFreshnessMarker,
)
from nott_spine.types import (
    CaptureFrame,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
    validate_binding,
    validate_digest,
)


def reference() -> ContentRef:
    return (
        ContentAuthority.from_secret(bytes(range(32)))
        .issuer(SourceCapability.NBrowser)
        .issue(
            "sha256:" + "a" * 64,
            OriginMetadata.browser_capture(
                "fixture://café/界", "été", CaptureFrame(1280, 720, 2, "帧-é")
            ),
            RetentionPolicy.NoStore,
            TaintClass.PixelDerived,
        )
    )


def test_non_ascii_binding_and_content_wire_match_independent_byte_oracle() -> None:
    # Literal declaration-order UTF-8, not the implementation's JSON encoder or
    # origin.to_dict(). Codes are literal spec values, not enum.code() calls.
    origin = (
        '{"kind":"browser_capture","locator":"fixture://café/界",'
        '"captured_at":"été","capture_frame":{"viewport_width_css_px":1280,'
        '"viewport_height_css_px":720,"device_pixel_ratio":2.0,'
        '"freshness_marker":"帧-é"}}'
    ).encode()
    digest = ("sha256:" + "a" * 64).encode("ascii")
    domain = digest + b"\x00\x01" + origin + b"\x03\x02"
    expected_binding = hmac.digest(bytes(range(32)), domain, hashlib.sha256).hex()
    assert expected_binding == (
        "cb0b830e416b89cbf01bb86f41ae835583ca9e0b1af6f0d26f4c6cb05eabf958"
    )
    expected_wire = (
        b'{"digest":"'
        + digest
        + b'","source_capability":"nbrowser","origin":'
        + origin
        + b',"retention":"no_store","taint":"pixel_derived","binding":"'
        + expected_binding.encode("ascii")
        + b'"}'
    )
    ref = reference()
    assert ref.to_dict()["binding"] == expected_binding
    assert ref.to_json().encode("utf-8") == expected_wire
    authority = ContentAuthority.from_secret(bytes(range(32)))
    assert (
        authority.resolver().resolve(
            UntrustedContentRef.from_dict(json.loads(expected_wire.decode("utf-8")))
        )
        == ref
    )


def test_new_coordinate_space_requires_explicit_bounds_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Model the enum growing: a newly recognized tag must not inherit DevicePx
    # math. This exercises the rejecting terminal arm without excluding it.
    class ExtendedSpace(enum.StrEnum):
        CssPx = "css_px"
        DevicePx = "device_px"
        Future = "future"


@pytest.mark.parametrize("text", ["a" * 128, "é" * 64])
def test_frame_and_capture_time_accept_exact_utf8_byte_limit(text: str) -> None:
    frame = CaptureFrame(1, 8192, 3, text)
    assert frame.freshness_marker == text
    origin = OriginMetadata("fixture", "界" * 85 + "a", text, frame)
    assert len(origin.locator.encode("utf-8")) == 256
    assert OriginMetadata.from_dict(origin.to_dict()) == origin


@pytest.mark.parametrize("text", ["a" * 129, "é" * 64 + "a"])
def test_frame_refuses_one_byte_over_limit(text: str) -> None:
    with pytest.raises(MissingFreshnessMarker):
        CaptureFrame(1280, 720, 2, text)


@pytest.mark.parametrize("text", ["a" * 257, "界" * 85 + "ab"])
def test_origin_refuses_one_byte_over_limit(text: str) -> None:
    with pytest.raises(InvalidOrigin):
        OriginMetadata("fixture", text)


@pytest.mark.parametrize("text", ["", " ", "\x00", "\ud800", "a" * 129, "é" * 64 + "a"])
def test_capture_time_refusal_keeps_its_error_type(text: str) -> None:
    with pytest.raises(InvalidCaptureTime):
        OriginMetadata("fixture", "fixture://page", captured_at=text)


def test_byte_255_is_a_valid_authority_key_component() -> None:
    source = reference()
    from_list = ContentAuthority.from_secret([255] * 32)
    from_bytes = ContentAuthority.from_secret(b"\xff" * 32)
    ref = from_list.issuer(source.source_capability).issue(
        source.digest, source.origin, source.retention, source.taint
    )
    assert (
        from_bytes.resolver().resolve(
            UntrustedContentRef.from_dict(json.loads(ref.to_json()))
        )
        == ref
    )


@pytest.mark.parametrize("character", ["X", "A", "f", "0"])
def test_digest_and_binding_accept_only_lowercase_hex(character: str) -> None:
    binding = "a" * 63 + character
    digest = "sha256:" + binding
    if character in "abcdef0123456789":
        validate_digest(digest)
        validate_binding(binding)
    else:
        with pytest.raises(InvalidDigest):
            validate_digest(digest)
        with pytest.raises(InvalidBinding):
            validate_binding(binding)
