"""Generative consumer invariants across trust, inheritance and frame boundaries."""

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nott_spine.authority import ContentAuthority, UntrustedContentRef
from nott_spine.errors import (
    BindingMismatch,
    InvalidAuthorityKey,
)
from nott_spine.types import (
    CaptureFrame,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)


@st.composite
def frames(draw: st.DrawFn) -> CaptureFrame:
    return CaptureFrame(
        draw(st.integers(1, 8192)),
        draw(st.integers(1, 8192)),
        draw(st.floats(1, 3, allow_nan=False, allow_infinity=False)),
        draw(st.text(alphabet="abc012é界", min_size=1, max_size=32)),
    )


@settings(max_examples=100, database=None, derandomize=True)
@given(
    key=st.binary(min_size=32, max_size=32),
    digest=st.binary(min_size=32, max_size=32),
    frame=frames(),
    retention=st.sampled_from(list(RetentionPolicy)),
    taint=st.sampled_from(list(TaintClass)),
    capability=st.sampled_from(list(SourceCapability)),
)
def test_authenticated_roundtrip_never_changes_policy(
    key, digest, frame, retention, taint, capability
) -> None:
    authority = ContentAuthority.from_secret(key)
    origin = OriginMetadata.browser_capture("fixture://é界", "capture-time", frame)
    ref = authority.issuer(capability).issue(
        "sha256:" + digest.hex(), origin, retention, taint
    )
    resolver = authority.resolver()
    resolved = resolver.resolve(
        UntrustedContentRef.from_dict(json.loads(ref.to_json()))
    )
    assert resolved == ref
    assert resolved.to_json() == ref.to_json()
    authority.close()
    with pytest.raises(InvalidAuthorityKey):
        resolver.resolve(UntrustedContentRef.from_dict(json.loads(ref.to_json())))


@settings(max_examples=100, database=None, derandomize=True)
@given(
    key=st.binary(min_size=32, max_size=32),
    frame=frames(),
    field=st.sampled_from(
        [
            "digest",
            "source_capability",
            "retention",
            "taint",
            "binding",
            "locator",
            "captured_at",
            "kind",
            "width",
            "height",
            "dpr",
            "freshness",
        ]
    ),
)
def test_authentication_binds_every_wire_metadata_field(key, frame, field) -> None:
    authority = ContentAuthority.from_secret(key)
    ref = authority.issuer(SourceCapability.NBrowser).issue(
        "sha256:" + "a" * 64,
        OriginMetadata.browser_capture("fixture://original", "now", frame),
        RetentionPolicy.NoStore,
        TaintClass.PixelDerived,
    )
    data = json.loads(ref.to_json())
    replacements = {
        "digest": "sha256:" + "b" * 64,
        "source_capability": "nvision",
        "retention": "managed_purgeable",
        "taint": "owner_stated",
    }
    if field in replacements:
        data[field] = replacements[field]
    elif field == "binding":
        data[field] = ("0" if data[field][0] != "0" else "1") + data[field][1:]
    elif field in ("locator", "captured_at", "kind"):
        data["origin"][field] = {
            "locator": "fixture://other",
            "captured_at": "later",
            "kind": "fixture",
        }[field]
    else:
        frame_data = data["origin"]["capture_frame"]
        key_name = {
            "width": "viewport_width_css_px",
            "height": "viewport_height_css_px",
            "dpr": "device_pixel_ratio",
            "freshness": "freshness_marker",
        }[field]
        value = frame_data[key_name]
        if field in ("width", "height"):
            frame_data[key_name] = 1 if value != 1 else 2
        elif field == "dpr":
            frame_data[key_name] = 1.0 if value != 1.0 else 2.0
        else:
            frame_data[key_name] = value + "x"
    with pytest.raises(BindingMismatch):
        authority.resolver().resolve(UntrustedContentRef.from_dict(data))
    other_key = bytes([key[0] ^ 1]) + key[1:]
    foreign = ContentAuthority.from_secret(other_key)
    with pytest.raises(BindingMismatch):
        foreign.resolver().resolve(
            UntrustedContentRef.from_dict(json.loads(ref.to_json()))
        )
