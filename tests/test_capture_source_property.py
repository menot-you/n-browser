"""Property: the capture `source` survives its wire trip.

What nbrowser_page_capture emits (ContentRef.to_dict) is what a reader gets back
(UntrustedContentRef.from_dict -> resolver().resolve), for every digest,
viewport and device pixel ratio the spine admits."""

from __future__ import annotations

import json
import secrets

from hypothesis import given, settings
from hypothesis import strategies as st
from nott_spine import (
    CaptureFrame,
    ContentAuthority,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
    UntrustedContentRef,
)

AUTHORITY = ContentAuthority.from_secret(secrets.token_bytes(32))
HEX64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@settings(max_examples=200, deadline=None)
@given(
    digest=HEX64,
    width=st.integers(min_value=1, max_value=8192),
    height=st.integers(min_value=1, max_value=8192),
    dpr=st.floats(min_value=1.0, max_value=3.0, allow_nan=False, allow_infinity=False),
    port=st.integers(min_value=1, max_value=65535),
    retention=st.sampled_from(
        [RetentionPolicy.NoStore, RetentionPolicy.EphemeralSession]
    ),
)
def test_capture_source_round_trips_through_its_wire_dict(
    digest: str,
    width: int,
    height: int,
    dpr: float,
    port: int,
    retention: RetentionPolicy,
) -> None:
    frame = CaptureFrame(width, height, dpr, digest)
    origin = OriginMetadata.browser_capture(
        f"http://127.0.0.1:{port}", "2026-09-05T00:00:00Z", frame
    )
    source = AUTHORITY.issuer(SourceCapability.NBrowser).issue(
        "sha256:" + digest, origin, retention, TaintClass.PixelDerived
    )
    wire = json.loads(json.dumps(source.to_dict()))
    resolved = AUTHORITY.resolver().resolve(UntrustedContentRef.from_dict(wire))
    assert resolved == source
    assert resolved.origin.capture_frame == frame
    assert resolved.origin.locator == f"http://127.0.0.1:{port}"
