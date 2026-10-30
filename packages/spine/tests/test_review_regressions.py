"""Single-field regressions from the S+ review."""

import pytest

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
    validate_binding,
    validate_digest,
)


@pytest.mark.parametrize("text", ["a" * 128, "é" * 64])
def test_frame_and_capture_time_accept_exact_utf8_byte_limit(text: str) -> None:
    frame = CaptureFrame(1, 8192, 3, text)
    assert frame.to_dict()["freshness_marker"] == text
    origin = OriginMetadata("fixture", "界" * 85 + "a", text, frame)
    assert len(origin.to_dict()["locator"].encode("utf-8")) == 256
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
