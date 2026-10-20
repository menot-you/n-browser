"""Shared content-reference types for nBROWSER.

These types carry policy (source, origin, retention, taint) on digest-bound
references. They do not grant authority and cannot represent a witnessed result.
"""

from __future__ import annotations

from nott_spine.authority import (
    ContentAuthority,
    ContentIssuer,
    ContentRef,
    ContentResolver,
    UntrustedContentRef,
)
from nott_spine.errors import (
    AuthorityError,
    BindingMismatch,
    ContractError,
    EmptyViewport,
    InvalidAuthorityKey,
    InvalidBinding,
    InvalidCaptureTime,
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
)

__all__ = [
    "MAX_CAPTURE_FRAME_AXIS_CSS_PX",
    "MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO",
    "MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO",
    "AuthorityError",
    "BindingMismatch",
    "CaptureFrame",
    "ContentAuthority",
    "ContentIssuer",
    "ContentRef",
    "ContentResolver",
    "ContractError",
    "EmptyViewport",
    "InvalidAuthorityKey",
    "InvalidBinding",
    "InvalidCaptureTime",
    "InvalidDevicePixelRatio",
    "InvalidDigest",
    "InvalidOrigin",
    "MissingCaptureFrame",
    "MissingFreshnessMarker",
    "OriginKind",
    "OriginMetadata",
    "ReceiptRung",
    "RetentionPolicy",
    "SourceCapability",
    "TaintClass",
    "UntrustedContentRef",
    "ViewportTooLarge",
]
