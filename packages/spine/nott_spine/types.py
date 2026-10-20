"""Shared capability types, enums, frames, and origin metadata."""

from __future__ import annotations

import enum
import math
import unicodedata
from typing import Any

from nott_spine.errors import (
    ContractError,
    EmptyViewport,
    InvalidBinding,
    InvalidCaptureTime,
    InvalidDevicePixelRatio,
    InvalidDigest,
    InvalidOrigin,
    MissingCaptureFrame,
    MissingFreshnessMarker,
    ViewportTooLarge,
)

MAX_CAPTURE_FRAME_AXIS_CSS_PX: int = 8192
MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO: float = 1.0
MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO: float = 3.0


def validate_digest(value: str) -> None:
    """Validates that a digest has the format sha256: followed by 64 lowercase hex digits."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise InvalidDigest()
    hex_part = value[7:]
    if len(hex_part) != 64 or not all(c in "0123456789abcdef" for c in hex_part):
        raise InvalidDigest()


def validate_binding(value: str) -> None:
    """Validates that a binding has 64 lowercase hex digits."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not all(c in "0123456789abcdef" for c in value)
    ):
        raise InvalidBinding()


def validate_bounded_text(
    value: str,
    max_bytes: int,
    error: type[ContractError],
) -> None:
    """Validates bounded text refusing trim-empty, byte len over max, or any Cc control char."""
    if not isinstance(value, str) or value.strip() == "":
        raise error()
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise error() from None
    if len(encoded) > max_bytes:
        raise error()
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise error()


class SourceCapability(enum.StrEnum):
    NBrowser = "nbrowser"
    NVision = "nvision"

    def code(self) -> int:
        match self:
            case SourceCapability.NBrowser:
                return 1
            case SourceCapability.NVision:
                return 2
        raise ValueError(f"Unknown SourceCapability: {self}")


class OriginKind(enum.StrEnum):
    Fixture = "fixture"
    AllowedRootFile = "allowed_root_file"
    BrowserCapture = "browser_capture"
    DerivedContent = "derived_content"


class TaintClass(enum.StrEnum):
    PageDerived = "page_derived"
    PixelDerived = "pixel_derived"
    OcrDerived = "ocr_derived"
    NetworkMetadata = "network_metadata"
    HostFileDerived = "host_file_derived"
    ThirdPartyText = "third_party_text"
    OwnerStated = "owner_stated"
    BodyObserved = "body_observed"
    ExecClaimed = "exec_claimed"
    ThirdParty = "third_party"

    def code(self) -> int:
        match self:
            case TaintClass.PageDerived:
                return 1
            case TaintClass.PixelDerived:
                return 2
            case TaintClass.OcrDerived:
                return 3
            case TaintClass.NetworkMetadata:
                return 4
            case TaintClass.HostFileDerived:
                return 5
            case TaintClass.ThirdPartyText:
                return 6
            case TaintClass.OwnerStated:
                return 7
            case TaintClass.BodyObserved:
                return 8
            case TaintClass.ExecClaimed:
                return 9
            case TaintClass.ThirdParty:
                return 10
        raise ValueError(f"Unknown TaintClass: {self}")


class RetentionPolicy(enum.StrEnum):
    ManagedPurgeable = "managed_purgeable"
    EphemeralSession = "ephemeral_session"
    NoStore = "no_store"

    def code(self) -> int:
        match self:
            case RetentionPolicy.ManagedPurgeable:
                return 1
            case RetentionPolicy.EphemeralSession:
                return 2
            case RetentionPolicy.NoStore:
                return 3
        raise ValueError(f"Unknown RetentionPolicy: {self}")


class ReceiptRung(enum.StrEnum):
    UnwitnessedLocal = "un_witnessed_local"


class CaptureFrame:
    """Validated viewport carried by screenshot/image references."""

    __slots__ = (
        "_device_pixel_ratio",
        "_freshness_marker",
        "_viewport_height_css_px",
        "_viewport_width_css_px",
    )

    def __init__(
        self,
        viewport_width_css_px: int,
        viewport_height_css_px: int,
        device_pixel_ratio: float,
        freshness_marker: str,
    ) -> None:
        if (
            isinstance(viewport_width_css_px, bool)
            or isinstance(viewport_height_css_px, bool)
            or not isinstance(viewport_width_css_px, int)
            or not isinstance(viewport_height_css_px, int)
        ):
            raise EmptyViewport()
        if viewport_width_css_px <= 0 or viewport_height_css_px <= 0:
            raise EmptyViewport()
        if (
            viewport_width_css_px > MAX_CAPTURE_FRAME_AXIS_CSS_PX
            or viewport_height_css_px > MAX_CAPTURE_FRAME_AXIS_CSS_PX
        ):
            raise ViewportTooLarge()
        if (
            not isinstance(device_pixel_ratio, (int, float))
            or isinstance(device_pixel_ratio, bool)
            or not (
                MIN_CAPTURE_FRAME_DEVICE_PIXEL_RATIO
                <= device_pixel_ratio
                <= MAX_CAPTURE_FRAME_DEVICE_PIXEL_RATIO
            )
            or not math.isfinite(device_pixel_ratio)
        ):
            raise InvalidDevicePixelRatio()

        validate_bounded_text(freshness_marker, 128, MissingFreshnessMarker)

        self._viewport_width_css_px = viewport_width_css_px
        self._viewport_height_css_px = viewport_height_css_px
        self._device_pixel_ratio = float(device_pixel_ratio)
        self._freshness_marker = freshness_marker

    @property
    def viewport_width_css_px(self) -> int:
        return self._viewport_width_css_px

    @property
    def viewport_height_css_px(self) -> int:
        return self._viewport_height_css_px

    @property
    def device_pixel_ratio(self) -> float:
        return self._device_pixel_ratio

    @property
    def freshness_marker(self) -> str:
        return self._freshness_marker

    def to_dict(self) -> dict[str, Any]:
        return {
            "viewport_width_css_px": self._viewport_width_css_px,
            "viewport_height_css_px": self._viewport_height_css_px,
            "device_pixel_ratio": self._device_pixel_ratio,
            "freshness_marker": self._freshness_marker,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CaptureFrame:
        if not isinstance(data, dict):
            raise EmptyViewport()
        for key, error in (
            ("viewport_width_css_px", EmptyViewport),
            ("viewport_height_css_px", EmptyViewport),
            ("device_pixel_ratio", InvalidDevicePixelRatio),
            ("freshness_marker", MissingFreshnessMarker),
        ):
            if key not in data:
                raise error()
        return cls(
            viewport_width_css_px=data["viewport_width_css_px"],
            viewport_height_css_px=data["viewport_height_css_px"],
            device_pixel_ratio=data["device_pixel_ratio"],
            freshness_marker=data["freshness_marker"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CaptureFrame):
            return False
        return (
            self._viewport_width_css_px == other._viewport_width_css_px
            and self._viewport_height_css_px == other._viewport_height_css_px
            and self._device_pixel_ratio == other._device_pixel_ratio
            and self._freshness_marker == other._freshness_marker
        )

    def __repr__(self) -> str:
        return (
            f"CaptureFrame(viewport_width_css_px={self._viewport_width_css_px}, "
            f"viewport_height_css_px={self._viewport_height_css_px}, "
            f"device_pixel_ratio={self._device_pixel_ratio}, "
            f"freshness_marker={self._freshness_marker!r})"
        )


class OriginMetadata:
    """Trace metadata. Caller-visible identifiers are bounded and reject controls."""

    __slots__ = ("_capture_frame", "_captured_at", "_kind", "_locator")

    def __init__(
        self,
        kind: OriginKind | str,
        locator: str,
        captured_at: str | None = None,
        capture_frame: CaptureFrame | None = None,
    ) -> None:
        if isinstance(kind, str):
            try:
                kind = OriginKind(kind)
            except ValueError:
                raise InvalidOrigin()

        if not isinstance(kind, OriginKind):
            raise InvalidOrigin()
        if capture_frame is not None and not isinstance(capture_frame, CaptureFrame):
            raise MissingCaptureFrame()
        if (
            kind in (OriginKind.AllowedRootFile, OriginKind.BrowserCapture)
            and capture_frame is None
        ):
            raise MissingCaptureFrame()

        validate_bounded_text(locator, 256, InvalidOrigin)
        if captured_at is not None:
            validate_bounded_text(captured_at, 128, InvalidCaptureTime)

        self._kind = kind
        self._locator = locator
        self._captured_at = captured_at
        self._capture_frame = capture_frame

    @classmethod
    def browser_capture(
        cls,
        locator: str,
        captured_at: str | None = None,
        capture_frame: CaptureFrame | None = None,
    ) -> OriginMetadata:
        if capture_frame is None:
            raise MissingCaptureFrame()
        return cls(OriginKind.BrowserCapture, locator, captured_at, capture_frame)

    @classmethod
    def derived_content(
        cls,
        locator: str,
        captured_at: str | None = None,
        capture_frame: CaptureFrame | None = None,
    ) -> OriginMetadata:
        return cls(OriginKind.DerivedContent, locator, captured_at, capture_frame)

    @property
    def kind(self) -> OriginKind:
        return self._kind

    @property
    def locator(self) -> str:
        return self._locator

    @property
    def captured_at(self) -> str | None:
        return self._captured_at

    @property
    def capture_frame(self) -> CaptureFrame | None:
        return self._capture_frame

    def to_dict(self) -> dict[str, Any]:
        """Canonical origin dict in declaration order: kind, locator, captured_at, capture_frame."""
        return {
            "kind": self._kind.value,
            "locator": self._locator,
            "captured_at": self._captured_at,
            "capture_frame": self._capture_frame.to_dict()
            if self._capture_frame is not None
            else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OriginMetadata:
        if not isinstance(data, dict):
            raise InvalidOrigin()
        if "kind" not in data or "locator" not in data:
            raise InvalidOrigin()

        try:
            kind = OriginKind(data["kind"])
        except ValueError:
            raise InvalidOrigin()

        locator = data["locator"]
        captured_at = data.get("captured_at")
        frame_raw = data.get("capture_frame")

        frame: CaptureFrame | None = None
        if frame_raw is not None:
            frame = CaptureFrame.from_dict(frame_raw)

        return cls(kind, locator, captured_at, frame)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OriginMetadata):
            return False
        return (
            self._kind == other._kind
            and self._locator == other._locator
            and self._captured_at == other._captured_at
            and self._capture_frame == other._capture_frame
        )

    def __repr__(self) -> str:
        return (
            f"OriginMetadata(kind={self._kind!r}, locator={self._locator!r}, "
            f"captured_at={self._captured_at!r}, capture_frame={self._capture_frame!r})"
        )
