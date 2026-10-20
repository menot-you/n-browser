"""Typed error hierarchy for nott-spine: contract and authority refusals."""

from __future__ import annotations


class ContractError(Exception):
    """Base error for contract and validation violations."""

    DEFAULT_MESSAGE: str = "contract violation"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.DEFAULT_MESSAGE
        super().__init__(self.message)


class InvalidDigest(ContractError):
    DEFAULT_MESSAGE = (
        "digest must be sha256: followed by 64 lowercase hexadecimal digits"
    )


class InvalidBinding(ContractError):
    DEFAULT_MESSAGE = "content reference binding is invalid"


class InvalidAuthorityKey(ContractError):
    DEFAULT_MESSAGE = "content authority key is invalid"


class InvalidOrigin(ContractError):
    DEFAULT_MESSAGE = "origin locator is invalid"


class InvalidCaptureTime(ContractError):
    DEFAULT_MESSAGE = "capture time is invalid"


class EmptyViewport(ContractError):
    DEFAULT_MESSAGE = "viewport dimensions must be nonzero"


class ViewportTooLarge(ContractError):
    DEFAULT_MESSAGE = "viewport dimensions exceed the shared frame limit"


class InvalidDevicePixelRatio(ContractError):
    DEFAULT_MESSAGE = "device pixel ratio is outside the shared frame range"


class MissingFreshnessMarker(ContractError):
    DEFAULT_MESSAGE = "freshness marker is required"


class MissingCaptureFrame(ContractError):
    DEFAULT_MESSAGE = "this origin kind requires a capture frame"


class AuthorityError(Exception):
    """Base error for authority and binding verification failures."""

    DEFAULT_MESSAGE: str = "authority violation"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.DEFAULT_MESSAGE
        super().__init__(self.message)


class BindingMismatch(AuthorityError):
    DEFAULT_MESSAGE = "content reference binding mismatch"
