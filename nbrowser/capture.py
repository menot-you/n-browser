"""Screenshot capture with ephemeral byte custody.

Bytes never ride stdio: the PNG lands in the session quarantine and the wire
carries only the digest ref. managed_purgeable writes the PNG to the capture root
(nott_database.captures) only when NOTT_DATABASE_DIR is set; otherwise it refuses with
grant_required."""

import base64

from .errors import BrowserError, FailureCode

MAX_SCREENSHOT_BYTES = 4 * 1024 * 1024


def validate_screenshot_bytes(size: int) -> None:
    if size == 0 or size > MAX_SCREENSHOT_BYTES:
        raise BrowserError(
            FailureCode.CONTENT_BUDGET_EXCEEDED,
            f"screenshot bytes out of bounds: {size}",
        )


from collections.abc import Callable


def capture_png(evaluate_page: Callable[[], str | bytes | None]) -> bytes:
    """`evaluate_page()` answers a base64 PNG from Page.captureScreenshot."""
    raw = evaluate_page()
    if not raw:
        raise BrowserError(
            FailureCode.CAPTURE_EXPORT_FAILED, "capture returned no bytes"
        )
    data = base64.b64decode(raw if isinstance(raw, str) else bytes(raw))
    validate_screenshot_bytes(len(data))
    return data
