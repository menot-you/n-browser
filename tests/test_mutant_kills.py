"""Tests killing specific mutants in capture."""

from __future__ import annotations

import base64

import pytest

from nbrowser.capture import (
    MAX_SCREENSHOT_BYTES,
    capture_png,
    validate_screenshot_bytes,
)
from nbrowser.errors import BrowserError, FailureCode


# 2. capture mutants
def test_capture_mutants() -> None:
    # size 0 must raise
    with pytest.raises(BrowserError) as exc0:
        validate_screenshot_bytes(0)
    assert exc0.value.code == FailureCode.CONTENT_BUDGET_EXCEEDED

    # size 1 must NOT raise
    validate_screenshot_bytes(1)

    # size MAX must NOT raise
    validate_screenshot_bytes(MAX_SCREENSHOT_BYTES)

    # size MAX + 1 must raise
    with pytest.raises(BrowserError) as exc_max:
        validate_screenshot_bytes(MAX_SCREENSHOT_BYTES + 1)
    assert exc_max.value.code == FailureCode.CONTENT_BUDGET_EXCEEDED

    # capture_png with empty / None raw
    with pytest.raises(BrowserError) as exc_empty:
        capture_png(lambda: "")
    assert exc_empty.value.code == FailureCode.CAPTURE_EXPORT_FAILED

    with pytest.raises(BrowserError) as exc_none:
        capture_png(lambda: None)
    assert exc_none.value.code == FailureCode.CAPTURE_EXPORT_FAILED

    # capture_png valid
    valid_raw = base64.b64encode(b"valid png content").decode("ascii")
    assert capture_png(lambda: valid_raw) == b"valid png content"
