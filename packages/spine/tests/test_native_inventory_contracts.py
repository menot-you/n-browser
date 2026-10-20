"""Consumer contracts for source constructs outside the legacy mutation inventory."""

import pytest

import nott_spine
from nott_spine import errors
from nott_spine.types import CaptureFrame, OriginKind, OriginMetadata


def test_export_registry_exposes_the_complete_public_api() -> None:
    """The star-import registry contains exactly the resolvable public names."""
    expected = {
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
    }
    assert set(nott_spine.__all__) == expected
    assert len(nott_spine.__all__) == len(expected)
    for name in nott_spine.__all__:
        assert name in vars(nott_spine)


@pytest.mark.parametrize(
    "error_class",
    [
        value
        for value in vars(errors).values()
        if isinstance(value, type)
        and issubclass(value, Exception)
        and "DEFAULT_MESSAGE" in vars(value)
    ],
)
def test_each_default_refusal_supplies_a_text_diagnostic(
    error_class: type[Exception],
) -> None:
    """A typed refusal without caller context still explains itself as text."""
    error = error_class()
    assert len(error.args) == 1
    message = error.args[0]
    assert isinstance(message, str)
    assert message.strip()
    assert str(error) == message


@pytest.mark.parametrize("kind", list(OriginKind))
def test_origin_constructor_accepts_wire_kind_strings(kind: OriginKind) -> None:
    """The public string overload normalizes valid wire tags to enum members."""
    frame = CaptureFrame(100, 100, 1, "fresh")
    actual = OriginMetadata(kind.value, "fixture://origin", "now", frame)
    expected = OriginMetadata(kind, "fixture://origin", "now", frame)
    assert actual.kind is kind
    assert actual == expected
    assert actual.to_dict() == expected.to_dict()


def test_capture_time_refusal_is_catchable_through_public_error_alias() -> None:
    with pytest.raises(errors.InvalidCaptureTime):
        OriginMetadata("fixture", "fixture://origin", captured_at="")
