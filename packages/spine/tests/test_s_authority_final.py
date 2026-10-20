"""Non-ASCII origins round-trip through the binding; secret holders redact their repr."""

from __future__ import annotations

import json

from nott_spine.authority import (
    ContentAuthority,
    ContentRef,
    UntrustedContentRef,
)
from nott_spine.types import (
    CaptureFrame,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)

# Non-ASCII locator: "fixture://façade-café" exercises the ensure_ascii=False branch
# in `_canonical_origin_bytes` and `ContentRef.to_json`. With ensure_ascii=None
# (the json.dumps default), non-ASCII chars would be escaped to "\\u00e7" and "\\u00e9"
# and the binding would no longer roundtrip.
NON_ASCII_LOCATOR = "fixture://façade-café"


def _make_authority() -> ContentAuthority:
    return ContentAuthority.from_secret(bytes([7] * 32))


def _make_ref_with_locator(locator: str) -> ContentRef:
    authority = _make_authority()
    frame = CaptureFrame(1280, 720, 2.0, "capture-1")
    origin = OriginMetadata.browser_capture(locator, "2026-07-19T12:00:00Z", frame)
    issuer = authority.issuer(SourceCapability.NBrowser)
    return issuer.issue(
        "sha256:" + "a" * 64, origin, RetentionPolicy.NoStore, TaintClass.PixelDerived
    )


# ---------------------------------------------------------------------------
# Mutant M4 (L26) — `_canonical_origin_bytes` uses ensure_ascii=False.
# Mutation: ensure_ascii=False -> ensure_ascii=None (defaults to True).
# The binding must roundtrip for a non-ASCII locator; with the mutation the
# canonical bytes change (non-ASCII gets escaped to \uXXXX) and verify_binding
# would raise BindingMismatch.
# ---------------------------------------------------------------------------


def test_canonical_origin_bytes_preserves_non_ascii_roundtrip() -> None:
    """Non-ASCII origin must roundtrip issue -> to_json -> resolve (L26 ensure_ascii)."""
    ref = _make_ref_with_locator(NON_ASCII_LOCATOR)
    resolver = _make_authority().resolver()
    untrusted = UntrustedContentRef.from_dict(json.loads(ref.to_json()))
    # With the mutation, resolve() raises BindingMismatch because the canonical
    # bytes used to verify the binding would escape the non-ASCII chars.
    resolved = resolver.resolve(untrusted)
    assert resolved == ref
    assert resolved.origin.locator == NON_ASCII_LOCATOR


# ---------------------------------------------------------------------------
# Mutant M46 (L92) — `ContentRef.to_json()` uses ensure_ascii=False.
# Mutation: ensure_ascii=False -> ensure_ascii=None (defaults to True).
# The serialized JSON must contain the raw non-ASCII character; the mutation
# escapes it to "\\u00e7" and "\\u00e9".
# ---------------------------------------------------------------------------


def test_content_ref_to_json_keeps_non_ascii_raw() -> None:
    """to_json must emit raw non-ASCII characters (L92 ensure_ascii)."""
    ref = _make_ref_with_locator(NON_ASCII_LOCATOR)
    json_str = ref.to_json()
    assert "façade-café" in json_str
    assert "\\u00e7" not in json_str
    assert "\\u00e9" not in json_str
    # And the parsed locator must equal the original.
    data = json.loads(json_str)
    assert data["origin"]["locator"] == NON_ASCII_LOCATOR


# ---------------------------------------------------------------------------
# Mutant M365 (L363) — ContentAuthority.__repr__ returns "ContentAuthority([redacted])".
# Mutation: wrapped in "XX...XX". The repr must equal exactly that string.
# ---------------------------------------------------------------------------


def test_content_authority_repr_is_redacted() -> None:
    """ContentAuthority.__repr__ must equal exact literal (L363 no XX prefix)."""
    authority = _make_authority()
    assert repr(authority) == "ContentAuthority([redacted])"
    assert "XX" not in repr(authority)


# ---------------------------------------------------------------------------
# Mutant M414 (L420) — ContentResolver.__repr__ returns "ContentResolver([redacted])".
# Mutation: wrapped in "XX...XX". The repr must equal exactly that string.
# ---------------------------------------------------------------------------


def test_content_resolver_repr_is_redacted() -> None:
    """ContentResolver.__repr__ must equal exact literal (L420 no XX prefix)."""
    resolver = _make_authority().resolver()
    assert repr(resolver) == "ContentResolver([redacted])"
    assert "XX" not in repr(resolver)
