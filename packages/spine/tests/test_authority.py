import json

import pytest

from nott_spine.authority import (
    ContentAuthority,
    ContentRef,
    UntrustedContentRef,
)
from nott_spine.errors import (
    BindingMismatch,
    InvalidAuthorityKey,
    InvalidBinding,
    InvalidDigest,
    InvalidOrigin,
)
from nott_spine.types import (
    CaptureFrame,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
)

DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST_B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def make_authority() -> ContentAuthority:
    return ContentAuthority.from_secret(bytes([7] * 32))


def make_sample_ref(
    authority: ContentAuthority,
    retention: RetentionPolicy = RetentionPolicy.EphemeralSession,
) -> ContentRef:
    frame = CaptureFrame(1280, 720, 2.0, "capture-1")
    origin = OriginMetadata.browser_capture(
        "fixture://page", "2026-07-19T12:00:00Z", frame
    )
    issuer = authority.issuer(SourceCapability.NBrowser)
    return issuer.issue(DIGEST_A, origin, retention, TaintClass.PixelDerived)


def test_issue_serialize_untrusted_resolve_roundtrip() -> None:
    authority = make_authority()
    source = make_sample_ref(authority, RetentionPolicy.NoStore)

    # Assert exact binding hex over canonical domain bytes
    assert (
        source.to_dict()["binding"]
        == "326c8b305e6789edd32d18edd77b8a64582a8d03abc0e86cd537b591890bd2c2"
    )

    # Serialize
    json_str = source.to_json()
    data = json.loads(json_str)
    assert data["source_capability"] == "nbrowser"
    assert data["retention"] == "no_store"
    assert data["taint"] == "pixel_derived"
    assert data["digest"] == DIGEST_A

    # Parse as untrusted
    untrusted = UntrustedContentRef.from_dict(json.loads(json_str))

    # Resolve
    resolver = authority.resolver()
    resolved = resolver.resolve(untrusted)
    assert resolved == source
    assert resolved.retention == RetentionPolicy.NoStore
    assert resolved.taint == TaintClass.PixelDerived


def test_tamper_vectors_refuse_binding() -> None:
    authority = make_authority()
    source = make_sample_ref(authority, RetentionPolicy.NoStore)
    valid_dict = source.to_dict()
    resolver = authority.resolver()

    # 1. Retention tamper
    tampered_ret = dict(valid_dict)
    tampered_ret["retention"] = "managed_purgeable"
    untrusted_ret = UntrustedContentRef.from_dict(tampered_ret)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_ret)

    # 2. Taint tamper
    tampered_taint = dict(valid_dict)
    tampered_taint["taint"] = "ocr_derived"
    untrusted_taint = UntrustedContentRef.from_dict(tampered_taint)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_taint)

    # 3. Digest tamper
    tampered_digest = dict(valid_dict)
    tampered_digest["digest"] = DIGEST_B
    untrusted_digest = UntrustedContentRef.from_dict(tampered_digest)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_digest)

    # 4. Source capability tamper
    tampered_cap = dict(valid_dict)
    tampered_cap["source_capability"] = "nvision"
    untrusted_cap = UntrustedContentRef.from_dict(tampered_cap)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_cap)

    # 5. Origin metadata tamper
    tampered_origin = dict(valid_dict)
    tampered_origin["origin"] = dict(valid_dict["origin"])
    tampered_origin["origin"]["locator"] = "fixture://tampered"
    untrusted_orig = UntrustedContentRef.from_dict(tampered_origin)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_orig)

    # 6. Binding corruption
    tampered_bind = dict(valid_dict)
    tampered_bind["binding"] = "0" * 64
    untrusted_bind = UntrustedContentRef.from_dict(tampered_bind)
    with pytest.raises(BindingMismatch):
        resolver.resolve(untrusted_bind)


def test_privilege_escape_absence() -> None:
    authority = make_authority()
    resolver = authority.resolver()

    # ContentResolver has NO issue or derive or tighten method
    assert not hasattr(resolver, "issue")
    assert not hasattr(resolver, "derive")
    assert not hasattr(resolver, "tighten")

    with pytest.raises(AttributeError):
        _ = resolver.issue  # type: ignore[attr-defined]

    with pytest.raises(AttributeError):
        _ = resolver.tighten  # type: ignore[attr-defined]

    # ContentRef has NO from_json or from_dict method
    assert not hasattr(ContentRef, "from_json")
    assert not hasattr(ContentRef, "from_dict")


def test_redacted_repr_and_key_zeroization() -> None:
    authority = make_authority()
    issuer = authority.issuer(SourceCapability.NBrowser)
    resolver = authority.resolver()

    assert "redacted" in repr(authority)
    assert "redacted" in repr(issuer)
    assert "redacted" in repr(resolver)

    # Invalid authority key length (< 32 bytes)
    with pytest.raises(InvalidAuthorityKey):
        ContentAuthority.from_secret(b"short")

    # Key closing / wipe
    authority.close()
    with pytest.raises(InvalidAuthorityKey):
        issuer.issue(
            DIGEST_A,
            OriginMetadata("fixture", "f", None, None),
            RetentionPolicy.NoStore,
            TaintClass.PageDerived,
        )


def test_untrusted_constructor_refuses_non_origin_object() -> None:
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef(
            DIGEST_A,
            SourceCapability.NBrowser,
            object(),  # type: ignore[arg-type]
            RetentionPolicy.NoStore,
            TaintClass.PageDerived,
            "0" * 64,
        )


def test_untrusted_constructor_refuses_unknown_source_capability() -> None:
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef(
            DIGEST_A,
            "unknown",
            OriginMetadata("fixture", "fixture://source", None, None),
            RetentionPolicy.NoStore,
            TaintClass.PageDerived,
            "0" * 64,
        )


def test_untrusted_constructor_refuses_unknown_retention() -> None:
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef(
            DIGEST_A,
            SourceCapability.NBrowser,
            OriginMetadata("fixture", "fixture://source", None, None),
            "unknown",
            TaintClass.PageDerived,
            "0" * 64,
        )


def test_untrusted_constructor_refuses_unknown_taint() -> None:
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef(
            DIGEST_A,
            SourceCapability.NBrowser,
            OriginMetadata("fixture", "fixture://source", None, None),
            RetentionPolicy.NoStore,
            "unknown",
            "0" * 64,
        )


def test_untrusted_from_dict_refuses_non_object_payload() -> None:
    with pytest.raises(InvalidOrigin):
        UntrustedContentRef.from_dict(5)  # type: ignore[arg-type]


def test_untrusted_from_dict_refuses_missing_source_capability() -> None:
    data = make_sample_ref(make_authority()).to_dict()
    del data["source_capability"]

    with pytest.raises(InvalidOrigin):
        UntrustedContentRef.from_dict(data)


def test_untrusted_from_dict_refuses_missing_digest() -> None:
    data = make_sample_ref(make_authority()).to_dict()
    del data["digest"]

    with pytest.raises(InvalidDigest):
        UntrustedContentRef.from_dict(data)


def test_untrusted_from_dict_refuses_missing_binding() -> None:
    data = make_sample_ref(make_authority()).to_dict()
    del data["binding"]

    with pytest.raises(InvalidBinding):
        UntrustedContentRef.from_dict(data)


def test_invalid_binding_is_translated_before_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = make_authority()
    origin = OriginMetadata("fixture", "fixture://source", None, None)

    def return_invalid_binding(*_args: object, **_kwargs: object) -> str:
        return "invalid"

    monkeypatch.setattr(type(authority._key), "bind", return_invalid_binding)
    with pytest.raises(BindingMismatch):
        authority._key.verify_binding(
            DIGEST_A,
            SourceCapability.NBrowser,
            origin,
            RetentionPolicy.NoStore,
            TaintClass.PageDerived,
            "invalid",
        )
