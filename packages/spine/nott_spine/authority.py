"""Content authority, issuer, resolver, and HMAC-SHA256 binding domain."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from nott_spine.errors import (
    BindingMismatch,
    ContractError,
    InvalidAuthorityKey,
    InvalidBinding,
    InvalidDigest,
    InvalidOrigin,
)
from nott_spine.types import (
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
    validate_binding,
    validate_digest,
)


def _canonical_origin_bytes(origin: OriginMetadata) -> bytes:
    data = origin.to_dict()
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ContentRef:
    """Digest-bound handle to bytes held outside model context.

    Trusted references can only be issued by ContentIssuer or authenticated by
    ContentResolver.
    """

    __slots__ = (
        "_binding",
        "_digest",
        "_origin",
        "_retention",
        "_source_capability",
        "_taint",
    )

    def __init__(
        self,
        digest: str,
        source_capability: SourceCapability,
        origin: OriginMetadata,
        retention: RetentionPolicy,
        taint: TaintClass,
        binding: str,
    ) -> None:
        self._digest = digest
        self._source_capability = source_capability
        self._origin = origin
        self._retention = retention
        self._taint = taint
        self._binding = binding

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def source_capability(self) -> SourceCapability:
        return self._source_capability

    @property
    def origin(self) -> OriginMetadata:
        return self._origin

    @property
    def retention(self) -> RetentionPolicy:
        return self._retention

    @property
    def taint(self) -> TaintClass:
        return self._taint

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self._digest,
            "source_capability": self._source_capability.value,
            "origin": self._origin.to_dict(),
            "retention": self._retention.value,
            "taint": self._taint.value,
            "binding": self._binding,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ContentRef):
            return False
        return (
            self._digest == other._digest
            and self._source_capability == other._source_capability
            and self._origin == other._origin
            and self._retention == other._retention
            and self._taint == other._taint
            and self._binding == other._binding
        )

    def __repr__(self) -> str:
        return (
            f"ContentRef(digest={self._digest!r}, source_capability={self._source_capability!r}, "
            f"origin={self._origin!r}, retention={self._retention!r}, taint={self._taint!r}, "
            f"binding={self._binding!r})"
        )


class UntrustedContentRef:
    """Deserialized content metadata is untrusted until the configured authority verifies its binding."""

    __slots__ = (
        "_binding",
        "_digest",
        "_origin",
        "_retention",
        "_source_capability",
        "_taint",
    )

    def __init__(
        self,
        digest: str,
        source_capability: SourceCapability | str,
        origin: OriginMetadata | dict[str, Any],
        retention: RetentionPolicy | str,
        taint: TaintClass | str,
        binding: str,
    ) -> None:
        validate_digest(digest)
        validate_binding(binding)

        if isinstance(source_capability, str):
            try:
                source_capability = SourceCapability(source_capability)
            except ValueError:
                raise InvalidOrigin()

        if isinstance(origin, dict):
            origin = OriginMetadata.from_dict(origin)
        elif not isinstance(origin, OriginMetadata):
            raise InvalidOrigin()

        if isinstance(retention, str):
            try:
                retention = RetentionPolicy(retention)
            except ValueError:
                raise InvalidOrigin()

        if isinstance(taint, str):
            try:
                taint = TaintClass(taint)
            except ValueError:
                raise InvalidOrigin()

        if not isinstance(source_capability, SourceCapability):
            raise InvalidOrigin()
        if not isinstance(retention, RetentionPolicy):
            raise InvalidOrigin()
        if not isinstance(taint, TaintClass):
            raise InvalidOrigin()

        self._digest = digest
        self._source_capability = source_capability
        self._origin = origin
        self._retention = retention
        self._taint = taint
        self._binding = binding

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UntrustedContentRef:
        if not isinstance(data, dict):
            raise InvalidOrigin()
        required = (
            "digest",
            "source_capability",
            "origin",
            "retention",
            "taint",
            "binding",
        )
        for key in required:
            if key not in data:
                if key == "digest":
                    raise InvalidDigest()
                if key == "binding":
                    raise InvalidBinding()
                raise InvalidOrigin()
        return cls(
            digest=data["digest"],
            source_capability=data["source_capability"],
            origin=data["origin"],
            retention=data["retention"],
            taint=data["taint"],
            binding=data["binding"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UntrustedContentRef):
            return False
        return (
            self._digest == other._digest
            and self._source_capability == other._source_capability
            and self._origin == other._origin
            and self._retention == other._retention
            and self._taint == other._taint
            and self._binding == other._binding
        )

    def __repr__(self) -> str:
        return (
            f"UntrustedContentRef(digest={self._digest!r}, source_capability={self._source_capability!r}, "
            f"origin={self._origin!r}, retention={self._retention!r}, taint={self._taint!r}, "
            f"binding={self._binding!r})"
        )


class _AuthorityKey:
    """Internal key owner holding the 32-byte secret in a mutable bytearray."""

    __slots__ = ("_closed", "_secret")

    def __init__(self, secret: bytes | bytearray | list[int]) -> None:
        # NOT-PORTED-ZEROIZE: CPython cannot guarantee secret zeroization (GC/hmac copy the key);
        # upgrade: a keyed-hash extension module owning its buffer lifts this ceiling.
        if not isinstance(secret, (bytes, bytearray, list)) or len(secret) != 32:
            raise InvalidAuthorityKey()
        if isinstance(secret, list) and any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 255
            for value in secret
        ):
            raise InvalidAuthorityKey()
        self._secret = bytearray(secret)
        self._closed = False

    def close(self) -> None:
        """Best-effort key wipe."""
        if not self._closed:
            for i in range(len(self._secret)):
                self._secret[i] = 0
            self._closed = True

    def bind(
        self,
        digest: str,
        source_capability: SourceCapability,
        origin: OriginMetadata,
        retention: RetentionPolicy,
        taint: TaintClass,
    ) -> str:
        if self._closed:
            raise InvalidAuthorityKey("Authority key has been closed")
        origin_bytes = _canonical_origin_bytes(origin)
        domain_bytes = (
            digest.encode("utf-8")
            + b"\x00"
            + bytes([source_capability.code()])
            + origin_bytes
            + bytes([retention.code(), taint.code()])
        )
        mac = hmac.new(bytes(self._secret), domain_bytes, hashlib.sha256)
        return mac.hexdigest()

    def verify_binding(
        self,
        digest: str,
        source_capability: SourceCapability,
        origin: OriginMetadata,
        retention: RetentionPolicy,
        taint: TaintClass,
        binding: str,
    ) -> None:
        try:
            validate_binding(binding)
        except ContractError:
            raise BindingMismatch()

        expected = self.bind(digest, source_capability, origin, retention, taint)
        if not hmac.compare_digest(binding, expected):
            raise BindingMismatch()

    def issue(
        self,
        digest: str,
        source_capability: SourceCapability,
        origin: OriginMetadata,
        retention: RetentionPolicy,
        taint: TaintClass,
    ) -> ContentRef:
        validate_digest(digest)
        binding = self.bind(digest, source_capability, origin, retention, taint)
        return ContentRef(
            digest=digest,
            source_capability=source_capability,
            origin=origin,
            retention=retention,
            taint=taint,
            binding=binding,
        )


class ContentAuthority:
    """Bootstrap owner for the content-reference binding key."""

    __slots__ = ("_key",)

    def __init__(self, key: _AuthorityKey) -> None:
        self._key = key

    @classmethod
    def from_secret(cls, secret: bytes | bytearray | list[int]) -> ContentAuthority:
        return cls(_AuthorityKey(secret))

    def issuer(self, source_capability: SourceCapability) -> ContentIssuer:
        return ContentIssuer(self._key, source_capability)

    def resolver(self) -> ContentResolver:
        return ContentResolver(self._key)

    def close(self) -> None:
        self._key.close()

    def __repr__(self) -> str:
        return "ContentAuthority([redacted])"


class ContentIssuer:
    """Root issuer restricted to a single producing capability."""

    __slots__ = ("_key", "_source_capability")

    def __init__(self, key: _AuthorityKey, source_capability: SourceCapability) -> None:
        self._key = key
        self._source_capability = source_capability

    def issue(
        self,
        digest: str,
        origin: OriginMetadata,
        retention: RetentionPolicy,
        taint: TaintClass,
    ) -> ContentRef:
        return self._key.issue(
            digest, self._source_capability, origin, retention, taint
        )

    def __repr__(self) -> str:
        return f"ContentIssuer(source_capability={self._source_capability!r}, key='[redacted]')"


class ContentResolver:
    """Resolver/verifier for existing references. It has no issuance path."""

    __slots__ = ("_key",)

    def __init__(self, key: _AuthorityKey) -> None:
        self._key = key

    def resolve(self, untrusted: UntrustedContentRef) -> ContentRef:
        self._key.verify_binding(
            untrusted._digest,
            untrusted._source_capability,
            untrusted._origin,
            untrusted._retention,
            untrusted._taint,
            untrusted._binding,
        )
        return ContentRef(
            digest=untrusted._digest,
            source_capability=untrusted._source_capability,
            origin=untrusted._origin,
            retention=untrusted._retention,
            taint=untrusted._taint,
            binding=untrusted._binding,
        )

    def __repr__(self) -> str:
        return "ContentResolver([redacted])"
