"""Request/response metadata with no headers, bodies, cookie values, or credentials."""

import enum
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .errors import BrowserError, InputFailure
from .sanitize import redact_asset_url_keep_path


class HttpMethod(str, enum.Enum):
    GET = "get"
    HEAD = "head"
    POST = "post"
    PUT = "put"
    PATCH = "patch"
    DELETE = "delete"
    OPTIONS = "options"
    OTHER = "other"


@dataclass(frozen=True)
class NetworkEntry:
    method: HttpMethod
    location: str
    status: int | None = None
    encoded_bytes: int | None = None
    seq: int = 0

    @classmethod
    def from_observation(
        cls,
        method: HttpMethod,
        raw_url: str,
        status: int | None = None,
        encoded_bytes: int | None = None,
        seq: int = 0,
    ) -> NetworkEntry:
        parsed = urlsplit(raw_url)
        if parsed.scheme not in ("http", "https"):
            raise BrowserError(InputFailure.QUERY, "unsupported scheme")
        return cls(
            method=method,
            location=redact_asset_url_keep_path(raw_url),
            status=status,
            encoded_bytes=encoded_bytes,
            seq=seq,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "method": self.method.value,
            "location": self.location,
        }
        if self.status is not None:
            out["status"] = self.status
        if self.encoded_bytes is not None:
            out["encoded_bytes"] = self.encoded_bytes
        return out


@dataclass
class NetworkEvidence:
    requests: list[NetworkEntry] = field(default_factory=list)
    taint: str = "network_metadata"
    rung: str = "un_witnessed_local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": [r.to_dict() for r in self.requests],
            "taint": self.taint,
            "rung": self.rung,
        }
