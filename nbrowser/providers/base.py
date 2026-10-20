"""Provider lane plumbing.

Sync core, urllib at the door. The allowlist is enforced BEFORE any socket
opens: validate_provider_url refuses non-https, non-approved hosts, and
anything the SSRF kernel denies, exactly as the contract does.
"""

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..egress_guard import is_public_safe

PROVIDER_CALL_TIMEOUT = 12
PROVIDER_BODY_CAP = 4 * 1024 * 1024
KEY_MIN = 8
KEY_MAX = 4096

# Exactly four approved provider hosts (d81-provider-web-intelligence-lanes).
APPROVED_HOSTS = (
    "api.z.ai",
    "api.minimax.io",
    "api.tavily.com",
    "api.firecrawl.dev",
)


def is_approved_host(host: str) -> bool:
    return host in APPROVED_HOSTS


def validate_provider_url(url: str) -> str | None:
    """None when valid; the error string otherwise."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "unapproved_scheme: only https is allowed"
    host = parts.hostname or ""
    if not host:
        return "missing_host"
    if not is_approved_host(host):
        return f"unapproved_host: {host}"
    if not is_public_safe(url):
        return "egress_denied"
    return None


class ProviderKey:
    """Vendor key. repr/str redact so credentials never reach logs or errors."""

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "ProviderKey([redacted])"

    def __str__(self) -> str:
        return "[redacted]"

    def expose(self) -> str:
        return self._value

    @classmethod
    def from_env(cls, name: str) -> ProviderKey | None:
        value = os.environ.get(name)
        if value is None:
            return None
        return cls.from_value(value)

    @classmethod
    def from_value(cls, value: str) -> ProviderKey | None:
        if KEY_MIN <= len(value) <= KEY_MAX:
            return cls(value)
        return None


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str | None = None
    date: str | None = None
    providers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "title": self.title,
            "url": self.url,
            "providers": self.providers,
        }
        if self.snippet is not None:
            out["snippet"] = self.snippet
        if self.date is not None:
            out["date"] = self.date
        return out


class LaneStatus:
    OK = "ok"
    SKIPPED_NO_KEY = "skipped_no_key"
    ERROR = "error"
    PENDING = "pending"


@dataclass
class LaneReport:
    provider: str
    status: str
    detail: str | None = None
    ms: int = 0
    results: int = 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "provider": self.provider,
            "status": self.status,
            "ms": self.ms,
            "results": self.results,
        }
        if self.detail is not None:
            out["detail"] = self.detail
        return out


def redact(err: str) -> str:
    first_line = err.splitlines()[0] if err.splitlines() else ""
    truncated = first_line[:120]
    return truncated if truncated else "transport_error"


@dataclass
class HttpResponse:
    status: int
    body: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _bearer_request(
    method: str, base: str, path: str, key: ProviderKey, payload: dict[str, Any] | None
) -> HttpResponse:
    url = base.rstrip("/") + path
    invalid = validate_provider_url(url)
    if invalid:
        raise ProviderTransportError(invalid)
    data = None
    headers = {
        "Authorization": f"Bearer {key.expose()}",
        "accept": "application/json, text-event-stream",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=PROVIDER_CALL_TIMEOUT) as resp:
            body = resp.read(PROVIDER_BODY_CAP + 1).decode("utf-8", errors="replace")
            if len(body) > PROVIDER_BODY_CAP:
                raise ProviderTransportError(f"body_too_large:{resp.status}")
            return HttpResponse(status=resp.status, body=body)
    except urllib.error.HTTPError as e:
        if e.code // 100 in (3,):
            # redirects surface as HTTPError when the handler refuses them
            raise ProviderTransportError(f"redirect_refused:{e.code}") from None
        body = e.read(PROVIDER_BODY_CAP + 1).decode("utf-8", errors="replace")
        if len(body) > PROVIDER_BODY_CAP:
            raise ProviderTransportError(f"body_too_large:{e.code}") from None
        return HttpResponse(status=e.code, body=body)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ProviderTransportError(redact(str(e))) from None


class ProviderTransportError(Exception):
    pass


def bearer_post(
    base: str, path: str, key: ProviderKey, payload: dict[str, Any]
) -> HttpResponse:
    return _bearer_request("POST", base, path, key, payload)
