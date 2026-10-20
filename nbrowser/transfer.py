"""Fixture-scoped upload and in-memory download quarantine (port of
transfer.rs). Host downloads ride the SSRF kernel before any socket opens."""

import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .egress_guard import (
    bare_host,
    connect_admitted,
    is_cross_origin_internal,
    is_public_safe,
)
from .errors import BrowserError, FailureCode

MAX_FIXTURE_TRANSFER_BYTES = 1024 * 1024


def estimated_tokens_for(byte_len: int) -> int:
    return (byte_len + 3) // 4


@dataclass
class TextArtifactCandidate:
    format: str
    body: str


def apply_text_artifacts(
    payload: dict[str, Any],
    candidates: list[TextArtifactCandidate],
    max_content_bytes: int | None,
    stage: Any = None,
) -> None:
    """Spill oversized formats into session-owned refs."""
    estimates: dict[str, int] = {}
    artifacts: dict[str, Any] = {}

    for candidate in candidates:
        # The ceiling is bytes, so every measure here is the UTF-8 length.
        body_bytes = candidate.body.encode("utf-8")
        estimates[candidate.format] = estimated_tokens_for(len(body_bytes))
        if max_content_bytes is None or len(body_bytes) <= max_content_bytes:
            continue
        if stage is None:
            raise BrowserError(
                FailureCode.CONTENT_UNAVAILABLE, "no artifact context to stage into"
            )
        digest = stage(candidate.body)
        artifacts[candidate.format] = {
            "ref": digest,
            "bytes": len(body_bytes),
            "sha256": digest,
        }
        payload.pop(candidate.format, None)

    if estimates:
        payload["estimated_tokens"] = estimates
    if artifacts:
        payload["artifacts"] = artifacts


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


class _HTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self._create_connection = connect_admitted
        super().connect()


class _HTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        self._create_connection = connect_admitted
        super().connect()


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_HTTPSConnection, req)


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect, _HTTPHandler, _HTTPSHandler
)


def download_host_page(
    url: str, timeout: float = 12.0, *, html_only: bool = False
) -> tuple[bytes, str, str, str | None]:
    """Bounded, credential-free, redirect-refusing host GET, with the headers
    the static extractor needs: (body, content_type, content_encoding, charset),
    all lower-cased, the type without parameters, the declared charset or None.
    The SSRF kernel decides BEFORE the socket; public->loopback redirects
    refuse; every 3xx refuses."""
    if not is_public_safe(url):
        raise BrowserError(
            FailureCode.GRANT_REQUIRED, f"download target refused: {bare_host(url)}"
        )
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": (
                "text/html, application/xhtml+xml;q=0.9"
                if html_only
                else "text/markdown, text/plain;q=0.9, text/html;q=0.7, */*;q=0.1"
            ),
            "Accept-Encoding": "identity",
        },
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            if is_cross_origin_internal(final_url, url):
                raise BrowserError(
                    FailureCode.GRANT_REQUIRED,
                    f"redirect into loopback refused: {bare_host(final_url)}",
                )
            length = int(resp.headers.get("Content-Length", "0") or 0)
            if length > MAX_FIXTURE_TRANSFER_BYTES:
                raise BrowserError(
                    FailureCode.CONTENT_BUDGET_EXCEEDED,
                    f"download exceeds 1 MiB bound: {length}",
                )
            data = resp.read(MAX_FIXTURE_TRANSFER_BYTES + 1)
            if len(data) > MAX_FIXTURE_TRANSFER_BYTES:
                raise BrowserError(
                    FailureCode.CONTENT_BUDGET_EXCEEDED, "download exceeds 1 MiB bound"
                )
            type_params = str(resp.headers.get("Content-Type", "")).split(";")
            content_type = type_params[0].strip().lower()
            charset: str | None = None
            for param in type_params[1:]:
                name, _, value = param.partition("=")
                if name.strip().lower() == "charset":
                    charset = value.strip().strip("'\"").lower() or None
                    break
            content_encoding = (
                str(resp.headers.get("Content-Encoding", "")).strip().lower()
            )
            return bytes(data), content_type, content_encoding, charset
    except urllib.error.HTTPError as e:
        if e.code // 100 == 3:
            raise BrowserError(
                FailureCode.GRANT_REQUIRED, f"redirect refused: {e.code}"
            ) from None
        raise BrowserError(
            FailureCode.CONTENT_UNAVAILABLE,
            f"http_{e.code}",
        ) from None
    except (urllib.error.URLError, OSError) as e:
        raise BrowserError(
            FailureCode.CONTENT_UNAVAILABLE, f"transport: {str(e)[:120]}"
        ) from None


def download_host(url: str, timeout: float = 12.0) -> bytes:
    """The bytes of download_host_page: the quarantine and the frontier need
    no headers."""
    return download_host_page(url, timeout)[0]
