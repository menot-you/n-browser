"""The crawl frontier, pure: strings in, strings out. It opens no socket and
imports no session — the driver (crawl.py) injects the one fetch it needs
(transfer.download_host) for robots.txt, and drives Chromium
itself. Origin is judged on the SEED's scheme+host+PORT: `localhost` and
`127.0.0.1` are different origins, and a link to another loopback port is
another origin too."""

from __future__ import annotations

import enum
import ipaddress
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .errors import BrowserError, FailureCode, InputFailure

DEFAULT_CRAWL_PAGES = 25
MAX_CRAWL_PAGES = 100
Fetch = Callable[[str], bytes]
KINDS = ("crawl",)


class StopReason(enum.StrEnum):
    EXHAUSTED = "exhausted"
    MAX_PAGES = "max_pages"
    DEADLINE = "deadline"


def is_web_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    del port
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)


def _host(parts: Any) -> str:
    host = str(parts.hostname or "").lower()
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return f"[{host}]" if ":" in host else host


def normalize(url: str) -> str:
    """One string per document: no fragment, lowercase scheme and host, the
    default port dropped, the query sorted, an empty path spelled `/`."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = _host(parts) if port is None or default else f"{_host(parts)}:{port}"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))


def origin_key(url: str) -> str:
    """scheme+host+PORT of the url, the port always explicit."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{_host(parts)}:{port}"


def same_origin(url: str, seed: str) -> bool:
    return origin_key(url) == origin_key(seed)


def root_url(url: str, path: str) -> str:
    parts = urlsplit(normalize(url))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def load_robots(fetch: Fetch, seed: str) -> RobotFileParser:
    """robots.txt through the injected fetch, fed to `.parse(lines)` — never
    the parser's own network reader, which opens its own socket (redirects
    followed, no size cap, no SSRF kernel); this source names neither, so
    the contract test can grep for both. The status map mirrors that reader:
    401/403 disallow all, any other 4xx allows all; a 5xx or a dead transport
    is a typed refusal, because a crawl that cannot fetch robots.txt cannot
    fetch pages either."""
    parser = RobotFileParser()
    try:
        body = fetch(root_url(seed, "/robots.txt"))
    except BrowserError as e:
        if e.code is FailureCode.CONTENT_UNAVAILABLE and e.message in (
            "http_401",
            "http_403",
        ):
            parser.parse(["User-agent: *", "Disallow: /"])
            return parser
        if e.code is FailureCode.CONTENT_UNAVAILABLE and e.message.startswith("http_4"):
            parser.parse(["User-agent: *", "Allow: /"])
            return parser
        if e.code is FailureCode.CONTENT_UNAVAILABLE:
            raise BrowserError(
                FailureCode.CONTENT_UNAVAILABLE, f"robots.txt unavailable: {e.message}"
            ) from e
        raise
    parser.parse(body.decode("utf-8", errors="replace").splitlines())
    return parser


def canonical_state_bytes(state: dict[str, Any]) -> bytes:
    return json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Frontier:
    """Same-origin BFS over normalized absolute URLs. `allowed` is the robots
    verdict the driver injects (judged with UA `*`). `state()` and
    `from_state()` round-trip through canonical JSON — the cursor is a
    ContentRef over the digest of those bytes (crawl.py)."""

    def __init__(
        self,
        seed: str,
        allowed: Callable[[str], bool],
        max_pages: int,
        kind: str = "crawl",
    ) -> None:
        if isinstance(max_pages, bool) or max_pages < 1:
            raise BrowserError(InputFailure.OPERATION, "max_pages must be >= 1")
        if kind not in KINDS:
            raise BrowserError(InputFailure.OPERATION, f"unknown frontier kind: {kind}")
        if not is_web_url(seed):
            raise BrowserError(
                InputFailure.OPERATION, f"seed is not an http(s) url: {seed}"
            )
        self.seed = normalize(seed)
        self.kind = kind
        self.allowed = allowed
        self.max_pages = max_pages
        self.queue: list[str] = [self.seed]
        self.seen: set[str] = {self.seed}
        # Pages of THIS call; a resumed frontier starts it empty.
        self.visited: list[str] = []
        self.stop_reason: StopReason | None = None

    def next(self) -> str | None:
        if self.stop_reason is not None:
            return None
        if len(self.visited) >= self.max_pages:
            self.stop_reason = (
                StopReason.MAX_PAGES if self.queue else StopReason.EXHAUSTED
            )
            return None
        while self.queue:
            url = self.queue.pop(0)
            if self.allowed(url):
                return url
        self.stop_reason = StopReason.EXHAUSTED
        return None

    def record(self, url: str, links: list[str], landed: str | None = None) -> None:
        self.visited.append(normalize(url))
        if landed is not None and is_web_url(landed):
            self.seen.add(normalize(landed))
        for link in links:
            if not is_web_url(link) or not same_origin(link, self.seed):
                continue
            n = normalize(link)
            if n in self.seen:
                continue
            self.seen.add(n)
            self.queue.append(n)

    def deadline(self) -> None:
        self.stop_reason = StopReason.DEADLINE if self.queue else StopReason.EXHAUSTED

    def state(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "seed": self.seed,
            "queue": list(self.queue),
            "seen": sorted(self.seen),
        }

    @classmethod
    def from_state(
        cls, state: dict[str, Any], allowed: Callable[[str], bool], max_pages: int
    ) -> Frontier:
        try:
            f = cls(
                str(state["seed"]),
                allowed,
                max_pages,
                kind=str(state["kind"]),
            )
            f.queue = [str(u) for u in state["queue"]]
            f.seen = {str(u) for u in state["seen"]}
        except (KeyError, TypeError, ValueError) as e:
            raise BrowserError(
                InputFailure.CONTENT_REF, f"cursor state unreadable: {e}"
            ) from e
        return f
