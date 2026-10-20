"""The nbrowser_site_crawl driver: the tool lives here and mcp_server.py only
dispatches. The frontier (frontier.py) is pure; the one socket it needs, for
robots.txt, is transfer.download_host. Every page loads inside ONE isolated browser context
per call, disposed in `finally`; same-origin is judged on location.href AFTER
the load, against the SEED's scheme+host+port. A cursor is a ContentRef of
the capture authority over the digest of the canonical frontier state, held
in the per-process resolver: it resumes once, and only in this process."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from nott_spine import (
    AuthorityError,
    ContractError,
    OriginKind,
    OriginMetadata,
    RetentionPolicy,
    SourceCapability,
    TaintClass,
    UntrustedContentRef,
)

from .errors import BrowserError, FailureCode, InputFailure
from .extract import scrape_markdown_live
from .frontier import (
    DEFAULT_CRAWL_PAGES,
    MAX_CRAWL_PAGES,
    Frontier,
    StopReason,
    canonical_state_bytes,
    load_robots,
    origin_key,
    same_origin,
)
from .transfer import TextArtifactCandidate, apply_text_artifacts, download_host
from .types import EffectOperation

if TYPE_CHECKING:
    from .mcp_server import McpServer
    from .session import BrowserSession

# Checked BETWEEN pages: the page in flight adds up to 15 s (Page.loadEventFired)
# plus 30 s per CDP command. Over the deadline the call answers what it has
# and a cursor — that is what the cursor exists for.
CRAWL_DEADLINE_S = 120.0
# Refused by length BEFORE base64/json touch the bytes.
CURSOR_WIRE_CAP = 2048
# Outstanding cursors per process; the oldest is evicted from custody.
MAX_OUTSTANDING_CURSORS = 8
# a.href is already absolute in the browser; the frontier gates origin.
LINKS_WALKER = "Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"

PerPage = Callable[[str, str], tuple[dict[str, Any], list[str]]]


def page_budget(raw: Any, ceiling: int, default: int, name: str) -> int:
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise BrowserError(InputFailure.OPERATION, f"{name} must be an integer")
    if raw < 1:
        raise BrowserError(
            InputFailure.OPERATION, f"{name} must be >= 1 (0 is not a limit)"
        )
    return min(raw, ceiling)


def bytes_ceiling(raw: Any) -> int | None:
    if raw is None:
        return None
    return max(1024, min(4 * 1024 * 1024, int(raw)))


def harvest_links(sess: BrowserSession, tab_id: str) -> list[str]:
    raw = sess.evaluate(tab_id, LINKS_WALKER)
    if not isinstance(raw, list):
        return []
    return [str(href) for href in raw]


def _walk(
    sess: BrowserSession,
    frontier: Frontier,
    per_page: PerPage,
    off_shape: dict[str, Any],
    deadline_s: float = CRAWL_DEADLINE_S,
) -> list[dict[str, Any]]:
    """BFS on ONE tab inside ONE fresh context. No per-page recovery: a late
    Page.loadEventFired would satisfy the next page's wait, so a BrowserError
    propagates whole and `finally` disposes the context."""
    pages: list[dict[str, Any]] = []
    started = time.monotonic()
    ctx = sess.context_open()
    tab: str | None = None
    try:
        while True:
            if time.monotonic() - started > deadline_s:
                frontier.deadline()
                break
            url = frontier.next()
            if url is None:
                break
            if tab is None:
                tab = sess.tabs_open(url, ctx)
            else:
                sess.navigate(tab, url)
            final = str(sess.evaluate(tab, "location.href") or "")
            if not same_origin(final, frontier.seed):
                pages.append({"url": url, **off_shape, "off_origin": origin_key(final)})
                frontier.record(url, [])
                continue
            fields, links = per_page(tab, final)
            frontier.record(url, links, landed=final)
            pages.append({"url": final, **fields})
    finally:
        sess.context_dispose(ctx)
    return pages


def mint_cursor(server: McpServer, state: dict[str, Any]) -> str:
    """Stage the canonical state, bind its digest under the process key."""
    data = canonical_state_bytes(
        {**state, "invocation": state.get("invocation") or secrets.token_hex(8)}
    )
    digest = server._stage_artifact_bytes(data)
    if digest not in server.cursor_digests:
        server.cursor_digests.append(digest)
        while len(server.cursor_digests) > MAX_OUTSTANDING_CURSORS:
            old = server.cursor_digests.pop(0)
            with server.resolver.lock:
                server.resolver.store.pop(old, None)
    origin = OriginMetadata.derived_content(origin_key(str(state["seed"])))
    ref = server.content_authority.issuer(SourceCapability.NBrowser).issue(
        "sha256:" + digest,
        origin,
        RetentionPolicy.EphemeralSession,
        TaintClass.PageDerived,
    )
    return base64.urlsafe_b64encode(ref.to_json().encode("utf-8")).decode("ascii")


def resume_cursor(
    server: McpServer, wire: Any, kind: str, host_url: Any
) -> dict[str, Any]:
    if not isinstance(wire, str) or not wire:
        raise BrowserError(
            InputFailure.CONTENT_REF, "cursor must be a non-empty string"
        )
    if len(wire.encode("utf-8")) > CURSOR_WIRE_CAP:
        raise BrowserError(
            InputFailure.CONTENT_REF, f"cursor exceeds {CURSOR_WIRE_CAP} bytes"
        )
    try:
        raw = json.loads(base64.urlsafe_b64decode(wire.encode("ascii")))
    except binascii.Error, ValueError, UnicodeError:
        raise BrowserError(
            InputFailure.CONTENT_REF, "cursor is not base64url JSON"
        ) from None
    if not isinstance(raw, dict):
        raise BrowserError(InputFailure.CONTENT_REF, "cursor is not a content ref")
    try:
        resolved = server.content_authority.resolver().resolve(
            UntrustedContentRef.from_dict(raw)
        )
    except ContractError as e:
        raise BrowserError(
            InputFailure.CONTENT_REF, f"cursor fields invalid: {e}"
        ) from None
    except AuthorityError:
        raise BrowserError(
            InputFailure.CONTENT_REF, "cursor minted by another process"
        ) from None
    if resolved.origin.kind is not OriginKind.DerivedContent:
        raise BrowserError(InputFailure.CONTENT_REF, "ref is not a crawl cursor")
    if host_url is not None and origin_key(str(host_url)) != resolved.origin.locator:
        raise BrowserError(
            InputFailure.CONTENT_REF,
            f"cursor was minted for {resolved.origin.locator}; host_url is {origin_key(str(host_url))}",
        )
    digest = resolved.digest.removeprefix("sha256:")
    if digest not in server.cursor_digests:
        raise BrowserError(
            FailureCode.CONTENT_UNAVAILABLE, "cursor already resumed or unknown"
        )
    with server.resolver.lock:
        held = server.resolver.store.get(digest)
    if held is None:
        server.cursor_digests.remove(digest)
        raise BrowserError(
            FailureCode.CONTENT_UNAVAILABLE, "cursor already resumed or unknown"
        )
    state = json.loads(held)
    if not isinstance(state, dict) or state.get("kind") != kind:
        raise BrowserError(
            InputFailure.CONTENT_REF,
            f"cursor of kind {state.get('kind')!r} presented to {kind}",
        )
    server.cursor_digests.remove(digest)
    server.resolver.resolve_once(digest)
    return state


def cursor_or_null(server: McpServer, frontier: Frontier) -> str | None:
    if (
        frontier.stop_reason in (StopReason.MAX_PAGES, StopReason.DEADLINE)
        and frontier.queue
    ):
        return mint_cursor(server, frontier.state())
    return None


def _open_frontier(
    server: McpServer,
    *,
    host_url: Any,
    cursor: Any,
    kind: str,
    budget: int,
) -> tuple[Frontier, dict[str, Any] | None]:
    state = (
        resume_cursor(server, cursor, kind, host_url) if cursor is not None else None
    )
    try:
        if state is None and not host_url:
            raise BrowserError(InputFailure.OPERATION, "host_url or cursor is required")
        seed = str(state["seed"]) if state is not None else str(host_url)
        seed = server.seam.authorize_host(EffectOperation.navigate, seed).url
        robots = load_robots(download_host, seed)

        def allowed(url: str) -> bool:
            return bool(robots.can_fetch("*", url))

        if state is not None:
            return Frontier.from_state(
                {k: v for k, v in state.items() if k != "invocation"}, allowed, budget
            ), state
        return Frontier(seed, allowed, budget, kind=kind), None
    except BrowserError:
        if state is not None:
            mint_cursor(server, state)
        raise


def execute_crawl(
    server: McpServer,
    *,
    host_url: Any,
    cursor: Any,
    max_pages: Any,
    max_content_bytes: Any,
) -> dict[str, Any]:
    budget = page_budget(max_pages, MAX_CRAWL_PAGES, DEFAULT_CRAWL_PAGES, "max_pages")
    ceiling = bytes_ceiling(max_content_bytes)
    sess = server.get_session()
    frontier, state = _open_frontier(
        server, host_url=host_url, cursor=cursor, kind="crawl", budget=budget
    )
    try:

        def per_page(tab: str, final: str) -> tuple[dict[str, Any], list[str]]:
            return (
                {"markdown": scrape_markdown_live(sess, tab)},
                harvest_links(sess, tab),
            )

        pages = _walk(sess, frontier, per_page, {"markdown": ""})
        payload: dict[str, Any] = {
            "pages": pages,
            "stop_reason": str(frontier.stop_reason),
            "cursor": cursor_or_null(server, frontier),
            "taint": "page_derived",
            "rung": "un_witnessed_local",
        }
        apply_text_artifacts(
            payload,
            [
                TextArtifactCandidate(
                    format="pages", body=json.dumps(pages, ensure_ascii=False)
                )
            ],
            ceiling,
            stage=server._stage_artifact,
        )
        return payload
    except BrowserError:
        if state is not None:
            # Restore the original cursor after every post-consumption failure.
            mint_cursor(server, state)
        raise
