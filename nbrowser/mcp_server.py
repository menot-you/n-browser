import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict
from typing import Any
from urllib.parse import SplitResult

import nott_database
from nott_database import captures

from .capture import capture_png
from .console import (
    MAX_SESSION_RINGS,
    ConsoleBuffer,
    ConsoleCategory,
    ConsoleLevel,
    least_recent_key,
    merge_rings,
)
from .content_custody import FixtureContentResolver
from .crawl import execute_crawl
from .design import componentize, read_design_blueprint
from .egress_guard import ActivationMode
from .errors import (
    BrowserError,
    FailureCode,
    InputFailure,
    failure_envelope,
)
from .extract import (
    RefMap,
    SnapshotEvidence,
    SnapshotOptions,
    compute_view_digest,
    diff_snapshots,
    snapshot,
)
from .interact import Interaction, interact
from .network import HttpMethod, NetworkEntry, NetworkEvidence
from .providers.merge import fan_out_search
from .sanitize import wrap_content_boundaries
from .seam import AuthoritySeam
from .session import BrowserLaunchConfig, BrowserSession
from .transfer import TextArtifactCandidate, apply_text_artifacts
from .types import (
    EffectOperation,
)

INPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "nbrowser_page_navigate": {
        "type": "object",
        "properties": {"host_url": {"type": "string"}},
        "required": ["host_url"],
    },
    "nbrowser_page_snapshot": {
        "type": "object",
        "properties": {
            "include_cards": {"type": "boolean"},
            "delta": {"type": "boolean", "default": False},
        },
    },
    "nbrowser_page_capture": {
        "$defs": {
            "RetentionChoice": {
                "enum": ["ephemeral_session", "no_store", "managed_purgeable"],
                "type": "string",
            }
        },
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {"retention": {"$ref": "#/$defs/RetentionChoice"}},
        "required": ["retention"],
        "type": "object",
    },
    "nbrowser_content_show": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "ref": {"type": "string"},
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "max_chars": {
                "type": "integer",
                "minimum": 1,
                "default": 20000,
                "description": "Maximum characters to return; clamped to 200000.",
            },
        },
        "required": ["ref"],
        "type": "object",
    },
    "nbrowser_site_crawl": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "cursor": {
                "default": None,
                "description": "Resume token from a previous crawl of this process (opaque; resumes once; refused when minted by another process).",
                "type": ["string", "null"],
            },
            "host_url": {
                "default": None,
                "description": "Seed URL; the crawl stays on its scheme+host+port. Required unless cursor is given.",
                "type": ["string", "null"],
            },
            "max_content_bytes": {
                "default": None,
                "description": "Byte ceiling for the inline pages; above it the pages ride a session-owned artifact ref. Omitted: no ceiling — every page returns inline.",
                "format": "uint",
                "minimum": 0,
                "type": ["integer", "null"],
            },
            "max_pages": {
                "default": None,
                "description": "Pages to visit in this call: default 25, ceiling 100; 0 is invalid_input.",
                "format": "uint",
                "minimum": 0,
                "type": ["integer", "null"],
            },
        },
        "type": "object",
    },
    "nbrowser_page_extract": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "limit": {
                "default": 50,
                "description": "Maximum matches, clamped to 1..500 (default 50); ignored with urls.",
                "format": "uint",
                "minimum": 0,
                "type": "integer",
            },
            "max_content_bytes": {
                "default": None,
                "description": "With urls: a ceiling on the documents' JSON, clamped to 1024..4194304; above it `documents` moves to a ref that nbrowser_content_show reads. Omitted: no ceiling. Without urls it does not shrink the answer: the matches stay inline, and a copy above the ceiling is also staged as a ref.",
                "format": "uint",
                "minimum": 0,
                "type": ["integer", "null"],
            },
            "mode": {
                "default": "auto",
                "enum": ["auto", "static", "browser"],
                "type": "string",
            },
            "html_only": {
                "default": False,
                "description": "With static URLs, request and extract only HTML or XHTML. Refuse other modes when true.",
                "type": "boolean",
            },
            "urls": {
                "default": None,
                "description": "URLs to extract as markdown (at most 50). mode: static = HTTP GET through the SSRF seam + stdlib projection, no Chromium; browser = one isolated context per url; auto (default) = static, falling to the browser only when the static markdown is empty or the seam refuses a redirect. In static/auto, 4xx/5xx/transport refuse content_unavailable and a non-HTML body is skipped:content_type. Browser mode does not judge HTTP status; its markdown is what Chromium renders, including error pages.",
                "items": {"type": "string"},
                "type": ["array", "null"],
            },
            "what": {
                "default": "",
                "description": "Case-insensitive substring to find in the snapshot's text blocks; empty returns the first `limit` blocks. Ignored with urls.",
                "type": "string",
            },
            "outline": {
                "default": False,
                "description": "When true, return only markdown heading lines (# .. ######).",
                "type": "boolean",
            },
            "filter": {
                "default": "",
                "description": "Optional heading substring filter; returns matching markdown sections.",
                "type": "string",
            },
            "content_boundaries": {
                "default": False,
                "description": "When true, wrap returned page text in CSPRNG-nonced boundary delimiters.",
                "type": "boolean",
            },
        },
        "type": "object",
    },
    "nbrowser_page_interact": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "verb": {"type": "string"},
            "selector": {"type": "string", "default": ""},
            "ref": {"type": "string", "default": ""},
            "text": {"type": "string", "default": ""},
            "value": {"type": "string", "default": ""},
            "key": {"type": "string", "default": ""},
            "x": {"type": "integer", "default": 0},
            "y": {"type": "integer", "default": 0},
            "human": {"type": "boolean", "default": False},
            "seed": {"type": "integer", "default": 0},
        },
        "required": ["verb"],
        "type": "object",
    },
    "nbrowser_page_scrape": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "format": {
                "default": "prompt",
                "enum": ["prompt", "markdown", "design", "components"],
                "type": "string",
            },
            "host_url": {
                "default": "",
                "description": "Optional URL to navigate to under the SSRF kernel before scraping. Omit to scrape the current page.",
                "type": "string",
            },
            "max_content_bytes": {
                "default": 65536,
                "description": "Spill larger text to a session-owned artifact; clamped to 1 KiB..4 MiB.",
                "type": "integer",
            },
            "content_boundaries": {
                "default": False,
                "description": "When true, wrap returned text in CSPRNG-nonced boundary delimiters.",
                "type": "boolean",
            },
        },
        "type": "object",
    },
    "nbrowser_web_search": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "max_results": {
                "default": 10,
                "description": "Optional maximum number of "
                "hits to return (default 10, "
                "max 50).",
                "format": "uint",
                "minimum": 0,
                "type": "integer",
            },
            "query": {
                "description": "Natural language or keyword query "
                "string to search across providers.",
                "type": "string",
            },
        },
        "required": ["query"],
        "type": "object",
    },
}

TOOL_NAMES = [
    "nbrowser_page_snapshot",
    "nbrowser_page_extract",
    "nbrowser_page_scrape",
    "nbrowser_site_crawl",
    "nbrowser_page_interact",
    "nbrowser_token_extract",
    "nbrowser_console_show",
    "nbrowser_network_show",
    "nbrowser_page_capture",
    "nbrowser_session_show",
    "nbrowser_tab_list",
    "nbrowser_page_navigate",
    "nbrowser_content_show",
    "nbrowser_web_search",
]

# Tool descriptions describe the handlers served by this runtime.
TOOL_DESCRIPTIONS: dict[str, str] = {
    "nbrowser_page_snapshot": "Read the active tab's page: {view: {url, title, state (ready, loading, empty or {blocked: reason}), http_status, visible_text (at most 40,000 characters: the text blocks joined), text_blocks (at most 200), elements (at most 512), forms, cards, ...}, digest}. This becomes the latest snapshot that nbrowser_page_extract (without urls) reads. include_cards (default true) adds up to 50 article and list cards.",
    "nbrowser_page_extract": "Two modes. Without urls: filter the latest nbrowser_page_snapshot (taken now only if none exists) and return {matches, count, what}: the text blocks containing `what` (case-insensitive), at most `limit`. When nothing matches, matches holds the page's first 200 characters instead (count 1), so check that a match contains `what`. With urls (1..50): return {documents: [{url, mode_used, markdown}]} and ignore what and limit. mode auto (default) fetches statically through the SSRF guard and uses Chromium only when the markdown is empty or a redirect is refused; static never uses Chromium; browser renders each url in an isolated context and does not check HTTP status. In static and auto, an HTTP 4xx/5xx or transport error on any url refuses the whole call (content_unavailable); a non-HTML body returns skipped: content_type.",
    "nbrowser_page_scrape": "Scrape the active page: format is prompt (default, visible text), markdown, design (rendered blueprint), or components (componentized blueprint). Optional host_url navigates under the SSRF kernel first. Text above max_content_bytes (default 64 KiB, clamped to 1 KiB..4 MiB) returns a session-owned artifact ref for nbrowser_content_show. It reads the active tab (after navigating to host_url, if given) and replaces the latest snapshot; to read several pages, or one without navigating the active tab, use nbrowser_page_extract with urls. design and components return the blueprint JSON inline; max_content_bytes applies only to prompt and markdown.",
    "nbrowser_site_crawl": "Crawl a site same-origin (scheme+host+port of host_url) inside one isolated browser context: robots.txt honoured for UA *, breadth-first over the page links, each page as markdown. Stops at max_pages (default 25, ceiling 100), when the site is exhausted, or at the 120 s deadline, and, when pages remain (max_pages or deadline), returns a cursor that resumes once in this process; null when exhausted. A page that lands on another origin is recorded with off_origin and never harvested. No politeness beyond max_pages.",
    "nbrowser_page_interact": "Apply one interaction to the active tab, which must be a public or loopback http(s) page. This tool dispatches these eleven verbs: click, hover, scroll, focus, type, fill_form, clear, select, press_key, submit and auth_login. click and submit resolve the action URL of their control first, and refuse it (grant_required) when it leaves the page's origin for a private or loopback target; use nbrowser_page_navigate to change the page. press_key dispatches the named key to the focused element; an Enter that submits a form resolves the form's action URL the same way. auth_login fills a saved login profile, only on that profile's own origin. back, refresh and dialog refuse with grant_required. drag refuses with invalid_input. An interaction that takes no effect (nothing matches `selector`, a scroll that does not move) refuses with invalid_input. Returns {status, verb, url, observed_state}.",
    "nbrowser_token_extract": "Read the active tab's design theme as {palette, fonts, spacing, custom_properties, taint, rung}: the theme nbrowser_page_scrape format=design returns, without the rest of the blueprint. fonts are the most-used font-family values, not evidence that a font loaded.",
    "nbrowser_console_show": "Read closed, redacted console metadata from every attached tab: one ring per CDP session, and a detached or disposed session drops its ring. Returns {entries, taint, rung}: only each entry's level and category, at most the latest 200 entries merged across the sessions so every session that holds entries is represented, newest last; message text and arguments are never captured.",
    "nbrowser_network_show": "Read closed, credential-free request metadata (method + sanitized location) from every attached tab: one ring per CDP session, and a detached or disposed session drops its ring. At most the latest 500 entries merged across the sessions so every session that holds entries is represented, newest last.",
    "nbrowser_page_capture": "Screenshot the active tab as a PNG; the image is not returned to you. Returns {ref, bytes, sha256, taint, retention, source}; nbrowser_content_show refuses the ref. retention no_store and ephemeral_session keep no bytes. managed_purgeable keeps one copy in the owner's capture cache until the owner clears it. It is refused (grant_required) when a NOTT host did not start this server.",
    "nbrowser_session_show": "Read the active local session state",
    "nbrowser_tab_list": "List local browser tabs with origin-only locations",
    "nbrowser_page_navigate": "Navigate the active tab to host_url (http or https; public hosts or loopback; private-network, link-local and cloud-metadata addresses are refused), opening a tab if none is open and launching headless Chromium on first use. Returns {status, url} with the requested url; the address the page landed on is the next snapshot's view.url. Navigation does not refresh the latest snapshot: call nbrowser_page_snapshot before nbrowser_page_extract (without urls).",
    "nbrowser_content_show": "Read a session-owned text artifact in character pages: offset defaults to 0; max_chars defaults to 20000 and is clamped to 200000. Returns content, offset, next_offset (null at end), and total_chars. The final page consumes the ref. Capture and download artifacts are refused, never inlined as text.",
    "nbrowser_web_search": "Unified search across keyed web-intelligence providers (Z.ai, MiniMax, Tavily, Firecrawl). Queries all configured providers concurrently, merges and dedupes hits. Returns {hits, lanes, estimated_tokens}. The query is sent to every provider with a key; a provider without a key is reported in lanes as skipped_no_key, so zero hits with every lane skipped means search is unconfigured.",
}


TOOLS = [
    {
        "name": name,
        "description": TOOL_DESCRIPTIONS[name],
        "inputSchema": INPUT_SCHEMAS.get(name, {"type": "object", "properties": {}}),
    }
    for name in TOOL_NAMES
]

# Runtime.consoleAPICalled `type` -> (level, category). Any other type is
# INFO/OTHER; the payload's arguments never cross into the buffer.
CONSOLE_KINDS: dict[str, tuple[ConsoleLevel, ConsoleCategory]] = {
    "log": (ConsoleLevel.INFO, ConsoleCategory.LOG),
    "info": (ConsoleLevel.INFO, ConsoleCategory.LOG),
    "warning": (ConsoleLevel.WARNING, ConsoleCategory.LOG),
    "error": (ConsoleLevel.ERROR, ConsoleCategory.LOG),
    "debug": (ConsoleLevel.DEBUG, ConsoleCategory.LOG),
    "assert": (ConsoleLevel.ERROR, ConsoleCategory.ASSERTION),
    "startGroup": (ConsoleLevel.INFO, ConsoleCategory.GROUP),
    "startGroupCollapsed": (ConsoleLevel.INFO, ConsoleCategory.GROUP),
    "endGroup": (ConsoleLevel.INFO, ConsoleCategory.GROUP),
}
# Bounded at APPEND per CDP sessionId, on the reader thread.
NETWORK_RING = 500
CAMPAIGN_B_TOOLS: frozenset[str] = frozenset()
# One Runtime.evaluate on the tab's session: the frame a coordinate is bound
# to must be the frame the screenshot was taken in, never Page.getLayoutMetrics
# on a second session.
VIEWPORT_PROBE = (
    "({w: window.innerWidth, h: window.innerHeight, "
    "dpr: window.devicePixelRatio, href: location.href})"
)


#: THE INSTRUCTIONS ARE A CONSTANT, not a string inside `initialize`.
#: Measured 2026-09-16 over 87,551 calls in the owner's real sessions: nMEMORY,
#: whose description says WHEN to use it, got 5,064 calls across 189 sessions; this
#: server, whose description was 61 bytes saying what it is, got 17 across 9 — with
#: 36 installed tools eating context budget for the whole session. That is not
#: underuse, it is a context tax with no return. The triggers go up front and name
#: the tool for each moment: a trigger without a tool name is advice, not a trigger.
SERVER_INSTRUCTIONS = (
    "nBrowser: headless-browser reads of live pages. Triggers — "
    "reach for these by WHEN, not by what they are: when a claim depends on "
    "what a page says now, read it with nbrowser_page_extract (urls) or "
    "nbrowser_page_scrape (host_url), which load the page in the same call, and "
    "cite its URL rather than an ad hoc fetch; when the "
    "fact is somewhere on the open web and you do not have the URL, start with "
    "nbrowser_web_search."
)


def origin_of(parts: SplitResult) -> str:
    """The ascii origin serialization: scheme, host, and a non-default port.
    Never the netloc — that carries userinfo."""
    port_val = parts.port
    is_default = (parts.scheme == "https" and port_val == 443) or (
        parts.scheme == "http" and port_val == 80
    )
    port = f":{port_val}" if (port_val and not is_default) else ""
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{port}"


class McpServer:
    def __init__(self) -> None:
        self.tools = TOOLS
        self.session: BrowserSession | None = None
        self.seam = AuthoritySeam(
            activation=ActivationMode.LOCAL_DOM_EXCEPTION,
        )
        self.resolver = FixtureContentResolver()
        # Digests staged as crawl/map cursors: nbrowser_content_show refuses
        # them, and at most MAX_OUTSTANDING_CURSORS are held (crawl.py).
        self.cursor_digests: list[str] = []
        from nott_spine import ContentAuthority

        # Born with the process: a public constant lets anyone who read the
        # source mint a ref that verifies, and refs never cross processes
        # (FixtureContentResolver.store is a per-process dict).
        self.content_authority = ContentAuthority.from_secret(secrets.token_bytes(32))
        self.console_buffer = ConsoleBuffer()
        self.network_entries: dict[str, list[NetworkEntry]] = {}
        self._network_lock = threading.Lock()
        # A monotonic append sequence across all network rings gives one order.
        self._network_seq = 0
        self.last_snapshot: SnapshotEvidence | None = None
        self.ref_map = RefMap()

    def close(self) -> None:
        if self.session is not None and not self.session.closed:
            self.session.close_session()

    def get_session(self) -> BrowserSession:
        if self.session is None or self.session.closed:
            self.session = BrowserSession(
                BrowserLaunchConfig(headless=True), on_event=self.on_cdp_event
            )
        return self.session

    def on_cdp_event(self, event: dict[str, Any]) -> None:
        """Reader-thread sink for the frames CdpPipeClient consumes.

        NEVER raises: it runs on the pipe's reader thread, which catches
        OSError only. Every field is read defensively and every refusal is a
        silent drop — an unreadable frame is not evidence. Each CDP sessionId
        keeps its own console and network ring; frames with no sessionId share
        one ring. A detached session (Target.detachedFromTarget, fired when a
        flattened session closes or its context is disposed) drops its rings."""
        from urllib.parse import urlsplit

        method = event.get("method")
        params = event.get("params")
        if not isinstance(params, dict):
            return
        session_id = str(event.get("sessionId") or "")
        if method == "Target.detachedFromTarget":
            detached = str(params.get("sessionId") or session_id)
            if detached:
                self.console_buffer.drop(detached)
                with self._network_lock:
                    self.network_entries.pop(detached, None)
            return
        if method == "Runtime.consoleAPICalled":
            level, category = CONSOLE_KINDS.get(
                str(params.get("type", "")),
                (ConsoleLevel.INFO, ConsoleCategory.OTHER),
            )
            self.console_buffer.record(session_id, level, category)
            return
        if method == "Runtime.exceptionThrown":
            self.console_buffer.record(
                session_id, ConsoleLevel.ERROR, ConsoleCategory.DIAGNOSTIC
            )
            return
        if method != "Fetch.requestPaused":
            return
        request = params.get("request")
        if not isinstance(request, dict):
            return
        url = str(request.get("url", ""))
        try:
            scheme = urlsplit(url).scheme
        except ValueError:
            return
        if scheme not in ("http", "https"):
            # data:/blob:/about: sub-resources: from_observation would raise
            # here, on the reader thread, and take the pipe down with it.
            return
        try:
            http_method = HttpMethod(str(request.get("method", "")).lower())
        except ValueError:
            http_method = HttpMethod.OTHER
        # status and encoded_bytes stay None: Fetch.requestPaused is observed
        # before any response exists. ponytail: Network.responseReceived is
        # the upgrade when a caller asks for a status.
        with self._network_lock:
            if (
                session_id not in self.network_entries
                and len(self.network_entries) >= MAX_SESSION_RINGS
            ):
                self.network_entries.pop(least_recent_key(self.network_entries), None)
            ring = self.network_entries.setdefault(session_id, [])
            entry = NetworkEntry.from_observation(
                http_method, url, seq=self._network_seq
            )
            self._network_seq += 1
            if len(ring) >= NETWORK_RING:
                del ring[0]
            ring.append(entry)

    def _stage_artifact(self, body: str) -> str:
        return self._stage_artifact_bytes(body.encode("utf-8"), "text")

    def _stage_artifact_bytes(self, data: bytes, kind: str = "binary") -> str:
        import hashlib

        digest = hashlib.sha256(data).hexdigest()
        # Text keeps its existing ref; binary kinds have separate custody even
        # when their bytes match text or another binary producer exactly.
        ref = f"{kind}:{digest}" if kind == "download" else digest
        self.resolver.store_bytes(ref, data, kind)
        return ref

    def handle_tool_call(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        if name not in TOOL_NAMES:
            raise BrowserError(InputFailure.OPERATION, f"Tool {name} not found")

        if name == "nbrowser_site_crawl":
            return self._tool_crawl(params)

        if name == "nbrowser_page_navigate":
            return self._tool_navigate(params)

        if name == "nbrowser_page_interact":
            return self._tool_interact(params)

        if name == "nbrowser_page_snapshot":
            return self._tool_snapshot(params)

        if name == "nbrowser_web_search":
            return self._tool_search(params)

        if name == "nbrowser_page_scrape":
            return self._tool_scrape(params)

        if name == "nbrowser_page_capture":
            return self._tool_capture(params)

        if name == "nbrowser_content_show":
            return self._tool_content_get(params)

        if name == "nbrowser_tab_list":
            return self._tool_tabs_list()

        if name == "nbrowser_session_show":
            return self._tool_session_get()

        if name == "nbrowser_console_show":
            return self._tool_console()

        if name == "nbrowser_network_show":
            return self._tool_network()

        if name == "nbrowser_token_extract":
            return self._tool_tokens()

        if name == "nbrowser_page_extract":
            return self._tool_extract(params)

        raise BrowserError(
            FailureCode.NOT_IMPLEMENTED, f"Tool {name} is not implemented yet"
        )

    def _tool_crawl(self, params: dict[str, Any]) -> dict[str, Any]:
        return execute_crawl(
            self,
            host_url=params.get("host_url"),
            cursor=params.get("cursor"),
            max_pages=params.get("max_pages"),
            max_content_bytes=params.get("max_content_bytes"),
        )

    def _tool_navigate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("host_url", "")
        if not url:
            # No fixture runtime in this port stage yet; the specification's
            # fixture_path fallback is not reachable, so refuse typed.
            raise BrowserError(InputFailure.OPERATION, "host_url is required")

        # Authorize via Seam
        target = self.seam.authorize_host(EffectOperation.navigate, url)

        sess = self.get_session()
        tabs = sess.tabs_list()
        if not tabs:
            tab_id = sess.tabs_open(target.url)
        else:
            tab_id = tabs[0]
            sess.navigate(tab_id, target.url)

        return {"status": "navigated", "url": target.url}

    def _tool_interact(self, params: dict[str, Any]) -> dict[str, Any]:
        verb = params.get("verb", "")
        try:
            op = EffectOperation(verb)
        except ValueError:
            raise BrowserError(
                InputFailure.OPERATION, f"unknown interaction verb: {verb}"
            )
        if op is EffectOperation.drag:
            # EffectOperation carries `drag` for the run loop's ledger, but
            # a drag needs a DESTINATION and this tool's schema declares
            # none. Without the guard it would build an empty to_selector,
            # find no target, and answer `selector not found` — a refusal
            # by accident, whose message names the wrong cause.
            raise BrowserError(
                InputFailure.OPERATION,
                "drag needs a destination element and this tool takes none",
            )
        raw_ref = str(params.get("ref", "") or "")
        interaction = Interaction(
            verb=verb,
            selector=params.get("selector", ""),
            ref=raw_ref,
            text=params.get("text", ""),
            value=params.get("value", ""),
            key=params.get("key", ""),
            x=int(params.get("x", 0)),
            y=int(params.get("y", 0)),
            human=bool(params.get("human", False)),
            seed=int(params.get("seed", 0)),
        )
        sess = self.get_session()
        tabs = sess.tabs_list()
        if not tabs:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active page")
        tab_id = tabs[0]
        active_url = str(sess.evaluate(tab_id, "location.href") or "")
        try:
            from urllib.parse import urlsplit

            parsed_act = urlsplit(active_url)
            interaction.expected_origin = origin_of(parsed_act)
        except ValueError, TypeError, KeyError, AttributeError:
            pass

        if raw_ref:
            live_doc_gen = str(
                sess.evaluate(
                    tab_id, "String(window[Symbol.for('nbrowser.docGen')] || '')"
                )
                or ""
            )
            entry = self.ref_map.resolve(tab_id, active_url, live_doc_gen, raw_ref)
            if not interaction.selector:
                interaction.selector = entry.selector
            interaction.node_uid = entry.node_uid
            interaction.doc_gen = (
                "" if entry.doc_gen.startswith("url:") else entry.doc_gen
            )
            interaction.fallback_kind = entry.kind
            interaction.fallback_label = entry.label
            interaction.fallback_name = entry.name
            interaction.fallback_count = entry.sibling_count

        permit = self.seam.authorize_host_activation(op, active_url, interaction)

        applied = interact(sess, interaction, tab_id)
        if not applied:
            raise BrowserError(
                InputFailure.SELECTOR,
                f"selector not found: {interaction.selector or raw_ref}",
            )
        return {
            "status": "applied",
            "verb": verb,
            "url": permit.url,
            "observed_state": "state_changed"
            if verb in ("submit", "auth_login")
            else "succeeded",
        }

    def _tool_snapshot(self, params: dict[str, Any]) -> dict[str, Any]:
        sess = self.get_session()
        include_cards = params.get("include_cards", True)
        want_delta = bool(params.get("delta", False))
        prev_view = self.last_snapshot.view if self.last_snapshot else None
        options = SnapshotOptions(include_cards=include_cards)
        evidence = snapshot(sess, options)
        active_tab = getattr(sess, "_active_tab", None) or "t0"
        self.ref_map.record_snapshot(active_tab, evidence.view)
        evidence.digest = compute_view_digest(evidence.view)
        self.last_snapshot = evidence
        out: dict[str, Any] = {
            "view": asdict(evidence.view),
            "digest": evidence.digest,
        }
        if want_delta and prev_view is not None:
            out["delta"] = diff_snapshots(prev_view, evidence.view)
        elif want_delta:
            out["delta"] = diff_snapshots(evidence.view, evidence.view)
        return out

    def _tool_search(self, params: dict[str, Any]) -> dict[str, Any]:
        query = params.get("query", "")
        if not query:
            raise BrowserError(InputFailure.QUERY, "query is required")
        raw = params.get("max_results")
        if raw is None:
            max_results = 10
        elif isinstance(raw, bool) or not isinstance(raw, int):
            raise BrowserError(InputFailure.OPERATION, "max_results must be an integer")
        else:
            max_results = raw
        max_results = max(1, min(50, max_results))
        hits, lanes = fan_out_search(query, max_results)
        estimated_tokens = (
            sum(len((h.snippet or "").encode("utf-8")) for h in hits) // 4
        )
        return {
            "hits": [h.to_dict() for h in hits],
            "lanes": [l.to_dict() for l in lanes],
            "estimated_tokens": estimated_tokens,
        }

    def _tool_scrape(self, params: dict[str, Any]) -> dict[str, Any]:
        host_url = params.get("host_url", "")
        if host_url:
            self.handle_tool_call("nbrowser_page_navigate", {"host_url": host_url})
        fmt = params.get("format", "prompt")
        if fmt not in ("prompt", "markdown", "design", "components"):
            raise BrowserError(InputFailure.OPERATION, f"unsupported format: {fmt}")
        max_content_bytes = int(params.get("max_content_bytes", 65536))
        max_content_bytes = max(1024, min(4 * 1024 * 1024, max_content_bytes))
        use_boundaries = bool(params.get("content_boundaries", False))

        self.handle_tool_call("nbrowser_page_snapshot", {})
        view = self.last_snapshot.view if self.last_snapshot else None
        if view is None:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no snapshot")

        sess = self.get_session()
        tabs = sess.tabs_list()
        if not tabs:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active page")
        if fmt == "markdown":
            from .extract import scrape_markdown_live

            text = scrape_markdown_live(sess, tabs[0])
        elif fmt == "design":
            blueprint = read_design_blueprint(sess, tabs[0])
            return blueprint.to_dict()
        elif fmt == "components":
            blueprint = read_design_blueprint(sess, tabs[0])
            ir = componentize(blueprint)
            return ir.to_dict()
        else:
            text = view.visible_text

        if use_boundaries:
            text = wrap_content_boundaries(text, view.url)

        payload: dict[str, Any] = {"format": fmt, fmt: text}
        apply_text_artifacts(
            payload,
            [TextArtifactCandidate(format=fmt, body=text)],
            max_content_bytes,
            stage=lambda body: self._stage_artifact(body),
        )
        payload["truncated"] = "artifacts" in payload
        return payload

    def _tool_capture(self, params: dict[str, Any]) -> dict[str, Any]:
        retention = str(params.get("retention", "no_store"))
        if retention not in ("no_store", "ephemeral_session", "managed_purgeable"):
            raise BrowserError(InputFailure.OPERATION, f"bad retention: {retention}")
        # Only the node host grants capture retention to this server.
        if retention == "managed_purgeable" and (
            os.environ.get("NOTT_NBROWSER_CAPTURE_KEEP") != "1"
            or not os.environ.get(nott_database.DIRECTORY_VARIABLE)
        ):
            raise BrowserError(
                FailureCode.GRANT_REQUIRED,
                "managed_purgeable requires a persistence grant",
            )
        from urllib.parse import urlsplit

        from nott_spine import (
            CaptureFrame,
            ContractError,
            OriginMetadata,
            RetentionPolicy,
            SourceCapability,
            TaintClass,
        )

        sess = self.get_session()
        tabs = sess.tabs_list()
        if not tabs:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active page")
        tab_id = tabs[0]
        client = sess.client
        if client is None:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no CDP endpoint")
        # The tab's ONE flattened session, never a fresh attach: a second
        # attach births a second session and re-arms the interceptor.
        session_id = sess._session_for(tab_id)
        probe = sess.evaluate(tab_id, VIEWPORT_PROBE)
        if not isinstance(probe, dict):
            raise BrowserError(
                FailureCode.CAPTURE_EXPORT_FAILED,
                "viewport probe answered no object",
            )
        w, h, dpr = probe.get("w"), probe.get("h"), probe.get("dpr")
        if (
            any(isinstance(v, bool) or not isinstance(v, int) for v in (w, h))
            or isinstance(dpr, bool)
            or not isinstance(dpr, int | float)
            or not isinstance(probe.get("href"), str)
        ):
            raise BrowserError(
                FailureCode.CAPTURE_EXPORT_FAILED,
                "viewport probe answered with a non-numeric frame",
            )
        shot = client.send("Page.captureScreenshot", {"format": "png"}, session_id)
        data = capture_png(lambda: shot.get("data"))
        digest = hashlib.sha256(data).hexdigest()
        # Validate the frame before any side effect: a rejected probe must not
        # leave a staged blob or a kept PNG behind.
        try:
            frame = CaptureFrame(
                int(probe["w"]), int(probe["h"]), float(probe["dpr"]), digest
            )
        except ContractError as error:
            raise BrowserError(
                FailureCode.CAPTURE_EXPORT_FAILED,
                f"viewport probe is not a valid capture frame: {error}",
            ) from error
        # The digest is the ref: capture bytes never enter the resolver store.
        ref = f"capture:{digest}"
        if retention == "managed_purgeable":
            try:
                captures.keep(data)
            except captures.RefusedError as error:
                raise BrowserError(
                    FailureCode.CAPTURE_EXPORT_FAILED, str(error)
                ) from error
        origin = OriginMetadata.browser_capture(
            origin_of(urlsplit(str(probe["href"]))),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            frame,
        )
        policy = {
            "no_store": RetentionPolicy.NoStore,
            "ephemeral_session": RetentionPolicy.EphemeralSession,
            "managed_purgeable": RetentionPolicy.ManagedPurgeable,
        }[retention]
        source = self.content_authority.issuer(SourceCapability.NBrowser).issue(
            "sha256:" + digest, origin, policy, TaintClass.PixelDerived
        )
        # Pixels never ride stdio: the ref does.
        return {
            "ref": ref,
            "bytes": len(data),
            "sha256": digest,
            "taint": "pixel_derived",
            "retention": retention,
            "source": source.to_dict(),
        }

    def _tool_content_get(self, params: dict[str, Any]) -> dict[str, Any]:
        ref = params.get("ref", "")
        if not isinstance(ref, str) or not ref:
            raise BrowserError(InputFailure.CONTENT_REF, "ref is required")
        if ref in self.cursor_digests:
            raise BrowserError(
                InputFailure.CONTENT_REF,
                "ref is a crawl cursor; resume it through nbrowser_site_crawl",
            )
        if ref.startswith("capture:"):
            raise BrowserError(
                FailureCode.CONTENT_UNAVAILABLE,
                "capture pixels never ride the text door",
            )
        offset = params.get("offset", 0)
        max_chars = params.get("max_chars", 20000)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise BrowserError(
                InputFailure.OPERATION, "offset must be a non-negative integer"
            )
        if (
            isinstance(max_chars, bool)
            or not isinstance(max_chars, int)
            or max_chars < 1
        ):
            raise BrowserError(
                InputFailure.OPERATION, "max_chars must be a positive integer"
            )
        text, next_offset, total_chars = self.resolver.resolve_text_page(
            ref, offset, max_chars
        )
        return {
            "ref": ref,
            "content": text,
            "offset": offset,
            "next_offset": next_offset,
            "total_chars": total_chars,
        }

    def _tool_tabs_list(self) -> dict[str, Any]:
        sess = self.get_session()
        client = sess.client
        if client is None:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active session")
        targets = client.send("Target.getTargets").get("targetInfos", [])
        from urllib.parse import urlsplit

        page_tabs: list[dict[str, str]] = []
        for t in targets:
            if t.get("type") == "page":
                tid = str(t.get("targetId", ""))
                turl = str(t.get("url", ""))
                orig = origin_of(urlsplit(turl)) if turl else ""
                page_tabs.append({"tab_id": tid, "origin": orig})
        return {"tabs": page_tabs}

    def _tool_session_get(self) -> dict[str, Any]:
        active = self.session is not None and not self.session.closed
        tabs_count = 0
        if active and self.session is not None:
            # A refusal from the session travels: a count of 0 over a dead
            # client is not a fact about the session.
            tabs_count = len(self.session.tabs_list())
        return {"active": active, "tabs_count": tabs_count}

    def _tool_console(self) -> dict[str, Any]:
        return self.console_buffer.evidence().to_dict()

    def _tool_network(self) -> dict[str, Any]:
        with self._network_lock:
            rings = [list(ring) for ring in self.network_entries.values()]
        from nott_spine import ReceiptRung, TaintClass

        # Each session keeps its own ring in storage; one merged read is capped
        # at the network ceiling, represents every ring that holds entries, and
        # is ordered newest last.
        return NetworkEvidence(
            requests=merge_rings(rings, NETWORK_RING),
            taint=TaintClass.NetworkMetadata.value,
            rung=ReceiptRung.UnwitnessedLocal.value,
        ).to_dict()

    def _tool_tokens(self) -> dict[str, Any]:
        sess = self.get_session()
        tabs = sess.tabs_list()
        if not tabs:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active page")
        blueprint = read_design_blueprint(sess, tabs[0])
        theme = blueprint.theme
        return {
            "palette": theme.palette,
            "fonts": theme.fonts,
            "spacing": theme.spacing,
            "custom_properties": [
                {"name": cp.name, "value": cp.value} for cp in theme.custom_properties
            ],
            "taint": "page_derived",
            "rung": "un_witnessed_local",
        }

    def _tool_extract(self, params: dict[str, Any]) -> dict[str, Any]:
        what = str(params.get("what", "") or "")
        raw_limit: Any = params.get("limit")
        limit = int(raw_limit) if raw_limit is not None else 50
        limit = max(1, min(500, limit))
        extract_bytes_ceiling = params.get("max_content_bytes")
        urls = params.get("urls")
        mode = str(params.get("mode") or "auto")
        outline = bool(params.get("outline", False))
        filter_term = str(params.get("filter", "") or "")
        content_boundaries = bool(params.get("content_boundaries", False))
        html_only = params.get("html_only", False)
        if not isinstance(html_only, bool) or (
            html_only and (urls is None or mode != "static")
        ):
            raise BrowserError(
                InputFailure.OPERATION, "html_only requires a Boolean and static URLs"
            )
        if urls is not None:
            from .extract import extract_documents

            if not isinstance(urls, list):
                raise BrowserError(InputFailure.OPERATION, "urls must be a list")
            return extract_documents(
                self,
                urls,
                mode,
                extract_bytes_ceiling,
                outline=outline,
                filter_term=filter_term,
                content_boundaries=content_boundaries,
                html_only=html_only,
            )

        if self.last_snapshot is None:
            self.handle_tool_call("nbrowser_page_snapshot", {})
        view = self.last_snapshot.view if self.last_snapshot else None
        if view is None:
            raise BrowserError(FailureCode.NO_ACTIVE_SESSION, "no active page")
        if what:
            matches = [b for b in view.text_blocks if what.lower() in b.lower()][:limit]
            if not matches and view.visible_text:
                matches = [view.visible_text[:200]]
        else:
            matches = view.text_blocks[:limit]
        if content_boundaries:
            matches = [wrap_content_boundaries(m, view.url) for m in matches]
        extract_payload: dict[str, Any] = {
            "matches": matches,
            "count": len(matches),
            "what": what,
            "taint": "page_derived",
            "rung": "un_witnessed_local",
        }
        if extract_bytes_ceiling is not None:
            max_bytes = max(1024, min(4 * 1024 * 1024, int(extract_bytes_ceiling)))
            full_text = "\n\n".join(matches)
            apply_text_artifacts(
                extract_payload,
                [TextArtifactCandidate(format="extract", body=full_text)],
                max_bytes,
                stage=lambda body: self._stage_artifact(body),
            )
        return extract_payload

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """One `tools/call` as its `CallToolResult`: the payload as JSON text, or
        a `BrowserError` as an `isError` failure envelope. Any other exception
        escapes to the SDK, which answers it as a JSON-RPC error."""
        try:
            payload = self.handle_tool_call(name, args)
        except BrowserError as e:
            envelope = failure_envelope(e)
            if (
                name == "nbrowser_content_show"
                and e.code == FailureCode.CONTENT_UNAVAILABLE
            ) or (name == "nbrowser_page_interact" and e.code == InputFailure.SELECTOR):
                # An interact refusal names its cause (the overlay that covers
                # the target, the options a select offers, a stale ref); the
                # envelope already marks it page-derived.
                envelope["message"] = e.message
            return {
                "isError": True,
                "content": [
                    {"type": "text", "text": json.dumps(envelope, ensure_ascii=False)}
                ],
            }
        return {
            "content": [
                {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}
            ]
        }
