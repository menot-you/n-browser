"""Static projection of raw HTML into the markdown shape MARKDOWN_WALKER
(extract.py) produces inside the browser — headings, then blocks, then links —
so `mode: auto` compares like with like. Pure: strings in, strings out. The
consumer redacts (extract._redact_multiline) exactly as it redacts the live
walk; origin is the frontier's decision, this module only gates the scheme."""

from __future__ import annotations

import gzip
import io
import re
import zlib
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .egress_guard import is_public_safe
from .errors import BrowserError, FailureCode

MAX_STATIC_BYTES = 1024 * 1024
SKIPPED = frozenset({"script", "style", "noscript", "template"})
HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
BLOCKS = frozenset({"p", "li", "pre", "blockquote"})
_WS = re.compile(r"\s+")


def clean(text: str) -> str:
    return _WS.sub(" ", text).strip()


def decode_body(data: bytes, content_encoding: str | None) -> str:
    """Decode at most 1 MiB. A broken gzip is empty; expansion past the
    decoded-output ceiling is a typed refusal, never an empty fallback."""
    if content_encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                data = stream.read(MAX_STATIC_BYTES + 1)
        except OSError, EOFError, zlib.error:
            return ""
    if len(data) > MAX_STATIC_BYTES:
        raise BrowserError(
            FailureCode.CONTENT_BUDGET_EXCEEDED, "decoded HTML exceeds 1 MiB bound"
        )
    return data.decode("utf-8", errors="replace")


@dataclass
class StaticPage:
    markdown: str
    links: list[str]
    empty: bool
    ordered_markdown: str = ""


class _Projection(HTMLParser):
    """Headings and blocks collect their whole subtree text, nested ones each
    (querySelectorAll answers both the <li> and the <p> inside it); ordering
    is by START position, which is document order. Skipped subtrees never
    contribute a byte."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self._skip = 0
        self._order = 0
        self._open: list[tuple[str, int, list[str], int]] = []
        self._list_depth = 0
        self._anchor: list[str] | None = None
        self._anchor_href = ""
        self._based = False
        self.headings: list[tuple[int, str]] = []
        self.blocks: list[tuple[int, str]] = []
        self.link_lines: list[str] = []
        # The ordered projection, as the browser walker builds it: each text
        # run belongs to its nearest block (or, outside any block, to its
        # link); consecutive runs of one owner form a segment, and a link line
        # follows the segment that holds its text.
        self.segments: list[tuple[object, str, list[str], list[str]]] = []
        self._anchor_key = 0
        self.links: list[str] = []

    def _absolute(self, href: str) -> str | None:
        try:
            target = urljoin(self.base_url, href.strip())
        except ValueError:
            return None
        if target.lower().startswith(("http://", "https://")):
            return target
        return None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in SKIPPED:
            self._skip += 1
            return
        if self._skip:
            return
        if tag == "base" and not self._based:
            href = dict(attrs).get("href")
            if href:
                try:
                    self.base_url = urljoin(self.base_url, href)
                except ValueError:
                    return
                self._based = True
            return
        if tag in HEADINGS or tag in BLOCKS or tag in ("ul", "ol"):
            for i in range(len(self._open) - 1, -1, -1):
                if self._open[i][0] == "p":
                    self._flush_from(i)
                    break
        if tag == "li":
            for i in range(len(self._open) - 1, -1, -1):
                if self._open[i][0] == "li" and self._open[i][3] == self._list_depth:
                    self._flush_from(i)
                    break
        if tag in ("ul", "ol"):
            self._list_depth += 1
        if tag in HEADINGS or tag in BLOCKS:
            self._order += 1
            self._open.append((tag, self._order, [], self._list_depth))
            return
        if tag == "a":
            href = dict(attrs).get("href") or ""
            self._anchor_key += 1
            self._anchor = []
            self._anchor_href = href
            target = self._absolute(href) if href else None
            if target is not None and target not in self.links:
                self.links.append(target)

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIPPED:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag in HEADINGS or tag in BLOCKS:
            for i in range(len(self._open) - 1, -1, -1):
                if self._open[i][0] != tag:
                    continue
                self._flush_from(i)
                break
            return
        if tag in ("ul", "ol"):
            for i in range(len(self._open) - 1, -1, -1):
                if self._open[i][0] == "li" and self._open[i][3] == self._list_depth:
                    self._flush_from(i)
                    break
            self._list_depth = max(0, self._list_depth - 1)
        if tag == "a" and self._anchor is not None:
            text = clean("".join(self._anchor))
            target = self._absolute(self._anchor_href) if self._anchor_href else None
            if text and target is not None:
                line = f"[{text}]({target})"
                self.link_lines.append(line)
                if self.segments:
                    self.segments[-1][3].append(line)
            self._anchor = None

    def _flush_from(self, start: int) -> None:
        for tag, order, parts, _ in self._open[start:]:
            text = clean("".join(parts))
            if text and tag in HEADINGS:
                self.headings.append((order, "#" * int(tag[1]) + " " + text))
            elif text:
                self.blocks.append((order, text))
        del self._open[start:]

    def close(self) -> None:
        super().close()
        self._flush_from(0)

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        for _, _, parts, _ in self._open:
            parts.append(data)
        if self._anchor is not None:
            self._anchor.append(data)
        if self._open:
            key: object = self._open[-1][1]
            tag = self._open[-1][0]
        elif self._anchor is not None:
            key, tag = ("a", self._anchor_key), "a"
        else:
            return
        if not self.segments or self.segments[-1][0] != key:
            self.segments.append((key, tag, [], []))
        self.segments[-1][2].append(data)


def project(html: str, base_url: str) -> StaticPage:
    parser = _Projection(base_url)
    parser.feed(html)
    parser.close()
    headings = [t for _, t in sorted(parser.headings)]
    blocks = [t for _, t in sorted(parser.blocks)]
    ordered: list[str] = []
    for _, tag, texts, links in parser.segments:
        text = clean("".join(texts))
        if text and tag in HEADINGS:
            ordered.append("#" * int(tag[1]) + " " + text)
        elif text and tag != "a":
            ordered.append(text)
        ordered.extend(links)
    markdown = "\n\n".join(headings + blocks + parser.link_lines)
    ordered_markdown = "\n\n".join(ordered)
    return StaticPage(
        markdown=markdown,
        links=parser.links,
        empty=not headings and not blocks,
        ordered_markdown=ordered_markdown,
    )


_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")


def extract_markdown_outline(md: str) -> str:
    """Return only markdown heading lines (# .. ######)."""
    lines: list[str] = []
    for raw in md.splitlines():
        stripped = raw.strip()
        if _HEADING_RE.match(stripped):
            lines.append(stripped)
    return "\n".join(lines)


def filter_markdown_sections(md: str, term: str) -> str:
    """Return markdown sections whose heading contains `term` (case-insensitive)
    up to the next heading of equal or higher level."""
    needle = term.strip().lower()
    if not needle:
        return md
    sections: list[str] = []
    current_lines: list[str] = []
    capturing_level: int | None = None

    for line in md.splitlines():
        m = _HEADING_RE.match(line.strip())
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            if capturing_level is not None and level <= capturing_level:
                sections.append("\n".join(current_lines).strip())
                current_lines = []
                capturing_level = None
            if capturing_level is None and needle in title.lower():
                capturing_level = level
                current_lines = [line]
                continue
        if capturing_level is not None:
            current_lines.append(line)

    if capturing_level is not None and current_lines:
        sections.append("\n".join(current_lines).strip())
    return "\n\n".join(s for s in sections if s)


def _origin_key(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    return (scheme, host, port)


def ancestor_llms_urls(url: str) -> list[str]:
    """Candidate /llms.txt URLs from `url`'s directory up to `/` on the same origin."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return []
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    segments = [s for s in path.split("/") if s]
    out: list[str] = []
    for depth in range(len(segments), -1, -1):
        prefix = "/" + "/".join(segments[:depth])
        if not prefix.endswith("/"):
            prefix += "/"
        candidate = f"{origin}{prefix}llms.txt"
        if candidate not in out:
            out.append(candidate)
    return out


_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def parse_llms_txt_links(body: str, base_url: str) -> list[tuple[str, str]]:
    """Extract (title, absolute_url) pairs from /llms.txt restricted to the
    same origin as `base_url` and approved by `is_public_safe`."""
    base_origin = _origin_key(base_url)
    if base_origin is None:
        return []
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _MD_LINK_RE.finditer(body):
        title = clean(match.group(1))
        raw_target = match.group(2).strip()
        if not title or not raw_target:
            continue
        try:
            resolved = urljoin(base_url, raw_target).split("#", 1)[0]
        except ValueError:
            continue
        if _origin_key(resolved) != base_origin:
            continue
        if not is_public_safe(resolved):
            continue
        if resolved not in seen:
            seen.add(resolved)
            links.append((title, resolved))
    return links
