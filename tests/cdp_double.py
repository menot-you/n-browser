"""A protocol double for BrowserSession — the §31 answer to a host without
Chromium: the tests observe the same session behavior by injection, and the
absence branch is asserted as a typed refusal instead of a skip.

What the double CANNOT prove (a real CDP answering on the other end of the
pipe) is deferred as out-of-scope for this fixture and not silently skipped.
"""

import threading
from collections.abc import Callable
from typing import Any

from nbrowser.semantic_walker import SEMANTIC_WALKER
from nbrowser.session import CdpPipeClient

# One 1x1 PNG, base64: what Page.captureScreenshot answers. Fixed bytes, so
# the capture digest is the same on every run and a test can pin it.
PNG_1X1_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="


class FakePage:
    """One fixture page: URL, visible text, clickable selectors."""

    def __init__(self, url: str, title: str, text: str) -> None:
        self.url = url
        self.title = title
        self.text = text
        self.clicks: dict[str, int] = {}


class CdpDouble:
    """Speaks the exact CDP surface BrowserSession uses, over in-memory pages.

    `sent` records every frame (method, params, sessionId) so a test asserts
    TRAFFIC — which methods, on which session, in which order — never a key
    in a payload. `emit` pushes an id-less frame into the session's hook the
    way the reader thread would. What this double CANNOT prove: that a real
    engine delivers those frames, accepts `origin: "*"`, or renders pixels.
    """

    def __init__(
        self,
        pages: list[FakePage],
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.pages = pages
        self.targets = {f"t{i}": p for i, p in enumerate(pages)}
        self.launched = True
        self._next_id = 1
        self.on_event = on_event
        self.sent: list[tuple[str, dict[str, Any], str | None]] = []
        self.contexts: list[str] = []
        self.target_context: dict[str, str] = {}
        self._next_context = 1
        self._current_session: str | None = None
        self.cond = threading.Condition()
        self.events: list[dict[str, Any]] = []

    # -- CdpPipeClient surface -------------------------------------------------
    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        params = params or {}
        self.sent.append((method, dict(params), session_id))
        if method == "Target.getTargets":
            return {
                "targetInfos": [
                    {"targetId": tid, "type": "page", "url": p.url}
                    for tid, p in self.targets.items()
                ]
            }
        if method == "Target.createTarget":
            page = FakePage(params.get("url", "about:blank"), "", "")
            tid = f"t{self._next_id}"
            self._next_id += 1
            ctx_id = params.get("browserContextId")
            if ctx_id is not None:
                if str(ctx_id) not in self.contexts:
                    raise AssertionError(
                        f"CdpDouble: unknown browserContextId {ctx_id}"
                    )
                self.target_context[tid] = str(ctx_id)
            self.targets[tid] = page
            return {"targetId": tid}
        if method == "Target.closeTarget":
            self.targets.pop(params.get("targetId", ""), None)
            return {}
        if method == "Target.activateTarget":
            return {}
        if method == "Target.attachToTarget":
            return {"sessionId": f"s-{params.get('targetId', 't0')}"}
        if method == "Target.createBrowserContext":
            ctx = f"bc{self._next_context}"
            self._next_context += 1
            self.contexts.append(ctx)
            return {"browserContextId": ctx}
        if method == "Target.disposeBrowserContext":
            ctx = str(params.get("browserContextId", ""))
            if ctx in self.contexts:
                self.contexts.remove(ctx)
            for tid in [t for t, c in self.target_context.items() if c == ctx]:
                self.targets.pop(tid, None)
                del self.target_context[tid]
                # Chromium detaches each of a disposed context's flattened
                # sessions; the server drops that session's rings on the frame.
                if self.on_event is not None:
                    sid = f"s-{tid}"
                    self.on_event(
                        {
                            "method": "Target.detachedFromTarget",
                            "sessionId": sid,
                            "params": {"sessionId": sid, "targetId": tid},
                        }
                    )
            return {}
        if method == "Page.enable":
            return {}
        if method == "Page.navigate":
            page = self._page_for_session(session_id)
            if page is not None:
                page.url = str(params.get("url", page.url))
            result = {"frameId": f"f-{session_id}", "loaderId": f"l-{len(self.sent)}"}
            self.events.append(
                {
                    "method": "Page.lifecycleEvent",
                    "sessionId": session_id,
                    "params": {"name": "load", **result},
                }
            )
            return result
        if method == "Page.captureScreenshot":
            return {"data": PNG_1X1_BASE64}
        if method == "Runtime.enable":
            return {}
        if method == "Runtime.evaluate":
            self._current_session = session_id
            return {"result": {"value": self._evaluate(params.get("expression", ""))}}
        if method == "Input.dispatchMouseEvent":
            return {}
        if method == "Input.insertText":
            return {}
        if method == "Input.dispatchKeyEvent":
            return {}
        if method == "Page.addScriptToEvaluateOnNewDocument":
            return {"identifier": "1"}
        if method == "Storage.clearDataForOrigin":
            return {}
        if method == "Network.clearBrowserCookies":
            return {}
        raise AssertionError(f"CdpDouble: unhandled method {method}")

    def wait_event(
        self,
        method: str,
        session_id: str | None = None,
        timeout: float = 15.0,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return CdpPipeClient.wait_event(
            self, method, session_id, timeout, params=params
        )

    def emit(self, event: dict[str, Any]) -> None:
        """Push one id-less frame into the session's hook, as the reader would."""
        if self.on_event is None:
            raise AssertionError("CdpDouble: emit without an on_event hook")
        self.on_event(event)

    def close(self) -> None:
        self.launched = False

    # -- fixture behavior ------------------------------------------------------
    def _page_for_session(self, session_id: str | None) -> FakePage | None:
        if session_id is not None and session_id.startswith("s-"):
            tid = session_id[2:]
            if tid in self.targets:
                return self.targets[tid]
        first = next(iter(self.targets), None)
        return self.targets.get(first) if first else None

    def _page_for_expression(self, expression: str) -> FakePage | None:
        # The target of the session the evaluate was sent on; tabs[0] when none.
        return self._page_for_session(self._current_session)

    def _evaluate(self, expression: str) -> Any:
        page = self._page_for_expression(expression)
        if page is None:
            return None
        if expression.startswith(f"({SEMANTIC_WALKER[:24]}"):
            el_kind = "other"
            form_idx = 0 if "<form" in page.text.lower() else None
            if "<button" in page.text.lower():
                el_kind = "button"
            elif "<select" in page.text.lower():
                el_kind = "select"
            return {
                "url": page.url,
                "title": page.title,
                "page_hint": "",
                "elements": [
                    {
                        "id": 0,
                        "selector": "#x",
                        "kind": el_kind,
                        "label": page.text[:40],
                        "form_index": form_idx,
                    }
                ],
                "forms": [{"index": 0, "action": page.url}]
                if form_idx is not None
                else [],
                "visible_text": page.text,
                "text_blocks": [page.text],
                "state": "ready",
            }
        if "window.innerWidth" in expression:
            return {"w": 800, "h": 600, "dpr": 1, "href": page.url}
        if (
            "Symbol.for('nbrowser.docGen')" in expression
            and "location.href" not in expression
            and "querySelector" not in expression
        ):
            return "dg-double"
        if "location.href" in expression and "querySelector" not in expression:
            return page.url
        if "querySelector" in expression and "mouseenter" in expression:
            import json as _json
            from urllib.parse import urlsplit

            from nbrowser.mcp_server import origin_of

            p_orig = origin_of(urlsplit(page.url))
            if "window.location.origin !==" in expression:
                exp_orig = (
                    expression.split("window.location.origin !==")[1]
                    .split(")")[0]
                    .strip()
                    .strip('"')
                )
                if exp_orig and exp_orig != p_orig:
                    return False
            parts = expression.split("const sel = ")
            if len(parts) > 1:
                marker = parts[1].split(";")[0].strip()
            else:
                marker = expression.split("querySelector(")[1].split(")")[0]
            selector = _json.loads(marker) if marker.startswith('"') else marker
            page.clicks[selector] = page.clicks.get(selector, 0) + 1
            return True
        if (
            "querySelector" in expression
            and "focus" in expression
            and "click" not in expression
        ):
            import json as _json

            parts = expression.split("const sel = ")
            if len(parts) > 1:
                marker = parts[1].split(";")[0].strip()
            else:
                marker = expression.split("querySelector(")[1].split(")")[0]
            selector = _json.loads(marker) if marker.startswith('"') else marker
            page.clicks[selector] = page.clicks.get(selector, 0) + 1
            return True
        if "querySelector" in expression and (
            "click" in expression or "isLiveSubmit" in expression
        ):
            import json as _json

            parts = expression.split("const sel = ")
            if len(parts) > 1:
                marker = parts[1].split(";")[0].strip()
            else:
                marker = expression.split("querySelector(")[1].split(")")[0]
            selector = _json.loads(marker) if marker.startswith('"') else marker
            page.clicks[selector] = page.clicks.get(selector, 0) + 1
            return {"ok": True, "x": 10.0, "y": 10.0, "targetUrl": None}
        return None
