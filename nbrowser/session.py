import base64
import codecs
import json
import os
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from .auth import origin_of
from .cgroup_custody import CGROUP_ROOT, CgroupCustody, unified_membership
from .egress_guard import (
    bare_host,
    is_cross_origin_internal,
    is_loopback_host,
    is_public_safe,
    resolve_admitted,
)
from .egress_proxy import EgressProxy
from .errors import BrowserError, ClosedFailure, FailureCode
from .frontier import same_origin
from .private_root import get_chromium_executable
from .process_custody import BrowserCustody
from .profile import BrowserProfile

DEFAULT_IDLE_REAP = 300
AUTO_ATTACH = {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}
TabId = str
EventHook = Callable[[dict[str, Any]], None]
# Frames the reader thread hands to `on_event` and NEVER appends to `events`:
# after Runtime.enable they arrive for the life of the tab, and `events` is
# drained only by wait_event, one method at a time, by linear scan.
# ponytail: Runtime.enable also pushes Runtime.executionContextCreated/Destroyed/
# executionContextsCleared (one per world, every navigation); they still land in
# `events` and grow it. Upgrade point: add them here, or index wait_event by method.
CONSUMED_EVENTS = frozenset(
    {
        "Runtime.consoleAPICalled",
        "Runtime.exceptionThrown",
        # The server drops the detached session's rings here; no caller waits
        # for this frame through wait_event.
        "Target.detachedFromTarget",
    }
)

CONTAINMENT_JS = r"""(function _installContainment(_boundOrigin, _boundBase) {
  const _global = typeof globalThis !== 'undefined' ? globalThis : self;
  // Once per global: a second run would wrap the wrappers, and a nested
  // Worker bootstrap would then meet its own blob: refusal.
  const _mark = Symbol.for('nbrowser.contained');
  if (_global[_mark]) return;
  Object.defineProperty(_global, _mark, { value: true });
  const _origImportScripts = typeof _global.importScripts === 'function'
    ? _global.importScripts.bind(_global)
    : null;
  const _effectiveOrigin = _boundOrigin || (_global.location ? _global.location.origin : '');
  const _scriptBase = _boundBase || (_global.location ? _global.location.href : '');
  const _securityError = (msg) => {
    try { return new DOMException(msg, 'SecurityError'); }
    catch (_) { const e = new Error(msg); e.name = 'SecurityError'; return e; }
  };
  const _mappedIpv4 = (h) => {
    if (!h.startsWith('::ffff:')) return null;
    const rest = h.slice(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) return rest;
    if (/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/i.test(rest)) {
      const [hi, lo] = rest.split(':').map((x) => parseInt(x, 16));
      return ((hi >> 8) & 255) + '.' + (hi & 255) + '.' + ((lo >> 8) & 255) + '.' + (lo & 255);
    }
    return null;
  };
  const _isLoopback = (h) => {
    let low = String(h || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const mapped = _mappedIpv4(low);
    if (mapped) low = mapped;
    return low === 'localhost' || low === '127.0.0.1' || low === '0.0.0.0' || low === '::1' || low === '::' || low === '0:0:0:0:0:0:0:1' || low === '0:0:0:0:0:0:0:0' || low.startsWith('127.');
  };
  const _isPrivate = (h) => {
    let low = String(h || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const mapped = _mappedIpv4(low);
    if (mapped) low = mapped;
    if (low === '169.254.169.254' || low === 'metadata.google.internal' || low === 'metadata.goog') return true;
    if (low.endsWith('.internal') || low.endsWith('.nip.io') || low.endsWith('.sslip.io') || low.endsWith('.localtest.me') || low.endsWith('.lvh.me') || low.endsWith('.xip.io')) return true;
    if (/^10\./.test(low) || /^192\.168\./.test(low) || /^169\.254\./.test(low)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(low)) return true;
    if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(low)) return true;
    if (/^f[cd][0-9a-f]{0,2}:/i.test(low) || /^fe[89ab][0-9a-f]:/i.test(low)) return true;
    return false;
  };
  const _checkUrl = (raw, allowWs = false, allowWorkerBlob = false) => {
    const s = String(raw || '');
    if (allowWorkerBlob && (s.startsWith('blob:') || s.startsWith('data:'))) return s;
    let u;
    try { u = new URL(s, _scriptBase || undefined); }
    catch (_) { throw _securityError('Blocked invalid URL'); }
    const scheme = u.protocol.toLowerCase();
    const okSchemes = allowWs ? ['http:', 'https:', 'ws:', 'wss:'] : ['http:', 'https:'];
    if (!okSchemes.includes(scheme)) throw _securityError('Blocked scheme: ' + scheme);
    const host = u.hostname || '';
    if (!host || _isPrivate(host)) throw _securityError('Blocked private host: ' + host);
    if (_isLoopback(host) && _effectiveOrigin && _effectiveOrigin !== 'null') {
      try {
        const origU = new URL(_effectiveOrigin);
        if (!_isLoopback(origU.hostname) || origU.origin !== u.origin) {
          throw _securityError('Blocked cross-origin loopback access');
        }
      } catch (e) {
        if (e && e.name === 'SecurityError') throw e;
      }
    }
    return u.href;
  };
  const _blockPeer = (name) => {
    if (typeof _global[name] !== 'function') return;
    const Blocked = function() {
      throw _securityError('RTCPeerConnection blocked by nBrowser containment');
    };
    try {
      Object.defineProperty(_global, name, { value: Blocked, writable: false, configurable: false });
    } catch (_) { _global[name] = Blocked; }
  };
  _blockPeer('RTCPeerConnection');
  _blockPeer('webkitRTCPeerConnection');
  if (typeof _global.fetch === 'function') {
    const _origFetch = _global.fetch.bind(_global);
    _global.fetch = function(input, init) {
      const raw = (typeof Request !== 'undefined' && input instanceof Request) ? input.url : String(input);
      try {
        _checkUrl(raw, false, false);
      } catch (err) {
        return Promise.reject(err);
      }
      return _origFetch(input, init);
    };
  }
  if (typeof _global.XMLHttpRequest === 'function' && _global.XMLHttpRequest.prototype) {
    const _origOpen = _global.XMLHttpRequest.prototype.open;
    _global.XMLHttpRequest.prototype.open = function(method, url) {
      _checkUrl(url, false, false);
      return _origOpen.apply(this, arguments);
    };
  }
  if (_origImportScripts) {
    _global.importScripts = function(...urls) {
      const checked = urls.map((u) => _checkUrl(u, false, false));
      return _origImportScripts(...checked);
    };
  }
  if (typeof _global.WebSocket === 'function') {
    const _OrigWS = _global.WebSocket;
    const WrappedWS = function(url, protocols) {
      const checked = _checkUrl(url, true, false);
      return protocols !== undefined ? new _OrigWS(checked, protocols) : new _OrigWS(checked);
    };
    Object.assign(WrappedWS, _OrigWS);
    WrappedWS.prototype = _OrigWS.prototype;
    try {
      Object.defineProperty(WrappedWS.prototype, 'constructor', { value: WrappedWS, writable: false, configurable: false });
    } catch (_) { WrappedWS.prototype.constructor = WrappedWS; }
    _global.WebSocket = WrappedWS;
  }
  if (typeof _global.EventSource === 'function') {
    const _OrigES = _global.EventSource;
    const WrappedES = function(url, opts) {
      const checked = _checkUrl(url, false, false);
      return new _OrigES(checked, opts);
    };
    Object.assign(WrappedES, _OrigES);
    WrappedES.prototype = _OrigES.prototype;
    try {
      Object.defineProperty(WrappedES.prototype, 'constructor', { value: WrappedES, writable: false, configurable: false });
    } catch (_) { WrappedES.prototype.constructor = WrappedES; }
    _global.EventSource = WrappedES;
  }
  if (_global.navigator && typeof _global.navigator.sendBeacon === 'function') {
    const _origBeacon = _global.navigator.sendBeacon.bind(_global.navigator);
    _global.navigator.sendBeacon = function(url, data) {
      try { _checkUrl(url, false, false); } catch (_) { return false; }
      return _origBeacon(url, data);
    };
  }
  if (typeof _global.addEventListener === 'function' && _global.document) {
    _global.addEventListener('submit', (e) => {
      try {
        const f = e.target;
        const sub = e.submitter;
        const act = (sub && sub.getAttribute && sub.getAttribute('formaction'))
          || (sub && sub.formAction)
          || (f && f.getAttribute && f.getAttribute('action'))
          || (f && f.action)
          || (_global.location ? _global.location.href : '');
        _checkUrl(act, false, false);
      } catch (err) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    }, true);
  }
  const _selfFn = _installContainment.toString();
  const _wrapWorker = (OrigWorker) => {
    if (typeof OrigWorker !== 'function') return OrigWorker;
    const Wrapped = function(scriptURL, options) {
      if (options && options.type === 'module') {
        throw _securityError('Module workers are refused under containment');
      }
      const checked = _checkUrl(scriptURL, false, true);
      const workerBase = (checked.startsWith('blob:') || checked.startsWith('data:')) ? _scriptBase : checked;
      const bootstrap = '(function(_boundOrigin, _boundBase) {'
        + 'const _origImport = self.importScripts.bind(self);'
        + '(' + _selfFn + ')(_boundOrigin, _boundBase);'
        + '_origImport(' + JSON.stringify(checked) + ');'
        + '})(' + JSON.stringify(_effectiveOrigin) + ',' + JSON.stringify(workerBase) + ');';
      const blob = new Blob([bootstrap], { type: 'application/javascript' });
      const blobUrl = URL.createObjectURL(blob);
      return new OrigWorker(blobUrl, options);
    };
    Object.assign(Wrapped, OrigWorker);
    Wrapped.prototype = OrigWorker.prototype;
    try {
      Object.defineProperty(Wrapped.prototype, 'constructor', { value: Wrapped, writable: false, configurable: false });
    } catch (_) { Wrapped.prototype.constructor = Wrapped; }
    return Wrapped;
  };
  if (typeof _global.Worker === 'function') _global.Worker = _wrapWorker(_global.Worker);
  if (typeof _global.SharedWorker === 'function') _global.SharedWorker = _wrapWorker(_global.SharedWorker);
})("", "")"""


class BrowserLaunchConfig:
    def __init__(self, headless: bool = True) -> None:
        self.headless = headless


# WHATWG form charset labels whose browser tables match more than one Python
# codec; other labels resolve through codecs.lookup.
FORM_CHARSET_CODECS: dict[str, tuple[str, ...]] = {
    "utf-8": ("utf-8",),
    "windows-1252": ("cp1252", "latin-1"),
    "iso-8859-1": ("cp1252", "latin-1"),
    "us-ascii": ("cp1252", "latin-1"),
    "shift_jis": ("shift_jis", "cp932"),
    "euc-jp": ("euc_jp", "euc_jis_2004"),
    "gbk": ("gbk", "gb18030"),
    "gb2312": ("gbk", "gb18030"),
    "big5": ("big5", "big5hkscs"),
    "euc-kr": ("euc_kr", "cp949"),
}


class CdpPipeClient:
    def __init__(
        self, fd_in: int, fd_out: int, on_event: EventHook | None = None
    ) -> None:
        self.fd_in = fd_in
        self.fd_out = fd_out
        # Set BEFORE the reader thread starts: the first frame can arrive
        # before __init__ returns, and a hook set afterwards would miss it.
        self.on_event = on_event
        self.msg_id = 1
        self.lock = threading.Lock()

        self.responses: dict[int, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.cond = threading.Condition(self.lock)
        # Ids of the interceptor's own replies. The engine acks every one of
        # them and nobody ever awaits those acks, so they are discarded on
        # arrival — kept, they would be one dict entry per sub-resource for
        # the life of the tab. Written and read by the reader thread alone.
        self.forgotten: set[int] = set()
        self.dialogs_closed: list[dict[str, Any]] = []
        self._contained: set[str | None] = set()
        # Frame identifiers survive a move between target sessions.
        self._frame_origins: dict[str, str] = {}
        self._document_requests: dict[str, tuple[str, str]] = {}
        self._main_frames: dict[str | None, str] = {}
        self._pending_nav_origin: dict[str | None, str] = {}
        self._auto_attach = False
        self._target_sessions: dict[str, str] = {}
        self._target_pending: set[str] = set()
        self._target_failed: set[str] = set()
        self._target_replies: dict[
            int, tuple[str, list[tuple[str, dict[str, Any]]]]
        ] = {}
        # Per session: login origins whose submission has not landed yet. Until
        # it does, a navigation to any other origin is refused, whatever its bytes.
        self._submit_locks: dict[str | None, set[str]] = {}
        # Per session: (login origin, request key) of the request that landed.
        self._landings: dict[str | None, tuple[str, str]] = {}
        # Per session: (origin, encodings) of each secret auth_login put on a page.
        self._armed_secrets: dict[str | None, list[tuple[str, tuple[bytes, ...]]]] = {}
        # Set once the pipe ends; after it no answer can arrive.
        self.ended = False

        self.reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.reader_thread.start()

    def _read_loop(self) -> None:
        buf = bytearray()
        try:
            while True:
                chunk = os.read(self.fd_in, 4096)
                if not chunk:
                    break
                buf.extend(chunk)
                while b"\0" in buf:
                    idx = buf.index(b"\0")
                    msg = buf[:idx]
                    del buf[: idx + 1]

                    if not msg:
                        continue

                    try:
                        resp = json.loads(msg.decode("utf-8"))
                    except ValueError:
                        continue
                    if resp.get("method") == "Target.attachedToTarget":
                        self._target_attached(resp)
                        continue
                    if resp.get("method") == "Page.frameAttached":
                        params = resp["params"]
                        with self.lock:
                            self._frame_origins.setdefault(
                                params["frameId"],
                                self._frame_origins.get(
                                    params["parentFrameId"], "about:blank"
                                ),
                            )
                        continue
                    if resp.get("method") == "Page.frameNavigated":
                        frame, session_id = (
                            resp["params"]["frame"],
                            resp.get("sessionId"),
                        )
                        with self.lock:
                            origin = str(
                                frame.get("securityOrigin")
                                or frame.get("url")
                                or "about:blank"
                            )
                            if origin not in ("about:blank", "about:srcdoc"):
                                self._frame_origins[frame["id"]] = origin
                            self._document_requests.pop(frame["id"], None)
                            if not frame.get("parentId"):
                                self._main_frames[session_id] = frame["id"]
                    if resp.get("method") == "Page.frameDetached":
                        params = resp["params"]
                        if params.get("reason") == "remove":
                            with self.lock:
                                self._frame_origins.pop(params["frameId"], None)
                                self._document_requests.pop(params["frameId"], None)
                    if resp.get("id") in self._target_replies:
                        session_id, steps = self._target_replies.pop(resp["id"])
                        if "error" in resp:
                            with self.cond:
                                self._target_failed.add(session_id)
                                self._target_pending.discard(session_id)
                                self.cond.notify_all()
                            self.forgotten.add(
                                self._post(
                                    "Target.closeTarget",
                                    {"targetId": self._main_frames[session_id]},
                                    None,
                                )
                            )
                        else:
                            self._target_next(session_id, steps)
                        continue
                    if resp.get("method") == "Fetch.requestPaused":
                        # Answered HERE and not by a waiting caller: the engine
                        # holds the request open until someone replies, and the
                        # only thread reading this pipe is this one.
                        self._resolve_paused(resp)
                        continue
                    if resp.get("method") == "Page.javascriptDialogOpening":
                        # Answered HERE so a synchronous alert/confirm/prompt
                        # never blocks Runtime.evaluate or Input.dispatchMouseEvent.
                        self._resolve_dialog(resp)
                        continue
                    if resp.get("method") in CONSUMED_EVENTS:
                        # Outside the lock, consumed and never appended. The
                        # hook MUST NOT raise: this loop catches OSError only,
                        # and a dead reader turns every later send into a
                        # 30 s `CDP timeout` naming nothing.
                        if self.on_event is not None:
                            self.on_event(resp)
                        continue
                    with self.lock:
                        if "id" in resp:
                            if resp["id"] in self.forgotten:
                                self.forgotten.discard(resp["id"])
                            else:
                                self.responses[resp["id"]] = resp
                        else:
                            self.events.append(resp)
                        self.cond.notify_all()
        except OSError:
            pass
        try:
            os.close(self.fd_in)
        except OSError:
            pass
        # EOF: the engine is gone. Waiters are woken to refuse now instead of
        # waiting out a timeout nothing can meet.
        with self.lock:
            self.ended = True
            self.cond.notify_all()

    def _target_attached(self, event: dict[str, Any]) -> None:
        params = event["params"]
        if not params.get("waitingForDebugger"):
            return
        info = params["targetInfo"]
        session_id, target_id = str(params["sessionId"]), str(info["targetId"])
        with self.lock:
            origin = self._frame_origins.get(
                target_id,
                self._frame_origins.get(
                    str(info.get("openerFrameId", "")), "about:blank"
                ),
            )
            target_url = str(info.get("url", ""))
            if is_public_safe(target_url) and not is_loopback_host(
                bare_host(target_url) or ""
            ):
                origin = target_url
            self._target_sessions[target_id] = session_id
            self._target_pending.add(session_id)
            self._main_frames[session_id] = target_id
            self._frame_origins[target_id] = origin
        steps: list[tuple[str, dict[str, Any]]] = [
            ("Fetch.enable", {"patterns": [{"urlPattern": "*"}]}),
            ("Target.setAutoAttach", AUTO_ATTACH),
        ]
        if info.get("type") in ("page", "iframe"):
            steps.extend(
                [
                    ("Page.enable", {}),
                    (
                        "Page.addScriptToEvaluateOnNewDocument",
                        {"source": CONTAINMENT_JS},
                    ),
                ]
            )
        steps.append(("Runtime.runIfWaitingForDebugger", {}))
        self._target_next(session_id, steps)

    def _target_next(
        self, session_id: str, steps: list[tuple[str, dict[str, Any]]]
    ) -> None:
        # The reader must receive each gate acknowledgement before it resumes the target.
        if steps:
            method, params = steps.pop(0)
            self._target_replies[self._post(method, params, session_id)] = (
                session_id,
                steps,
            )
        else:
            with self.cond:
                self._contained.add(session_id)
                self._target_pending.discard(session_id)
                self.cond.notify_all()

    def _post(
        self, method: str, params: dict[str, Any] | None, session_id: str | None
    ) -> int:
        """Write one frame and return its id, without waiting for the answer —
        the reader thread replies to paused requests and can never wait on
        itself. The write is under the lock because two threads now share this
        pipe and a frame past PIPE_BUF is not atomic.
        ponytail: one lock for both directions; a full pipe stalls the reader."""
        with self.lock:
            req_id = self.msg_id
            self.msg_id += 1
            req: dict[str, Any] = {
                "id": req_id,
                "method": method,
                "params": params or {},
            }
            if session_id is not None:
                req["sessionId"] = session_id
            os.write(self.fd_out, json.dumps(req).encode("utf-8") + b"\0")
        return req_id

    def _resolve_dialog(self, event: dict[str, Any]) -> None:
        session_id = event.get("sessionId")
        self.dialogs_closed.append(dict(event.get("params", {})))
        self.forgotten.add(
            self._post("Page.handleJavaScriptDialog", {"accept": False}, session_id)
        )

    def _record_navigation_reply(
        self, session_id: str | None, frame_id: str | None, requested_url: str
    ) -> None:
        with self.lock:
            if frame_id:
                self._main_frames[session_id] = frame_id
            self._pending_nav_origin.pop(session_id, None)

    def arm_secret(
        self,
        session_id: str | None,
        origin: str,
        secret: str,
        charsets: tuple[str, ...] = (),
    ) -> None:
        """Refuse, for the life of this session, every request that carries
        `secret` to an origin other than `origin`. `charsets` are the labels
        the form declares (`document.characterSet`, `accept-charset`): a form
        is sent in its charset, and a character it lacks becomes a numeric
        character reference. A label without a codec refuses to arm."""
        if not secret:
            return
        forms = {secret.encode("utf-8"), json.dumps(secret)[1:-1].encode("ascii")}
        for label in ("windows-1252", *charsets):
            codecs_for = FORM_CHARSET_CODECS.get(label.strip().lower())
            if codecs_for is None:
                try:
                    codecs_for = (codecs.lookup(label.strip()).name,)
                except LookupError:
                    raise BrowserError(
                        ClosedFailure.PROTOCOL,
                        f"auth_login cannot guard the form charset {label!r}",
                    ) from None
            for codec in codecs_for:
                forms.add(secret.encode(codec, "xmlcharrefreplace"))
        with self.lock:
            self._armed_secrets.setdefault(session_id, []).append(
                (origin, tuple(forms))
            )
            self._submit_locks.setdefault(session_id, set()).add(origin)

    def release_submit_lock(self, session_id: str | None) -> None:
        """End the submission window: the login landed, failed, or the agent
        navigates on its own authority. The byte guard stays armed."""
        with self.lock:
            self._submit_locks.pop(session_id, None)

    def _submit_lock_refuses(
        self, session_id: str | None, paused: dict[str, Any]
    ) -> bool:
        """A form sends its fields only by navigation; a page script that sends
        them is the login origin's own code. So while a login submits, a
        navigation to another origin is refused, and only a main-frame
        navigation to the login origin is the login landing. A login sent by
        script keeps the lock until the agent navigates. A redirect of the
        landing that keeps its method and body (307/308) is refused off the
        login origin; a 302/303 hop becomes a GET without the body."""
        req = paused.get("request", {})
        try:
            req_origin = origin_of(urlsplit(str(req.get("url", ""))))
        except ValueError:
            req_origin = ""
        # Chromium names a redirect hop `interception-job-<n>.<hop>`: the hops
        # of one request share the part before the last dot.
        landing_id = str(paused.get("requestId") or "").rpartition(".")[0] or str(
            paused.get("requestId") or ""
        )
        landing = self._landings.get(session_id)
        if (
            landing
            and landing_id
            and landing_id == landing[1]
            and req_origin != landing[0]
            and str(req.get("method", "GET")).upper() != "GET"
        ):
            return True
        locks = self._submit_locks.get(session_id)
        if not locks:
            return False
        resource_type = paused.get("resourceType")
        if req_origin in locks:
            frame_id = paused.get("frameId")
            main_frame = frame_id is None or frame_id == self._main_frames.get(
                session_id
            )
            if main_frame and resource_type == "Document":
                del self._submit_locks[session_id]
                if landing_id:
                    self._landings[session_id] = (req_origin, landing_id)
            return False
        return bool(resource_type == "Document")

    def _leaks_secret(self, session_id: str | None, req: dict[str, Any]) -> bool:
        """shortcut: matches the bytes a browser sends for the form (its
        charset, percent escapes, encoded twice); a page script that transforms
        the secret on its own origin is that origin's code, outside this guard."""
        armed = self._armed_secrets.get(session_id)
        if not armed:
            return False
        req_url = str(req.get("url", ""))
        try:
            req_origin = origin_of(urlsplit(req_url))
        except ValueError:
            req_origin = ""
        body = str(req.get("postData") or "")
        raw_parts = [req_url.encode("utf-8"), body.encode("utf-8")]
        for entry in req.get("postDataEntries") or []:
            raw = entry.get("bytes") if isinstance(entry, dict) else None
            if isinstance(raw, str):
                try:
                    raw_parts.append(base64.b64decode(raw, validate=True))
                except ValueError:
                    return True
        # A body the engine left out is not proof that the secret is absent.
        body_unseen = bool(req.get("hasPostData")) and len(raw_parts) == 2 and not body
        candidates = []
        for part in raw_parts:
            layer = part
            for _ in range(3):
                candidates.append(layer)
                layer = unquote_to_bytes(layer.replace(b"+", b" "))
            candidates.append(layer)
        return any(
            req_origin != origin
            and (body_unseen or any(f in c for f in forms for c in candidates))
            for origin, forms in armed
        )

    def _resolve_paused(self, event: dict[str, Any]) -> None:
        """The whole runtime SSRF gate: every request the engine pauses is put
        to the same kernel the seam uses on the URL a caller names, plus per-frame
        cross-origin internal (public -> loopback) containment."""
        paused = event["params"]
        session_id = event.get("sessionId")
        frame_id = paused.get("frameId")
        req = paused.get("request", {})
        req_url = str(req.get("url", ""))
        headers = req.get("headers") if isinstance(req.get("headers"), dict) else {}
        resource_type = paused.get("resourceType")

        with self.lock:
            initiators: list[str] = []
            main_fid = self._main_frames.get(session_id)
            pending = self._pending_nav_origin.get(session_id)
            explicit = (
                resource_type == "Document"
                and frame_id == main_fid
                and pending is not None
                and same_origin(req_url, pending)
                and not paused.get("redirectedRequestId")
            )
            document = self._document_requests.get(str(frame_id))
            if explicit:
                initiators.append(self._pending_nav_origin.pop(session_id))
            elif (
                resource_type == "Document"
                and document is not None
                and paused.get("redirectedRequestId") == document[0]
            ):
                initiators.append(document[1])
            else:
                initiators.append(self._frame_origins.get(str(frame_id), "about:blank"))
            for h_key, h_val in headers.items():
                if str(h_key).lower() in ("origin", "referer") and isinstance(
                    h_val, str
                ):
                    initiators.append(h_val)

            allowed = (
                is_public_safe(req_url)
                and not any(
                    is_cross_origin_internal(req_url, init_url)
                    for init_url in initiators
                    if init_url
                )
                and not self._leaks_secret(session_id, req)
                and not self._submit_lock_refuses(session_id, paused)
            )

            reply: dict[str, Any] = {"requestId": str(paused["requestId"])}
            if allowed:
                method = "Fetch.continueRequest"
                if resource_type == "Document" and frame_id:
                    main_fid = self._main_frames.get(session_id)
                    if (
                        main_fid is not None
                        and main_fid not in self._frame_origins
                        and not paused.get("parentFrameId")
                    ):
                        self._main_frames[session_id] = str(frame_id)
                        main_fid = str(frame_id)
                    # A local request does not grant permission to the old document.
                    if not is_loopback_host(bare_host(req_url) or ""):
                        self._frame_origins[str(frame_id)] = req_url
                    self._document_requests[str(frame_id)] = (
                        str(paused["requestId"]),
                        req_url,
                    )
                    if str(frame_id) == main_fid:
                        self._pending_nav_origin.pop(session_id, None)
            else:
                method = "Fetch.failRequest"
                reply["errorReason"] = "BlockedByClient"
                if resource_type == "Document":
                    self._document_requests.pop(str(frame_id), None)
        self.forgotten.add(self._post(method, reply, session_id))
        # The reply goes first so the engine is never kept waiting on the hook.
        if self.on_event is not None:
            self.on_event(event)

    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        if method == "Target.attachToTarget" and params and self._auto_attach:
            target_id = str(params["targetId"])
            with self.cond:
                ready = self.cond.wait_for(
                    lambda: (
                        self.ended
                        or (
                            target_id in self._target_sessions
                            and self._target_sessions[target_id]
                            not in self._target_pending
                        )
                    ),
                    timeout,
                )
                attached = self._target_sessions.get(target_id)
                if not ready or self.ended or attached in self._target_failed:
                    raise BrowserError(
                        ClosedFailure.PROTOCOL, "Target admission failed"
                    )
                return {"sessionId": attached}
        if method == "Page.navigate" and params and "url" in params:
            requested = urlsplit(str(params["url"]))
            self._pending_nav_origin[session_id] = (
                f"{origin_of(requested)}{requested.path or '/'}"
                + (f"?{requested.query}" if requested.query else "")
            )
            self.release_submit_lock(session_id)
        # A write to an engine that is gone is a closed browser, not an untyped
        # BrokenPipeError. Here and not in `_post`: the reader thread writes
        # through `_post` too, and its loop ends on OSError.
        try:
            req_id = self._post(method, params, session_id)
        except BrokenPipeError as e:
            if method == "Page.navigate":
                self._pending_nav_origin.pop(session_id, None)
            raise BrowserError(
                ClosedFailure.BROWSER_CLOSED, f"CDP pipe closed before {method}"
            ) from e

        # Wait for response
        with self.cond:
            try:
                deadline = time.monotonic() + timeout
                while req_id not in self.responses:
                    if self.ended:
                        raise BrowserError(
                            ClosedFailure.BROWSER_CLOSED,
                            f"CDP pipe ended before answering {method}",
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise BrowserError(
                            ClosedFailure.PROTOCOL, f"CDP timeout: {method}"
                        )
                    self.cond.wait(remaining)
                resp = self.responses.pop(req_id)

                if "error" in resp:
                    raise BrowserError(
                        ClosedFailure.PROTOCOL, f"CDP error: {resp['error']}"
                    )
                result = dict(resp.get("result", {}))
            finally:
                if method == "Page.navigate":
                    self._pending_nav_origin.pop(session_id, None)
        if method == "Target.setAutoAttach" and session_id is None:
            self._auto_attach = bool(params and params.get("autoAttach"))
        if method == "Target.attachToTarget":
            attached_sid = str(result["sessionId"])
            if params and "targetId" in params:
                self._main_frames[attached_sid] = str(params["targetId"])
                self._target_sessions[str(params["targetId"])] = attached_sid
            # Arm the interceptor at the session's BIRTH, outside the lock the
            # answer above was waiting under. An engine that refuses to arm
            # raises here, so no unguarded session is ever handed back.
            self.send(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*"}]},
                attached_sid,
                timeout,
            )
        if method == "Page.enable":
            # Page.loadEventFired has no document identity. Arm the load
            # events that carry frameId/loaderId and the pre-document
            # containment script before handing the page back.
            self.send(
                "Page.setLifecycleEventsEnabled", {"enabled": True}, session_id, timeout
            )
            # Page.enable runs on every navigation; the script is per session.
            # Marked only once the engine answers: a failed install is retried,
            # and the script's own guard makes a late duplicate return at once.
            if session_id not in self._contained:
                self.send(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": CONTAINMENT_JS},
                    session_id,
                    timeout,
                )
                self._contained.add(session_id)
        if method == "Page.navigate" and params and "url" in params:
            self._record_navigation_reply(
                session_id,
                str(result["frameId"]) if result.get("frameId") else None,
                str(params["url"]),
            )
        return result

    def wait_event(
        self,
        method: str,
        session_id: str | None = None,
        timeout: float = 15.0,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Wait for an event matching its method, session and supplied fields."""
        with self.cond:
            deadline = time.monotonic() + timeout
            while True:
                for i, ev in enumerate(self.events):
                    if ev.get("method") != method:
                        continue
                    if session_id is not None and ev.get("sessionId") != session_id:
                        continue
                    if params is not None and any(
                        ev.get("params", {}).get(key) != value
                        for key, value in params.items()
                    ):
                        continue
                    del self.events[i]
                    return dict(ev.get("params", {}))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BrowserError(
                        ClosedFailure.PROTOCOL, f"CDP event timeout: {method}"
                    )
                self.cond.wait(remaining)

    def close(self) -> None:
        # Only the write end: the reader thread owns fd_in and closes it at EOF.
        # Closed here while the reader runs, the number is reused by the next
        # pipe, and this reader would answer that browser with stale state.
        try:
            os.close(self.fd_out)
        except OSError:
            pass


class BrowserSession:
    def __init__(
        self,
        config: BrowserLaunchConfig,
        client_factory: Any = None,
        on_event: EventHook | None = None,
    ) -> None:
        """`client_factory` injects the CDP endpoint (the §31 double); without
        it the session launches and owns a real Chromium over pipes 3/4.
        `on_event` lives HERE because the client is rebuilt on idle reap
        (`_ensure_running`): a listener appended to one client dies with it."""
        self.config = config
        self.client_factory = client_factory
        self.on_event = on_event
        self.profile: BrowserProfile | None = None
        self.custody: BrowserCustody | None = None
        self.egress_proxy: EgressProxy | None = None
        self.client: CdpPipeClient | None = None
        self.last_active_time = time.time()
        self.closed = False
        self._tab_sessions: dict[TabId, str] = {}
        self._active_tab: TabId | None = None
        self._ensure_running()

    def _ensure_running(self) -> None:
        if self.closed:
            raise BrowserError(
                ClosedFailure.BROWSER_CLOSED, "Session is permanently closed"
            )

        if self.client and time.time() - self.last_active_time > DEFAULT_IDLE_REAP:
            self._teardown()
            self.last_active_time = time.time()

        if self.client is None:
            try:
                self._launch()
            except BaseException:
                self._teardown()
                raise

    def _launch(self) -> None:
        import sys

        if self.client_factory is not None:
            self.client = self.client_factory()
            return

        # get_chromium_executable raises ClosedFailure.LAUNCH itself when no
        # engine resolves, naming the slot and the override — the old `if not
        # exe` guard is unreachable now that it returns `str`, and an
        # unreachable branch is a branch coverage can never close.
        exe = get_chromium_executable()

        # `systemd-run --user` reaches the user manager only through the
        # session bus, and it reads that address out of the ENVIRONMENT: a
        # supervisor cleaned by `env -i` — what every lane proof runs under —
        # still has the bus on the disk and no name left for it. Both names
        # derive from the uid, so derive what the environment dropped. Before
        # the profile and the pipes on purpose: a refusal here has nothing
        # open to give back.
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        bus = Path(runtime_dir) / "bus"
        if not bus.is_socket():
            raise BrowserError(
                ClosedFailure.LAUNCH,
                f"no session bus socket at {bus}: an environment that merely "
                f"fails to NAME the bus is derived from the uid and no longer "
                f"refuses, so this is the bus itself absent — and without one "
                f"there is no scope, no delegated cgroup, and no engine worth "
                f"launching",
            )
        env = dict(
            os.environ,
            HOME=os.environ.get("HOME", os.path.expanduser("~")),
            TILION_NO_GEO="1",
            XDG_RUNTIME_DIR=runtime_dir,
            DBUS_SESSION_BUS_ADDRESS=os.environ.get(
                "DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}"
            ),
        )

        try:
            self.egress_proxy = EgressProxy()
        except OSError as error:
            raise BrowserError(ClosedFailure.LAUNCH, "Browser proxy failed") from error
        self.profile = BrowserProfile()

        # We need pipes for FDs 3 and 4
        # parent reads from pr, browser writes to pw (fd 4)
        pr, pw = os.pipe()
        # parent writes to cw, browser reads from cr (fd 3)
        cr, cw = os.pipe()
        # The wrapper reports the cgroup it was actually born into. Read back
        # from the process, never constructed from a unit name: the manager
        # nests slices, so the obvious path is the wrong one.
        rr, rw = os.pipe()
        # The death pipe. Nothing is ever written to it; the supervisor holds
        # `dw` and the kernel closes it when the supervisor dies — SIGKILL,
        # crash, or supervisor reaped by its own parent. EOF on `dr` is the
        # only trigger that survives the signal `_teardown` never gets to run.
        dr, dw = os.pipe()

        # `systemd-run --scope` is how the engine gets a cgroup of its own: a
        # process cannot move itself into a delegated subtree it was not born
        # in (measured here: EACCES, this login scope and the user manager
        # share only the root-owned `user-1000.slice`), so birth is the only
        # moment. The wrapper stays alive inside that scope as its reaper.
        wrapper = f"""import os, sys
os.write({rw}, open("/proc/self/cgroup", "rb").read())
os.close({rw})
if os.fork() == 0:
    os.close({dr})
    os.dup2({cr}, 3)
    os.dup2({pw}, 4)
    os.execv(sys.argv[1], sys.argv[1:])
os.close({cr})
os.close({pw})
os.read({dr}, 1)
mine = open("/proc/self/cgroup").read().split("0::")[1].strip()
open("{CGROUP_ROOT}" + mine + "/cgroup.kill", "w").write("1")
"""

        args = [
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            sys.executable,
            "-c",
            wrapper,
            exe,
            f"--user-data-dir={self.profile.path}",
            "--remote-debugging-pipe",
            "--no-first-run",
            "--no-startup-window",
            "--no-default-browser-check",
            "--disable-default-apps",
            "--disable-sync",
            f"--proxy-server=socks5://{self.egress_proxy.address}",
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ]
        if self.config.headless:
            args.append("--headless=new")

        try:
            process = subprocess.Popen(
                args,
                # Nothing reads it: a pipe would hold 64 KiB of Chromium's log
                # and then stall the engine on its next write.
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid,  # noqa: PLW1509
                pass_fds=(cr, pw, rw, dr),
                env=env,
            )
        except OSError as e:
            for fd in (pr, pw, cr, cw, rr, rw, dr, dw):
                os.close(fd)
            raise BrowserError(ClosedFailure.LAUNCH, f"Failed to launch Chrome: {e}")

        # The parent can now close its copies of the child's FDs. `dw` is the
        # one it must NOT close: it is the death pipe, and a supervisor that
        # drops it tells the reaper it already died.
        os.close(cr)
        os.close(pw)
        os.close(rw)
        os.close(dr)

        # Every step from here can raise — the read, the membership parse, the
        # custody constructor that refuses an unplaced scope. On that path the
        # engine is ALREADY running, so leaving without cleanup leaks three fds
        # and a zombie per attempt. Closing `dw` is itself the cleanup: it is
        # the death pipe, and the reaper answers EOF by killing the scope.
        try:
            born = os.read(rr, 4096).decode()
            # Self-falsifying: had the scope not placed the wrapper anywhere of
            # its own, `born` would name this very cgroup and custody refuses.
            self.custody = BrowserCustody(
                process, CgroupCustody(unified_membership(born)), dw
            )
        except BaseException:
            for fd in (pr, cw, dw):
                os.close(fd)
            process.wait(timeout=5)
            raise
        finally:
            os.close(rr)

        self.client = CdpPipeClient(fd_in=pr, fd_out=cw, on_event=self.on_event)
        self.client.send("Target.setAutoAttach", AUTO_ATTACH)

    def _teardown(self) -> None:
        self._tab_sessions.clear()
        self._active_tab = None
        if self.client:
            self.client.close()
            self.client = None
        try:
            if self.custody:
                self.custody.terminate()
                self.custody = None
            if self.profile:
                self.profile.close()
                self.profile = None
        finally:
            if self.egress_proxy:
                self.egress_proxy.close()
                self.egress_proxy = None

    def mark_active(self) -> None:
        # Reap check BEFORE the timestamp: a call that arrives after an idle
        # window must relaunch, not reset the clock first.
        self._ensure_running()
        self.last_active_time = time.time()

    def close_session(self) -> None:
        self.closed = True
        self._teardown()

    def tabs_list(self) -> list[TabId]:
        """Live page targets, with the selected tab first for every consumer."""
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        targets = self.client.send("Target.getTargets")
        tabs = [t["targetId"] for t in targets["targetInfos"] if t["type"] == "page"]
        if self._active_tab not in tabs:
            self._active_tab = tabs[0] if tabs else None
        else:
            tabs.remove(self._active_tab)
            tabs.insert(0, self._active_tab)
        return tabs

    def tabs_open(self, url: str, browser_context_id: str | None = None) -> TabId:
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        # Blank, then navigate: a `createTarget` carrying the URL starts
        # loading before anything is attached, and the sub-resources of that
        # first load would meet no interceptor at all. The context id, when
        # given, puts the tab in its own cookie jar and storage.
        params: dict[str, Any] = {"url": "about:blank"}
        if browser_context_id is not None:
            params["browserContextId"] = browser_context_id
        res = self.client.send("Target.createTarget", params)
        tab_id = str(res["targetId"])
        self.navigate(tab_id, url)
        return tab_id

    def context_open(self) -> str:
        """One isolated browser context: its own cookies and storage, gone at
        dispose. The caller holds it in try/finally — never __del__."""
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        res = self.client.send("Target.createBrowserContext")
        return str(res["browserContextId"])

    def context_dispose(self, context_id: str) -> None:
        """Dispose closes every target of the context; the session cache is
        then reconciled against Target.getTargets so a recycled targetId never
        reuses a dead sessionId (one call, no per-context bookkeeping)."""
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        self.client.send(
            "Target.disposeBrowserContext", {"browserContextId": context_id}
        )
        alive = {
            str(t["targetId"])
            for t in self.client.send("Target.getTargets")["targetInfos"]
        }
        for tab_id in [t for t in self._tab_sessions if t not in alive]:
            del self._tab_sessions[tab_id]

    def _session_for(self, tab_id: TabId) -> str:
        """One flattened CDP session per tab, reused. A fresh attach per call
        raced the page's execution context (a location.href read could answer
        before the navigated document's context existed) — the cache holds the
        session the navigation itself proved live."""
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        cached = self._tab_sessions.get(tab_id)
        if cached is not None:
            return cached
        res = self.client.send(
            "Target.attachToTarget", {"targetId": tab_id, "flatten": True}
        )
        session_id = str(res["sessionId"])
        # Armed at the session's birth, right after the Fetch.enable that
        # `send` arms on attach: console and exception frames flow only for
        # a session whose Runtime domain is enabled.
        self.client.send("Runtime.enable", {}, session_id)
        self._tab_sessions[tab_id] = session_id
        return session_id

    def navigate(self, tab_id: TabId, url: str) -> None:
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        if self.egress_proxy is not None:
            try:
                target = urlsplit(url)
                if target.scheme in ("http", "https"):
                    if not target.hostname:
                        raise BrowserError(
                            FailureCode.GRANT_REQUIRED, "Navigation target refused"
                        )
                    # Check each navigation even when Chromium reuses a connection.
                    resolve_admitted(
                        (
                            target.hostname,
                            target.port or (443 if target.scheme == "https" else 80),
                        )
                    )
            except (OSError, ValueError) as error:
                raise BrowserError(
                    ClosedFailure.PROTOCOL, "Navigation DNS failed"
                ) from error
        session_id = self._session_for(tab_id)
        self.client.send("Page.enable", {}, session_id)
        result = self.client.send("Page.navigate", {"url": url}, session_id)
        if result.get("errorText"):
            raise BrowserError(ClosedFailure.PROTOCOL, "CDP navigation failed")
        # Same-document navigation has no new loader or load event. Otherwise
        # only THIS loader's main-frame load can make the next snapshot fresh.
        if result.get("loaderId"):
            self.client.wait_event(
                "Page.lifecycleEvent",
                session_id,
                params={
                    "name": "load",
                    "frameId": result["frameId"],
                    "loaderId": result["loaderId"],
                },
            )
        self._active_tab = tab_id

    def evaluate(
        self, tab_id: TabId, expression: str, await_promise: bool = False
    ) -> Any:
        if not self.client:
            raise BrowserError(ClosedFailure.BROWSER_CLOSED, "No client")
        self.mark_active()
        session_id = self._session_for(tab_id)
        out = self.client.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
            },
            session_id,
        )
        if "exceptionDetails" in out:
            raise BrowserError(ClosedFailure.PROTOCOL, "Page evaluation failed")
        return out.get("result", {}).get("value")
