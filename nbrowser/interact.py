import json
import math
from typing import Any
from urllib.parse import urlsplit

from . import auth
from .egress_guard import is_cross_origin_internal, is_public_safe
from .errors import AuthorityRequired, BrowserError, InputFailure
from .session import BrowserSession
from .types import EffectOperation

ALLOWED_INTERACTION_VERBS = frozenset(
    {
        "click",
        "hover",
        "scroll",
        "focus",
        "type",
        "fill_form",
        "clear",
        "select",
        "press_key",
        "submit",
        "auth_login",
    }
)


class Interaction:
    def __init__(
        self,
        verb: str,
        selector: str = "",
        ref: str = "",
        text: str = "",
        value: str = "",
        key: str = "",
        x: int = 0,
        y: int = 0,
        human: bool = False,
        seed: int = 0,
        expected_origin: str | None = None,
        node_uid: int | None = None,
        doc_gen: str | None = None,
        fallback_kind: str | None = None,
        fallback_label: str | None = None,
        fallback_name: str | None = None,
        fallback_count: int | None = None,
    ):
        self.verb = verb
        self.selector = selector
        self.ref = ref
        self.text = text
        self.value = value
        self.key = key
        self.x = x
        self.y = y
        self.human = human
        self.seed = seed
        self.expected_origin = expected_origin
        self.node_uid = node_uid
        self.doc_gen = doc_gen
        self.fallback_kind = fallback_kind
        self.fallback_label = fallback_label
        self.fallback_name = fallback_name
        self.fallback_count = fallback_count


def is_local_activation(interaction: Any) -> bool:
    if not hasattr(interaction, "verb"):
        return False
    return str(interaction.verb) in ALLOWED_INTERACTION_VERBS


def _punctuation_key_info(ch: str) -> tuple[str, int]:
    table = {
        ";": ("Semicolon", 186),
        ":": ("Semicolon", 186),
        "=": ("Equal", 187),
        "+": ("Equal", 187),
        ",": ("Comma", 188),
        "<": ("Comma", 188),
        "-": ("Minus", 189),
        "_": ("Minus", 189),
        ".": ("Period", 190),
        ">": ("Period", 190),
        "/": ("Slash", 191),
        "?": ("Slash", 191),
        "`": ("Backquote", 192),
        "~": ("Backquote", 192),
        "[": ("BracketLeft", 219),
        "{": ("BracketLeft", 219),
        "\\": ("Backslash", 220),
        "|": ("Backslash", 220),
        "]": ("BracketRight", 221),
        "}": ("BracketRight", 221),
        "'": ("Quote", 222),
        '"': ("Quote", 222),
    }
    return table.get(ch, ("", 0))


def named_key_info(key: str) -> tuple[str, str, int, str | None]:
    """Return (key_name, code, windows_vk_code, text) matching Playwright's USKeyboardLayout."""
    low = key.lower()
    named: dict[str, tuple[str, str, int, str | None]] = {
        "enter": ("Enter", "Enter", 13, "\r"),
        "return": ("Enter", "Enter", 13, "\r"),
        "tab": ("Tab", "Tab", 9, "\t"),
        "escape": ("Escape", "Escape", 27, None),
        "esc": ("Escape", "Escape", 27, None),
        "backspace": ("Backspace", "Backspace", 8, None),
        "delete": ("Delete", "Delete", 46, None),
        "arrowup": ("ArrowUp", "ArrowUp", 38, None),
        "up": ("ArrowUp", "ArrowUp", 38, None),
        "arrowdown": ("ArrowDown", "ArrowDown", 40, None),
        "down": ("ArrowDown", "ArrowDown", 40, None),
        "arrowleft": ("ArrowLeft", "ArrowLeft", 37, None),
        "left": ("ArrowLeft", "ArrowLeft", 37, None),
        "arrowright": ("ArrowRight", "ArrowRight", 39, None),
        "right": ("ArrowRight", "ArrowRight", 39, None),
        "home": ("Home", "Home", 36, None),
        "end": ("End", "End", 35, None),
        "pageup": ("PageUp", "PageUp", 33, None),
        "pagedown": ("PageDown", "PageDown", 34, None),
        "space": (" ", "Space", 32, " "),
        " ": (" ", "Space", 32, " "),
    }
    if low in named:
        return named[low]
    if len(key) == 1:
        if key.isalpha():
            upper = key.upper()
            return (key, f"Key{upper}", ord(upper), key)
        if key.isdigit():
            return (key, f"Digit{key}", ord(key), key)
        code, vk = _punctuation_key_info(key)
        return (key, code or key, vk, key)
    return (key, key, 0, None)


def human_mouse_trajectory(
    start_x: float,
    start_y: float,
    target_x: float,
    target_y: float,
    *,
    seed: int = 0,
    steps: int | None = None,
) -> list[tuple[float, float]]:
    """Seeded smoothstep + perpendicular parabolic curve matching agent-browser's --human."""
    dx = target_x - start_x
    dy = target_y - start_y
    distance = math.hypot(dx, dy)
    if steps is None:
        duration_ms = min(700, max(100, int(80.0 + distance * 0.35)))
        spatial = min(60, max(1, math.ceil(distance / 12.0)))
        steps = min(240, max(spatial, (duration_ms + 15) // 16))
    steps = max(1, steps)
    if distance > 0.0:
        mixed = (
            (seed & 0xFFFFFFFFFFFFFFFF) * 6364136223846793005 + 1442695040888963407
        ) & 0xFFFFFFFFFFFFFFFF
        unit = float(mixed >> 11) / float(1 << 53)
        bend = (unit * 2.0 - 1.0) * min(36.0, distance * 0.08)
        perp_x = -dy / distance
        perp_y = dx / distance
    else:
        bend = 0.0
        perp_x = 0.0
        perp_y = 0.0

    points: list[tuple[float, float]] = []
    for step in range(1, steps + 1):
        if step == steps:
            points.append((target_x, target_y))
            continue
        t = step / float(steps)
        eased = t * t * (3.0 - 2.0 * t)
        curve = 4.0 * t * (1.0 - t) * bend
        px = round(start_x + dx * eased + perp_x * curve, 2)
        py = round(start_y + dy * eased + perp_y * curve, 2)
        points.append((px, py))
    return points


def _resolve_node_js(interaction: Interaction) -> str:
    """JS expression resolving `node` by (doc_gen, node_uid) with unambiguous
    role/label/name fallback or CSS selector."""
    sel_json = json.dumps(interaction.selector or "")
    uid_json = json.dumps(interaction.node_uid)
    doc_gen_json = json.dumps(interaction.doc_gen or "")
    fb_kind_json = json.dumps(interaction.fallback_kind or "")
    fb_label_json = json.dumps(interaction.fallback_label or "")
    fb_name_json = json.dumps(interaction.fallback_name or "")
    fb_count_json = json.dumps(interaction.fallback_count)
    return f"""(() => {{
        const reqDocGen = {doc_gen_json};
        const reqUid = {uid_json};
        if (reqDocGen) {{
            const liveGen = String(window[Symbol.for('nbrowser.docGen')] || '');
            if (liveGen !== reqDocGen) {{
                return {{ error: 'stale_doc_gen' }};
            }}
        }}
        if (reqUid !== null) {{
            const store = window[Symbol.for('nbrowser.refs')];
            if (store && store.uidToNode && store.uidToNode.has(reqUid)) {{
                const candidate = store.uidToNode.get(reqUid);
                if (candidate && candidate.isConnected) {{
                    return {{ node: candidate }};
                }}
            }}
            const fbKind = {fb_kind_json};
            const fbLabel = {fb_label_json};
            const fbName = {fb_name_json};
            const fbCount = {fb_count_json};
            if (fbKind && (fbLabel || fbName)) {{
                const kindOf = (el) => {{
                    const tag = (el.tagName || '').toLowerCase();
                    const type = (el.getAttribute ? (el.getAttribute('type') || '') : '').toLowerCase();
                    const hidden = (tag === 'label' && el.querySelector) ? el.querySelector('input[type="checkbox"], input[type="radio"]') : null;
                    if (tag === 'a' || (el.getAttribute && el.getAttribute('href') !== null)) return 'link';
                    if (tag === 'button' || (el.getAttribute && el.getAttribute('role') === 'button') || (tag === 'input' && ['submit','button'].includes(type))) return 'button';
                    if ((tag === 'input' && type === 'checkbox') || (hidden && (hidden.type || '').toLowerCase() === 'checkbox')) return 'checkbox';
                    if ((tag === 'input' && type === 'radio') || (hidden && (hidden.type || '').toLowerCase() === 'radio')) return 'radio';
                    if (tag === 'input') return 'input';
                    if (tag === 'select') return 'select';
                    if (tag === 'textarea') return 'textarea';
                    return 'button';
                }};
                const all = Array.from(document.querySelectorAll('button,input,select,textarea,a[href],[role=button],[role=link],[role=checkbox],[role=radio],label'));
                const clean = (v) => String(v || '').replace(/\\s+/g, ' ').trim();
                const matches = all.filter((el) => {{
                    if (kindOf(el) !== fbKind) return false;
                    const lbl = clean(el.getAttribute('aria-label') || el.innerText || el.textContent || el.placeholder || el.name || '');
                    const nm = clean(el.name || '');
                    if (fbLabel && lbl !== fbLabel) return false;
                    if (fbName && nm !== fbName) return false;
                    return true;
                }});
                if (matches.length === 1 && (fbCount === null || fbCount === 1)) {{
                    return {{ node: matches[0] }};
                }}
                if (matches.length > 1) {{
                    return {{ error: 'ambiguous_ref_fallback' }};
                }}
            }}
            return {{ error: 'stale_ref' }};
        }}
        const sel = {sel_json};
        if (!sel) return {{ node: document.activeElement }};
        const found = document.querySelector(sel);
        return found ? {{ node: found }} : {{ error: 'not_found' }};
    }})()"""


def _dispatch_cdp_pointer_move(
    session: BrowserSession,
    tab_id: str,
    target_x: float,
    target_y: float,
    *,
    human: bool,
    seed: int,
) -> None:
    if not hasattr(session, "client") or session.client is None:
        return
    session_id = session._session_for(tab_id)
    if human:
        pts = human_mouse_trajectory(0.0, 0.0, target_x, target_y, seed=seed)
    else:
        pts = [(target_x, target_y)]
    for px, py in pts:
        session.client.send(
            "Input.dispatchMouseEvent",
            {"type": "mouseMoved", "x": px, "y": py},
            session_id,
        )


def interact(session: BrowserSession, interaction: Interaction, tab_id: str) -> bool:
    verb = interaction.verb
    exp_origin_json = json.dumps(getattr(interaction, "expected_origin", None) or "")
    resolve_js = _resolve_node_js(interaction)

    if verb in ("click", "submit"):
        pre_script = f"""(() => {{
            const toStr = (v) => ((v === null || v === undefined) ? "" : ("" + v));
            const resolveUrl = (u) => {{
                const s = toStr(u);
                if (typeof s !== 'string') return null;
                try {{
                    if (typeof document !== 'undefined' && document.createElement) {{
                        const a = document.createElement('a');
                        a.href = s;
                        if (a.href) return a.href;
                    }}
                }} catch (_) {{}}
                try {{
                    const SafeURL = typeof URL !== 'undefined' ? URL : window.URL;
                    const SafeBaseURI = document.baseURI || document.URL;
                    return new SafeURL(s, SafeBaseURI).href;
                }} catch (_) {{
                    return null;
                }}
            }};
            if ({exp_origin_json}) {{
                const expOrig = {exp_origin_json};
                if (window.location.origin !== expOrig) return false;
            }}
            const resolved = {resolve_js};
            if (!resolved || resolved.error || !resolved.node) {{
                return resolved && resolved.error ? {{ error: resolved.error }} : false;
            }}
            const node = resolved.node;
            if (node.disabled || (node.matches && node.matches(':disabled'))) return false;
            if (node.scrollIntoViewIfNeeded) node.scrollIntoViewIfNeeded(true);
            else if (node.scrollIntoView) node.scrollIntoView({{ block: 'center', inline: 'center' }});
            const rect = node.getBoundingClientRect ? node.getBoundingClientRect() : {{ x: 0, y: 0, width: 10, height: 10 }};
            const cx = rect.x + rect.width / 2;
            const cy = rect.y + rect.height / 2;
            if (rect.width > 0 && rect.height > 0 && typeof document.elementFromPoint === 'function') {{
                const hit = document.elementFromPoint(cx, cy);
                if (hit && hit !== node && !node.contains(hit) && (!hit.contains || !hit.contains(node))) {{
                    const label = (node.closest && node.closest('label'));
                    if (!label || !label.contains(hit)) {{
                        const blockerTag = (hit.tagName || 'element').toLowerCase() + (hit.id ? '#' + hit.id : '');
                        return {{ error: 'intercepted:' + blockerTag }};
                    }}
                }}
            }}
            const form = node.form || (node.closest ? node.closest('form') : null) || (node.tagName && node.tagName.toLowerCase() === 'form' ? node : null);
            const isFormAssoc = Boolean(form);
            const liveTag = (node.tagName || '').toLowerCase();
            const liveType = (node.getAttribute ? (node.getAttribute('type') || node.type || '') : '').toLowerCase();
            const hasFormAction = Boolean(node.hasAttribute && node.hasAttribute('formaction'));
            const formaction = hasFormAction ? (node.getAttribute('formaction') || '') : null;
            const onclick = node.getAttribute ? (node.getAttribute('onclick') || '') : '';
            const isSubmitHandler = /submit\\s*\\(|\\.submit\\b/i.test(onclick);
            const isLiveSubmit = ({json.dumps(verb)} === 'submit') || isSubmitHandler || hasFormAction || (
                isFormAssoc && (
                    ['submit', 'image'].includes(liveType) ||
                    (liveTag === 'button' && !['button', 'reset'].includes(liveType))
                )
            );
            const liveHref = (liveTag === 'a' && node.getAttribute ? (node.getAttribute('href') || '') : '');
            let resolvedActionUrl = null;
            if (isLiveSubmit || liveTag === 'a') {{
                const rawAct = hasFormAction ? formaction : (liveHref || (form ? ((form.getAttribute ? form.getAttribute('action') : null) || form.action) : null) || window.location.href);
                resolvedActionUrl = resolveUrl(rawAct);
            }}
            return {{ ok: true, x: cx, y: cy, targetUrl: resolvedActionUrl }};
        }})()"""
        res = session.evaluate(tab_id, pre_script)
        if isinstance(res, dict):
            err = res.get("error")
            if isinstance(err, str):
                if err.startswith("intercepted:"):
                    blocker = err.split(":", 1)[1]
                    raise BrowserError(
                        InputFailure.SELECTOR,
                        f"element click intercepted by {blocker}",
                    )
                if err in ("stale_doc_gen", "stale_ref", "ambiguous_ref_fallback"):
                    raise BrowserError(
                        InputFailure.SELECTOR,
                        f"element reference is {err}: take a fresh snapshot",
                    )
                return False
            target_url = res.get("targetUrl")
            if isinstance(target_url, str) and target_url:
                bound_orig = getattr(interaction, "expected_origin", None) or ""
                if not is_public_safe(target_url) or (
                    bound_orig and is_cross_origin_internal(target_url, bound_orig)
                ):
                    raise AuthorityRequired(EffectOperation(verb), target_url)
            if not res.get("ok"):
                return False
            cx = float(res.get("x", 0.0))
            cy = float(res.get("y", 0.0))
            if getattr(interaction, "human", False) or (cx != 0.0 or cy != 0.0):
                _dispatch_cdp_pointer_move(
                    session,
                    tab_id,
                    cx,
                    cy,
                    human=bool(getattr(interaction, "human", False)),
                    seed=int(getattr(interaction, "seed", 0)),
                )
            act_script = f"""(() => {{
                if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
                const resolved = {resolve_js};
                if (!resolved || resolved.error || !resolved.node) return false;
                const node = resolved.node;
                const liveTag = (node.tagName || '').toLowerCase();
                const liveType = (node.getAttribute ? (node.getAttribute('type') || node.type || '') : '').toLowerCase();
                if ({json.dumps(verb)} === 'submit' && liveTag === 'form') {{
                    if (typeof node.requestSubmit === 'function') node.requestSubmit();
                    else if (typeof node.submit === 'function') node.submit();
                    else node.click();
                    return {{ ok: true }};
                }}
                // A label's click activates its control: one click is the whole activation.
                node.click();
                return {{ ok: true }};
            }})()"""
            act_res = session.evaluate(tab_id, act_script)
            if isinstance(act_res, dict):
                return bool(act_res.get("ok"))
            return True if act_res is None else bool(act_res)
        return bool(res)

    elif verb == "scroll":
        script = f"(() => {{ if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false; const before = [scrollX, scrollY]; scrollBy({interaction.x}, {interaction.y}); return before[0] !== scrollX || before[1] !== scrollY; }})()"
        res = session.evaluate(tab_id, script)
        return bool(res)

    elif verb == "hover":
        script = f"""(() => {{
            if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
            const resolved = {resolve_js};
            const node = resolved && resolved.node ? resolved.node : null;
            if (!node) return false;
            node.dispatchEvent(new MouseEvent('mouseenter', {{ bubbles: true }}));
            return true;
        }})()"""
        res = session.evaluate(tab_id, script)
        return bool(res)

    elif verb == "focus":
        script = f"""(() => {{
            if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
            const resolved = {resolve_js};
            const node = resolved && resolved.node ? resolved.node : null;
            if (!node || node.disabled || (node.matches && node.matches(':disabled'))) return false;
            node.focus();
            return document.activeElement === node;
        }})()"""
        res = session.evaluate(tab_id, script)
        return bool(res)

    elif verb in ("type", "fill_form", "clear"):
        should_clear = "true" if verb in ("fill_form", "clear") else "false"
        txt = "" if verb == "clear" else (interaction.text or interaction.value)
        prep_script = f"""(() => {{
            if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
            const resolved = {resolve_js};
            if (!resolved || resolved.error || !resolved.node) return false;
            const node = resolved.node;
            if (node.disabled || (node.matches && node.matches(':disabled'))) return false;
            node.focus();
            let active = document.activeElement;
            while (active && active.shadowRoot && active.shadowRoot.activeElement) {{
                active = active.shadowRoot.activeElement;
            }}
            if (active !== node && !(node.contains && node.contains(active))) return false;
            if ({should_clear}) {{
                node.value = '';
                node.dispatchEvent(new Event('input', {{ bubbles: true }}));
                node.dispatchEvent(new Event('change', {{ bubbles: true }}));
            }}
            return {{ ok: true }};
        }})()"""
        client = getattr(session, "client", None)
        if txt and client is None:
            return False
        if not session.evaluate(tab_id, prep_script):
            return False
        if txt and client is not None:
            # One path: CDP inserts the text at the focused caret, as typing does.
            client.send("Input.insertText", {"text": txt}, session._session_for(tab_id))
            change_script = f"""(() => {{
                const resolved = {resolve_js};
                if (!resolved || !resolved.node) return false;
                resolved.node.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return true;
            }})()"""
            session.evaluate(tab_id, change_script)
        return True

    elif verb == "select":
        val = interaction.value or interaction.text
        vals_json = json.dumps([val] if val else [])
        script = f"""(() => {{
            if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
            const resolved = {resolve_js};
            if (!resolved || resolved.error || !resolved.node) return false;
            const node = resolved.node;
            if (!node.options) return false;
            const normalize = (v) => String(v ?? '').replace(/[\\u200B\\u200C\\u200D\\u2060\\uFEFF]/g, '').replace(/\\s+/g, ' ').trim();
            const options = Array.from(node.options);
            const vals = {vals_json};
            const wanted = new Set();
            for (const value of vals) {{
                let matches = options.filter((opt) =>
                    value === opt.value ||
                    value === (opt.label || '').trim() ||
                    value === (opt.textContent || '').trim()
                );
                if (matches.length === 0) {{
                    const normVal = normalize(value);
                    matches = options.filter((opt) => normalize(opt.label || opt.textContent) === normVal);
                }}
                if (matches.length === 0) {{
                    const available = options.map((o) => o.value + ' ("' + normalize(o.label || o.textContent) + '")').join(', ');
                    return {{ error: 'No option matched ' + JSON.stringify(vals) + '. Available options: ' + available }};
                }}
                for (const opt of matches) wanted.add(opt);
            }}
            if (wanted.size === 0) {{
                const available = options.map((o) => o.value + ' ("' + normalize(o.label || o.textContent) + '")').join(', ');
                return {{ error: 'No option matched ' + JSON.stringify(vals) + '. Available options: ' + available }};
            }}
            for (const opt of options) opt.selected = wanted.has(opt);
            node.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return {{ matched: wanted.size }};
        }})()"""
        res = session.evaluate(tab_id, script)
        if isinstance(res, dict):
            if "error" in res:
                raise BrowserError(InputFailure.SELECTOR, str(res["error"]))
            return bool(res.get("matched"))
        return bool(res)

    elif verb == "press_key":
        key_raw = interaction.key or interaction.text or "Enter"
        key_name, code, vk_code, key_text = named_key_info(key_raw)
        check_js = f"""(() => {{
            if ({exp_origin_json} && window.location.origin !== {exp_origin_json}) return false;
            const resolved = {resolve_js};
            if (resolved && resolved.error) return {{ ok: false, error: resolved.error }};
            const node = (resolved && resolved.node) ? resolved.node : document.activeElement;
            // Keys go to the focused element: the named target takes focus first.
            if (resolved && resolved.node && node.focus) node.focus();
            if ({json.dumps(key_name)} === 'Enter' && node) {{
                const form = node.form || (node.closest ? node.closest('form') : null);
                // Implicit submission uses the form's default button as submitter.
                const isSubmit = (el) => el && ((el.tagName === 'BUTTON' && !['button', 'reset'].includes((el.getAttribute('type') || 'submit').toLowerCase()))
                    || (el.tagName === 'INPUT' && ['submit', 'image'].includes((el.type || '').toLowerCase())));
                const defaultButton = isSubmit(node) ? node
                    : (form ? Array.from(form.elements || []).find(isSubmit) : null);
                const act = (defaultButton && defaultButton.getAttribute('formaction'))
                    || (form ? ((form.getAttribute ? form.getAttribute('action') : null) || form.action) : null)
                    || window.location.href;
                try {{
                    const resolvedAct = new URL(String(act || ''), document.baseURI || location.href).href;
                    return {{ ok: true, targetUrl: resolvedAct }};
                }} catch (_) {{
                    return {{ ok: false }};
                }}
            }}
            return {{ ok: true, targetUrl: null }};
        }})()"""
        res = session.evaluate(tab_id, check_js)
        if isinstance(res, dict):
            if not res.get("ok"):
                return False
            target_url = res.get("targetUrl")
            if isinstance(target_url, str) and target_url:
                bound_orig = getattr(interaction, "expected_origin", None) or ""
                if not is_public_safe(target_url) or (
                    bound_orig and is_cross_origin_internal(target_url, bound_orig)
                ):
                    raise AuthorityRequired(EffectOperation.press_key, target_url)
        elif not res:
            return False

        if hasattr(session, "client") and session.client is not None:
            session_id = session._session_for(tab_id)
            down_params: dict[str, Any] = {
                "type": "keyDown",
                "key": key_name,
                "code": code,
                "windowsVirtualKeyCode": vk_code,
                "nativeVirtualKeyCode": vk_code,
            }
            if key_text is not None:
                down_params["text"] = key_text
                down_params["unmodifiedText"] = key_text
            up_params: dict[str, Any] = {
                "type": "keyUp",
                "key": key_name,
                "code": code,
                "windowsVirtualKeyCode": vk_code,
                "nativeVirtualKeyCode": vk_code,
            }
            # An Enter that submits a form navigates, and the engine never
            # answers a key event whose document is gone: past a short wait the
            # key is taken as applied.
            wait = 3.0 if key_name == "Enter" else 30.0
            try:
                for params in (down_params, up_params):
                    session.client.send(
                        "Input.dispatchKeyEvent", params, session_id, timeout=wait
                    )
            except BrowserError as exc:
                if key_name != "Enter" or not exc.message.startswith("CDP timeout"):
                    raise
        return True

    elif verb == "auth_login":
        profile_name = interaction.value or interaction.text
        profile = auth.load_profile(profile_name, allow_live_store=True)
        bound_orig = getattr(interaction, "expected_origin", None) or ""
        if not bound_orig or bound_orig != profile.origin:
            raise AuthorityRequired(
                EffectOperation.auth_login, bound_orig or "unknown_origin"
            )
        # The DOM checks give a clean refusal, but page code runs between them
        # and the submit. The network guard is the boundary: no request carries
        # the password to another origin for the life of this session.
        guard = getattr(session, "client", None)
        arm_secret = getattr(guard, "arm_secret", None)
        release_lock = getattr(guard, "release_submit_lock", None)
        if arm_secret is None or release_lock is None:
            raise BrowserError(
                InputFailure.SELECTOR, "auth_login needs the session's network guard"
            )
        u_sel = json.dumps(profile.username_selector)
        p_sel = json.dumps(profile.password_selector)
        s_sel = json.dumps(profile.submit_selector)
        u_val = json.dumps(profile.username)
        p_val = json.dumps(profile.password)
        orig_json = json.dumps(profile.origin)
        nodes_js = f"""
            if (window.location.origin !== {orig_json}) return {{ error: 'origin_mismatch' }};
            const uNode = document.querySelector({u_sel});
            const pNode = document.querySelector({p_sel});
            const sNode = document.querySelector({s_sel});
            if (!uNode || !pNode || !sNode) return {{ error: 'selector_missing' }};
            const form = sNode.form || pNode.form || (sNode.closest ? sNode.closest('form') : null);
            const resolveOrigin = () => {{
                const rawAct = (sNode.getAttribute && sNode.getAttribute('formaction'))
                    || sNode.formAction
                    || (form ? ((form.getAttribute ? form.getAttribute('action') : null) || form.action) : null)
                    || window.location.href;
                try {{
                    return new URL(String(rawAct), document.baseURI || window.location.href).origin;
                }} catch (_) {{
                    return '';
                }}
            }};
            const initialOrigin = resolveOrigin();
            if (initialOrigin !== {orig_json}) {{
                return {{ error: 'action_origin_mismatch:' + initialOrigin }};
            }}"""
        # Step 1, without the password: the checks and the form's charsets.
        probe_js = f"""(() => {{{nodes_js}
            const declared = form && form.acceptCharset ? form.acceptCharset.split(/[\\s,]+/) : [];
            return {{ ok: true, charsets: [document.characterSet, ...declared].filter(Boolean) }};
        }})()"""
        fill_js = f"""(() => {{{nodes_js}
            uNode.focus();
            uNode.value = {u_val};
            uNode.dispatchEvent(new Event('input', {{ bubbles: true }}));
            uNode.dispatchEvent(new Event('change', {{ bubbles: true }}));
            pNode.focus();
            pNode.value = {p_val};
            pNode.dispatchEvent(new Event('input', {{ bubbles: true }}));
            pNode.dispatchEvent(new Event('change', {{ bubbles: true }}));
            const afterInputOrigin = resolveOrigin();
            if (window.location.origin !== {orig_json} || afterInputOrigin !== {orig_json}) {{
                uNode.value = '';
                pNode.value = '';
                return {{ error: 'action_origin_mismatch:' + afterInputOrigin }};
            }}
            let mutated = false;
            const guardSubmit = (e) => {{
                if (window.location.origin !== {orig_json} || resolveOrigin() !== {orig_json}) {{
                    mutated = true;
                    e.preventDefault();
                    e.stopImmediatePropagation();
                }}
            }};
            window.addEventListener('submit', guardSubmit, true);
            try {{
                sNode.click();
            }} finally {{
                window.removeEventListener('submit', guardSubmit, true);
            }}
            if (mutated || resolveOrigin() !== {orig_json}) {{
                return {{ error: 'action_origin_mismatch' }};
            }}
            return {{ ok: true }};
        }})()"""

        def _checked(res: Any) -> Any:
            if isinstance(res, dict) and isinstance(res.get("error"), str):
                if "origin_mismatch" in res["error"]:
                    raise AuthorityRequired(
                        EffectOperation.auth_login,
                        bound_orig or urlsplit(profile.url).netloc,
                    )
                return None
            return res

        probe = _checked(session.evaluate(tab_id, probe_js))
        if not probe:
            return False
        charsets = probe.get("charsets") if isinstance(probe, dict) else None
        arm_secret(
            session._session_for(tab_id),
            profile.origin,
            profile.password,
            tuple(str(c) for c in charsets) if isinstance(charsets, list) else (),
        )
        try:
            res = _checked(session.evaluate(tab_id, fill_js))
        except AuthorityRequired:
            release_lock(session._session_for(tab_id))
            raise
        ok = bool(res.get("ok")) if isinstance(res, dict) else bool(res)
        if not ok:
            release_lock(session._session_for(tab_id))
        return ok

    return False
