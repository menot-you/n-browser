import re
import secrets
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

INLINE_DATA_REDACTED = "[inline-data-redacted]"
DIAGNOSTIC_CHARS = 512
_BOUNDARY_NONCE: str | None = None


def get_boundary_nonce() -> str:
    """Per-process 128-bit CSPRNG nonce so page content cannot predict or spoof
    the content boundary delimiter."""
    global _BOUNDARY_NONCE
    if _BOUNDARY_NONCE is None:
        _BOUNDARY_NONCE = secrets.token_hex(16)
    return _BOUNDARY_NONCE


def wrap_content_boundaries(content: str, origin: str) -> str:
    """Wrap page content in CSPRNG-nonced boundary markers."""
    nonce = get_boundary_nonce()
    safe_origin = redact_url_keep_path(origin) if origin else "unknown"
    return (
        f"--- NBROWSER_PAGE_CONTENT nonce={nonce} origin={safe_origin} ---\n"
        f"{content}\n"
        f"--- END_NBROWSER_PAGE_CONTENT nonce={nonce} ---"
    )


_SECRET_KEYS = (
    "token",
    "session",
    "password",
    "passwd",
    "pass",
    "pw",
    "pwd",
    "senha",
    "cookie",
    "secret",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
    "authorization",
    "bearer",
    "key",
    "pat",
    "code",
    "sig",
    "signature",
    "otp",
    "totp",
    "passphrase",
    "credential",
    "credentials",
    "userinfo",
    "pin",
)

SECRET_PREFIX_PATTERNS = re.compile(
    r"^(?:(?:sk|ghp|gho|ghu|ghs|ghr|github_pat|github|glpat|xoxb|xoxp|xoxr|npm|live|test|sec|secret|key|token|pat)[-_][0-9a-zA-Z]+|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"
)


_UNAMBIGUOUS_SECRET_SUBSTRINGS = (
    "password",
    "passwd",
    "senha",
    "secret",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
    "authorization",
)


def _unquote_fixed_point(val: str, max_passes: int = 32) -> str:
    """Iteratively percent-decode to a fixed point.

    If the bound is exhausted without reaching a fixed point, returns '[invalid-url]'
    to fail closed.
    """
    cur = val
    for _ in range(max_passes):
        nxt = unquote(cur)
        if nxt == cur:
            return cur
        cur = nxt
    return "[invalid-url]"


def is_secret_token(val: str) -> bool:
    """Check if a string matches known secret token prefixes, key patterns or secret keywords."""
    if not val:
        return False
    val_clean = _unquote_fixed_point(val).strip().lower()
    if val_clean == "[invalid-url]" or "[invalid-url]" in val_clean:
        return True
    if any(k in val_clean for k in _UNAMBIGUOUS_SECRET_SUBSTRINGS):
        return True
    sub_words = re.findall(r"[a-zA-Z0-9]+", val_clean)
    if any(k in sub_words for k in _SECRET_KEYS):
        return True
    if SECRET_PREFIX_PATTERNS.match(_unquote_fixed_point(val).strip()):
        return True
    if SECRET_PREFIX_PATTERNS.match(val_clean):
        return True
    for p in (
        "sk-",
        "sk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxr-",
        "npm_",
        "akia",
        "asia",
    ):
        if p in val_clean:
            return True
    return False


def _is_secret_pattern(k: str, max_passes: int = 32) -> bool:
    cur = k.strip()
    for _ in range(max_passes):
        clean = cur.strip()
        if SECRET_PREFIX_PATTERNS.match(clean) or SECRET_PREFIX_PATTERNS.match(
            clean.lower()
        ):
            return True
        clean_lower = clean.lower()
        for p in (
            "sk-",
            "sk_",
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "github_pat_",
            "glpat-",
            "xoxb-",
            "xoxp-",
            "xoxr-",
            "npm_",
            "akia",
            "asia",
        ):
            if p in clean_lower:
                return True
        nxt = unquote(cur)
        if nxt == cur:
            return False
        cur = nxt
    # Bound exhausted without reaching fixed point -> fail closed as True (redact)
    return True


def _redact_param_string(qs: str) -> str:
    if not qs:
        return qs
    delim = ";" if (";" in qs and "&" not in qs) else "&"
    if delim == "&":
        params = parse_qsl(qs, keep_blank_values=True)
        if not params:
            return qs
        safe = []
        for k, v in params:
            lower_k = _unquote_fixed_point(k).lower()
            dec_v = _unquote_fixed_point(v)
            k_has_assignment = "=" in lower_k or ":" in lower_k
            sub_k = (
                lower_k.partition("=")[0]
                if "=" in lower_k
                else lower_k.partition(":")[0]
            )
            k_is_secret = (
                _is_secret_pattern(k)
                or _is_secret_pattern(lower_k)
                or any(sec_key in lower_k for sec_key in _SECRET_KEYS)
                or any(sec_key in lower_k for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
                or "auth" in lower_k
                or is_secret_token(lower_k)
            )
            if (
                (
                    k_has_assignment
                    and (
                        any(sec_key in sub_k for sec_key in _SECRET_KEYS)
                        or any(
                            sec_key in sub_k
                            for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                        )
                        or is_secret_token(lower_k)
                    )
                )
                or (not v and k_is_secret)
                or _is_secret_pattern(k)
                or _is_secret_pattern(lower_k)
            ):
                safe.append(("[redacted]", "[redacted]"))
            elif (
                any(sec_key in lower_k for sec_key in _SECRET_KEYS)
                or any(sec_key in lower_k for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
                or "auth" in lower_k
                or is_secret_token(dec_v)
            ):
                safe.append((k, "[redacted]"))
            else:
                safe.append((k, v))
        return urlencode(safe)
    # matrix parameters with ';'
    parts = qs.split(";")
    safe_parts: list[str] = []
    for part in parts:
        if not part:
            safe_parts.append("")
            continue
        k, sep, v = part.partition("=")
        dec_k = _unquote_fixed_point(k).lower()
        dec_v = _unquote_fixed_point(v)
        k_has_assignment = "=" in dec_k or ":" in dec_k
        sub_k = dec_k.partition("=")[0] if "=" in dec_k else dec_k.partition(":")[0]
        k_is_secret = (
            _is_secret_pattern(k)
            or _is_secret_pattern(dec_k)
            or any(sec_key in dec_k for sec_key in _SECRET_KEYS)
            or any(sec_key in dec_k for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
            or "auth" in dec_k
            or is_secret_token(dec_k)
        )
        if (
            (
                k_has_assignment
                and (
                    any(sec_key in sub_k for sec_key in _SECRET_KEYS)
                    or any(
                        sec_key in sub_k for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                    )
                )
            )
            or (not sep and k_is_secret)
            or _is_secret_pattern(k)
            or _is_secret_pattern(dec_k)
        ):
            safe_parts.append("[redacted]=[redacted]" if sep else "[redacted]")
        elif (
            any(sec_key in dec_k for sec_key in _SECRET_KEYS)
            or any(sec_key in dec_k for sec_key in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
            or "auth" in dec_k
            or is_secret_token(dec_v)
        ):
            safe_parts.append(f"{k}=[redacted]" if sep else "[redacted]")
        else:
            safe_parts.append(part)
    return ";".join(safe_parts)


def redact_url_keep_path(value: str) -> str:
    if value == INLINE_DATA_REDACTED:
        return value

    try:
        parsed = urlparse(value)
    except ValueError:
        return "[invalid-url]"

    if parsed.scheme == "data":
        return INLINE_DATA_REDACTED

    is_relative = (
        not parsed.scheme and value.startswith("/") and not value.startswith("//")
    )
    if not is_relative:
        if parsed.scheme not in ("http", "https"):
            return "[invalid-url]"

        host_str = (parsed.hostname or "").strip()
        if not host_str:
            return "[invalid-url]"

        try:
            if parsed.port is not None:
                port_val = int(parsed.port)
                if ":" in host_str:
                    netloc = f"[{host_str}]:{port_val}"
                else:
                    netloc = f"{host_str}:{port_val}"
            else:
                netloc = f"[{host_str}]" if ":" in host_str else host_str
        except ValueError, TypeError:
            return "[invalid-url]"

        if not netloc:
            return "[invalid-url]"
    else:
        netloc = ""

    path_segments = parsed.path.split("/")
    safe_segments: list[str] = []
    prev_seg_is_secret_key = False
    for seg in path_segments:
        dec_seg = _unquote_fixed_point(seg)
        if is_secret_token(dec_seg) or prev_seg_is_secret_key:
            safe_segments.append("[redacted]")
        else:
            safe_segments.append(seg)
        clean_seg = dec_seg.strip().lower()
        prev_seg_is_secret_key = (
            clean_seg in _SECRET_KEYS
            or clean_seg in _UNAMBIGUOUS_SECRET_SUBSTRINGS
            or "password" in clean_seg
            or "passwd" in clean_seg
            or "token" in clean_seg
            or "secret" in clean_seg
        )
    safe_path = "/".join(safe_segments)

    safe_params = _redact_param_string(parsed.params) if parsed.params else ""
    safe_query = _redact_param_string(parsed.query)

    safe_fragment = parsed.fragment
    if safe_fragment:
        if "/" in safe_fragment or "?" in safe_fragment:
            frag_path, has_q, frag_query = safe_fragment.partition("?")
            frag_segs = frag_path.split("/")
            safe_frag_segs: list[str] = []
            prev_frag_is_sec = False
            for s in frag_segs:
                dec_s = _unquote_fixed_point(s)
                if is_secret_token(dec_s) or prev_frag_is_sec:
                    safe_frag_segs.append("[redacted]")
                else:
                    safe_frag_segs.append(s)
                clean_s = dec_s.strip().lower()
                prev_frag_is_sec = (
                    clean_s in _SECRET_KEYS
                    or clean_s in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                    or "password" in clean_s
                    or "passwd" in clean_s
                    or "token" in clean_s
                    or "secret" in clean_s
                )
            safe_frag_path = "/".join(safe_frag_segs)
            if has_q:
                safe_fragment = f"{safe_frag_path}?{_redact_param_string(frag_query)}"
            else:
                safe_fragment = safe_frag_path
        elif "=" in safe_fragment or ";" in safe_fragment:
            safe_fragment = _redact_param_string(safe_fragment)
        elif is_secret_token(unquote(safe_fragment)):
            safe_fragment = "[redacted]"

    # stripped userinfo, preserved path, safe matrix params and safe fragment
    safe_parsed = (
        parsed.scheme,
        netloc,
        safe_path,
        safe_params,
        safe_query,
        safe_fragment,
    )
    return urlunparse(safe_parsed)


def redact_asset_url_keep_path(value: str) -> str:
    val = value.strip()
    if val == INLINE_DATA_REDACTED:
        return INLINE_DATA_REDACTED
    if val.startswith("data:"):
        return INLINE_DATA_REDACTED
    try:
        parsed = urlparse(val)
    except ValueError:
        return "[invalid-url]"
    if parsed.scheme not in ("http", "https"):
        return "[invalid-url]"
    return redact_url_keep_path(val)


def redact_url_reference_keep_fragment(value: str) -> str:
    val = value.strip()
    if "\\" in val:
        return "[invalid-url]"
    if val.startswith("//"):
        redacted = redact_asset_url_keep_path(f"https:{val}")
        return (
            redacted.removeprefix("https:")
            if redacted != "[invalid-url]"
            else "[invalid-url]"
        )
    if val.startswith(("http://", "https://")):
        return redact_asset_url_keep_path(val)
    return redact_diagnostic(val)


def redact_css_custom_property_value(value: str) -> str:
    val = value.strip()
    if "data:" in val.lower():
        return INLINE_DATA_REDACTED
    if "\\" in val or "/*" in val or "*/" in val:
        return "[invalid-url]"
    if val.startswith(("http://", "https://")):
        return redact_asset_url_keep_path(val)
    if val.startswith("//"):
        return redact_url_reference_keep_fragment(val)
    return redact_diagnostic(val)


def redact_svg_paint_reference(value: str) -> str:
    val = value.strip()
    if "\\" in val or "/*" in val or "*/" in val:
        return "[invalid-svg-iri]"
    if val.lower().startswith("url("):
        inner = val[4:].lstrip()
        if inner.endswith(")"):
            inner = inner[:-1].strip("'\"")
            return f"url({redact_url_reference_keep_fragment(inner)})"
        return "[invalid-svg-iri]"
    if "://" in val or "@" in val:
        return "[invalid-svg-iri]"
    return redact_diagnostic(val)


def _ends_with_unescaped_quote(text: str, q: str) -> bool:
    if not text.endswith(q):
        return False
    if text == q:
        return True
    slashes = 0
    idx = len(text) - 2
    while idx >= 0 and text[idx] == "\\":
        slashes += 1
        idx -= 1
    return slashes % 2 == 0


def _redact_value_words(raw_words: list[str], start: int) -> tuple[list[str], int]:
    """Redact the value words from start: track an open quote and stop after
    its unescaped close; past the first value word, stop at a break word."""
    redacted: list[str] = []
    j = start
    quote_delim: str | None = None
    while j < len(raw_words):
        w_next = raw_words[j]
        redacted.append("[REDACTED]")
        if not quote_delim:
            q_idx = min(
                (w_next.find(c) for c in ('"', "'", "`") if c in w_next),
                default=-1,
            )
            if q_idx >= 0:
                quote_delim = w_next[q_idx]
                rem = w_next[q_idx:]
                is_closed = (
                    len(rem) >= 2
                    and rem.rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?").endswith(quote_delim)
                    and not rem.rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?").endswith(
                        f"\\{quote_delim}"
                    )
                )
                if is_closed:
                    quote_delim = None
                    j += 1
                    break
                j += 1
                continue
            w_next_clean = w_next.lower().strip("`'\"([{<)]}>:;,.*_~#$@!%^&+=|\\/?")
            if j > start and (
                w_next_clean in ("and", "then", "after", "next", "e", "depois")
                or "=" in w_next
                or (":" in w_next and not w_next.startswith("http"))
            ):
                break
        else:
            w_cand = w_next.rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?")
            if _ends_with_unescaped_quote(w_cand, quote_delim):
                quote_delim = None
                j += 1
                break
        j += 1
    return redacted, j


def redact_diagnostic(value: str, cap: int | None = DIAGNOSTIC_CHARS) -> str:
    """Prose stays readable; key=value secrets, secret header labels and their
    values, Bearer tokens, and known secret tokens redact."""
    bounded = "".join(c for c in value if ord(c) >= 32 or c == "\n")
    if cap is not None:
        bounded = bounded[:cap]

    lines = bounded.split("\n")
    redacted_lines: list[str] = []
    for line in lines:
        if not line.strip():
            redacted_lines.append(line)
            continue
        raw_words = line.split()
        words: list[str] = []
        i = 0
        while i < len(raw_words):
            word = raw_words[i]
            lower = word.lower()
            stripped = lower.rstrip(":=")
            clean_word = lower.strip("`'\"([{<)]}>:;,.*_~#$@!%^&+=|\\/?")

            # 1. Header format: "Authorization: ..."
            has_delim = (
                ":" in lower
                or "=" in lower
                or (i + 1 < len(raw_words) and raw_words[i + 1] in (":", "="))
            )
            is_auth_header = (
                clean_word == "authorization" and has_delim
            ) or lower.startswith(("authorization:", "authorization="))
            if is_auth_header:
                words.append("[REDACTED]")
                if i + 1 < len(raw_words) and raw_words[i + 1] in (":", "="):
                    words.append("[REDACTED]")
                    i += 1
                j = i + 1
                while j < len(raw_words):
                    words.append("[REDACTED]")
                    j += 1
                i = j
                continue

            # 2. Secret headers like Set-Cookie:, Cookie:, etc. (multiple subsequent cookie tokens)
            is_cookie_header = (
                clean_word in ("cookie", "set-cookie") and has_delim
            ) or lower.startswith(("set-cookie:", "set-cookie=", "cookie:", "cookie="))
            if is_cookie_header:
                words.append("[REDACTED]")
                if i + 1 < len(raw_words) and raw_words[i + 1] in (":", "="):
                    words.append("[REDACTED]")
                    i += 1
                j = i + 1
                while j < len(raw_words):
                    words.append("[REDACTED]")
                    j += 1
                i = j
                continue

            # 3. Spaced or hybrid assignment: e.g. "password = hunter2" or "password =\"correct..."
            is_secret_key = (
                clean_word in _SECRET_KEYS
                or clean_word in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                or any(sec in clean_word for sec in _SECRET_KEYS)
                or any(sec in clean_word for sec in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
            )
            if is_secret_key and i + 1 < len(raw_words):
                next_w = raw_words[i + 1]
                is_op = next_w in ("=", ":", "->", "is", "equals")
                is_hybrid = next_w.startswith(("=", ":")) and len(next_w) > 1
                if is_op and i + 2 < len(raw_words):
                    words.append(word)
                    words.append(next_w)
                    redacted, j = _redact_value_words(raw_words, i + 2)
                    words.extend(redacted)
                    i = j
                    continue
                elif is_hybrid:
                    words.append(word)
                    words.append(next_w[:1])
                    raw_words[i + 1] = next_w[1:]
                    redacted, j = _redact_value_words(raw_words, i + 1)
                    words.extend(redacted)
                    i = j
                    continue

            # 4. Key= or Key: with value in next word: e.g. "password= hunter2" or "token: secret123"
            if (
                lower.endswith(("=", ":"))
                or lower.rstrip("`'\"([{<)]}>").endswith(("=", ":"))
            ) and (
                clean_word in _SECRET_KEYS
                or clean_word in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                or stripped in _SECRET_KEYS
                or stripped in _UNAMBIGUOUS_SECRET_SUBSTRINGS
            ):
                words.append("[REDACTED]")
                redacted, j = _redact_value_words(raw_words, i + 1)
                words.extend(redacted)
                i = j
                continue

            # 5. Key:value or key=value attached
            has_attached_secret = False
            k_part = ""
            v_part = ""
            if "=" in lower:
                k_part, _, v_part = lower.partition("=")
            elif ":" in lower and not lower.startswith("http"):
                k_part, _, v_part = lower.partition(":")
            if k_part:
                k_clean = k_part.strip("`'\"([{<)]}>:;,.*_~#$@!%^&+=|\\/?")
                if (
                    k_clean in _SECRET_KEYS
                    or k_clean in _UNAMBIGUOUS_SECRET_SUBSTRINGS
                    or any(sec in k_clean for sec in _SECRET_KEYS)
                    or any(sec in k_clean for sec in _UNAMBIGUOUS_SECRET_SUBSTRINGS)
                ):
                    has_attached_secret = True
            if not has_attached_secret:
                for key in _SECRET_KEYS:
                    if f"{key}=" in lower or f"{key}:" in lower:
                        has_attached_secret = True
                        v_part = (
                            lower.partition("=")[2]
                            if "=" in lower
                            else lower.partition(":")[2]
                        )
                        break
            if has_attached_secret:
                words.append("[REDACTED]")
                val_part = v_part
                q_idx = min(
                    (val_part.find(c) for c in ('"', "'", "`") if c in val_part),
                    default=-1,
                )
                if q_idx >= 0:
                    q = val_part[q_idx]
                    rem = val_part[q_idx:]
                    is_closed = (
                        len(rem) >= 2
                        and rem.rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?").endswith(q)
                        and not rem.rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?").endswith(
                            f"\\{q}"
                        )
                    )
                    if not is_closed:
                        j = i + 1
                        while j < len(raw_words):
                            words.append("[REDACTED]")
                            w_cand = raw_words[j].rstrip(")]}>:;,.*_~#$@!%^&+=|\\/?")
                            if _ends_with_unescaped_quote(w_cand, q):
                                j += 1
                                break
                            j += 1
                        i = j
                        continue
                i += 1
                continue

            # 6. Bearer token
            if clean_word == "bearer" or lower.startswith("bearer"):
                words.append("[REDACTED]")
                if i + 1 < len(raw_words):
                    words.append("[REDACTED]")
                    i += 2
                    continue
                i += 1
                continue

            # 7. Bare secret tokens
            if (
                is_secret_token(word) or is_secret_token(clean_word)
            ) and clean_word not in ("authorization", "cookie", "set-cookie"):
                words.append("[REDACTED]")
                i += 1
                continue

            words.append(word)
            i += 1
        redacted_lines.append(" ".join(words))
    return "\n".join(redacted_lines)
