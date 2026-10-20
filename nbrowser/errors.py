import enum


class FailureCode(str, enum.Enum):
    GRANT_REQUIRED = "grant-required"
    CAPTURE_EXPORT_FAILED = "capture_export_failed"
    NO_ACTIVE_SESSION = "no_active_session"
    CONTENT_UNAVAILABLE = "content_unavailable"
    CONTENT_BUDGET_EXCEEDED = "content_budget_exceeded"
    NOT_IMPLEMENTED = "not_implemented"
    HOST_DEPENDENCY_MISSING = "host_dependency_missing"


class InputFailure(str, enum.Enum):
    SELECTOR = "selector"
    QUERY = "query"
    COORDINATE = "coordinate"
    CASSETTE = "cassette"
    OPERATION = "operation"
    CONTENT_REF = "content-ref"


class ClosedFailure(str, enum.Enum):
    LAUNCH = "launch"
    PROTOCOL = "protocol"
    BROWSER_CLOSED = "browser-closed"
    PROFILE = "profile"


class BrowserError(Exception):
    def __init__(self, code: FailureCode | InputFailure | ClosedFailure, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class AuthorityRequired(BrowserError):
    def __init__(self, operation: str, target: str):
        super().__init__(
            FailureCode.GRANT_REQUIRED,
            f"grant-required: {operation} is not authorized for {target}",
        )
        self.operation = operation
        self.target = target


# Oracle wire codes (mcp_server/mod.rs `enum FailureCode`, serde snake_case).
WIRE_CODES: dict[str, str] = {
    "grant-required": "grant_required",
    "capture_export_failed": "provider_unavailable",
    "no_active_session": "no_active_session",
    "content_unavailable": "content_unavailable",
    "content_budget_exceeded": "resource_exhausted",
    # Port-native: a declared tool with no handler is not a bad argument.
    "not_implemented": "not_implemented",
    # Port-native: a host binary the tool shells out to (jq) is absent. The
    # owner installs it (rails/floors.toml [runtime]); a retry changes nothing.
    "host_dependency_missing": "host_dependency_missing",
    # InputFailure/ClosedFailure land on the same envelope rungs as the oracle.
    "operation": "invalid_input",
    "selector": "invalid_input",
    "query": "invalid_input",
    "coordinate": "invalid_input",
    "cassette": "invalid_input",
    "content-ref": "invalid_input",
    "launch": "engine_failure",
    "protocol": "engine_failure",
    "browser-closed": "engine_failure",
    "profile": "engine_failure",
}


def wire_code(code: str) -> str:
    return WIRE_CODES.get(code, "internal")


def failure_envelope(e: BrowserError) -> dict[str, str | bool | None]:
    """FailureEnvelope exactly as the contract serializes it on the wire."""
    envelope: dict[str, str | bool | None] = {
        "ok": False,
        "code": wire_code(e.code.value),
        "taint": "page_derived",
        "rung": "un_witnessed_local",
    }
    if isinstance(e, AuthorityRequired):
        op = e.operation
        envelope["refused_operation"] = op.value if hasattr(op, "value") else str(op)
        envelope["refused_target"] = redact_target_origin(e.target)
    return envelope


def redact_target_origin(url: str) -> str:
    """RedactedTarget::from_url — origin only; path, query, fragment, credentials gone."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return "[invalid-url]"
    host = parts.hostname or ""
    if not host:
        return "[invalid-url]"
    # IPv6 literals keep their brackets on the wire (urlunsplit drops them).
    bracketed = f"[{host}]" if ":" in host else host
    netloc = f"{bracketed}:{parts.port}" if parts.port else bracketed
    return urlunsplit((parts.scheme, netloc, "/", "", ""))
