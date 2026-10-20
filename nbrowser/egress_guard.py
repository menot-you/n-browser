import enum
import ipaddress
import socket
from collections.abc import Sequence
from urllib.parse import urlparse

from .errors import BrowserError, FailureCode


class ActivationMode(str, enum.Enum):
    FIXTURE_ONLY = "fixture_only"
    LOCAL_DOM_EXCEPTION = "local_dom_exception"

    def allows_local_activation(self) -> bool:
        return self is ActivationMode.LOCAL_DOM_EXCEPTION


def bare_host(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    # strip trailing dot
    host = host.removesuffix(".")
    # brackets are already stripped by urlparse.hostname for IPv6 usually, but let's be safe:
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def is_loopback_host(bare: str) -> bool:
    if bare.lower() == "localhost" or bare == "0.0.0.0" or bare == "::":
        return True
    try:
        ip = ipaddress.ip_address(bare)
        if isinstance(ip, ipaddress.IPv4Address):
            return ip.is_loopback or ip.is_unspecified
        elif isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped:
                mapped = ip.ipv4_mapped
                return mapped.is_loopback or mapped.is_unspecified
            return ip.is_loopback or ip.is_unspecified
    except ValueError:
        pass
    return False


def is_private_host(bare: str) -> bool:
    if bare == "169.254.169.254":
        return True

    try:
        ip = ipaddress.ip_address(bare)
        if isinstance(ip, ipaddress.IPv4Address):
            # Check for CGNAT 100.64.0.0/10
            is_cgnat = ipaddress.ip_network("100.64.0.0/10", strict=False)
            if ip in is_cgnat:
                return True
            return ip.is_private or ip.is_link_local
        elif isinstance(ip, ipaddress.IPv6Address):
            # Check for ULA (fc00::/7) and link-local (fe80::/10)
            if ip.is_private or ip.is_link_local:
                return True
            if ip.ipv4_mapped:
                mapped = ip.ipv4_mapped
                is_cgnat = ipaddress.ip_network("100.64.0.0/10", strict=False)
                if mapped in is_cgnat:
                    return True
                return mapped.is_private or mapped.is_link_local
    except ValueError:
        pass
    return False


def is_suspicious_hostname(bare: str) -> bool:
    lower = bare.lower()
    suspicious_exact = {
        "localtest.me",
        "lvh.me",
        "nip.io",
        "sslip.io",
        "xip.io",
        "metadata.google.internal",
        "metadata.goog",
    }
    if lower in suspicious_exact:
        return True

    suffixes = (
        ".nip.io",
        ".sslip.io",
        ".localtest.me",
        ".lvh.me",
        ".xip.io",
        ".internal",
    )
    return lower.endswith(suffixes)


def is_public_safe(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    bare = bare_host(url)
    if not bare:
        return False

    if is_loopback_host(bare):
        return True

    return not (is_private_host(bare) or is_suspicious_hostname(bare))


def is_public_safe_ws(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss", "http", "https"):
        return False

    bare = bare_host(url)
    if not bare:
        return False

    if is_loopback_host(bare):
        return True

    return not (is_private_host(bare) or is_suspicious_hostname(bare))


def is_cross_origin_internal(final_url: str, bound_origin: str) -> bool:
    f_parsed = urlparse(final_url)
    b_parsed = urlparse(bound_origin)

    # same origin check
    if (
        f_parsed.scheme == b_parsed.scheme
        and f_parsed.hostname == b_parsed.hostname
        and f_parsed.port == b_parsed.port
    ):
        return False

    final_bare = bare_host(final_url)
    if not final_bare or not is_loopback_host(final_bare):
        return False

    bound_bare = bare_host(bound_origin)
    if not bound_bare:
        return True

    return not is_loopback_host(bound_bare)


def resolve_admitted(
    address: tuple[str, int],
) -> Sequence[
    tuple[
        int,
        int,
        int,
        str,
        tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
    ]
]:
    """Resolve the host and check every destination address."""
    host, port = address
    host = host.removesuffix(".")
    loopback = is_loopback_host(host)
    if is_suspicious_hostname(host) or (is_private_host(host) and not loopback):
        raise BrowserError(FailureCode.GRANT_REQUIRED, "Connection target refused")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError("No destination address")
    for family, _, _, _, target in answers:
        ip = ipaddress.ip_address(target[0])
        if family not in (socket.AF_INET, socket.AF_INET6) or not (
            (ip.is_global and not ip.is_multicast and not loopback)
            or (loopback and is_loopback_host(str(ip)))
        ):
            raise BrowserError(FailureCode.GRANT_REQUIRED, "DNS destination refused")
    return answers


def connect_admitted(
    address: tuple[str, int],
    timeout: float = 12.0,
    source_address: tuple[str, int] | None = None,
) -> socket.socket:
    """Check all DNS answers. Connect to a checked numeric address."""
    answers = resolve_admitted(address)
    last_error: OSError | None = None
    for family, kind, protocol, _, target in answers:
        connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(timeout)
            if source_address is not None:
                connection.bind(source_address)
            connection.connect(target)
            return connection
        except OSError as error:
            connection.close()
            last_error = error
    assert last_error is not None
    raise last_error
