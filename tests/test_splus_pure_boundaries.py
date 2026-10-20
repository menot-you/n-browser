"""Pure authority, destination, and redaction boundary observations."""

import pytest

from nbrowser.egress_guard import (
    bare_host,
    is_cross_origin_internal,
    is_loopback_host,
    is_private_host,
    is_public_safe,
    is_suspicious_hostname,
)
from nbrowser.errors import (
    AuthorityRequired,
    BrowserError,
    failure_envelope,
    redact_target_origin,
)
from nbrowser.network import HttpMethod, NetworkEntry
from nbrowser.sanitize import (
    redact_css_custom_property_value,
    redact_svg_paint_reference,
    redact_url_keep_path,
    redact_url_reference_keep_fragment,
)


@pytest.mark.parametrize(
    "host,loopback,private",
    [
        ("::1", True, True),
        ("::ffff:127.0.0.1", True, True),
        ("::ffff:0.0.0.0", True, True),
        ("::ffff:100.64.10.1", False, True),
        ("::ffff:8.8.8.8", False, False),
        ("2606:4700:4700::1111", False, False),
        ("fe80::1", False, True),
        ("fc00::1", False, True),
    ],
)
def test_ipv6_classification_is_pure(host: str, loopback: bool, private: bool) -> None:
    assert is_loopback_host(host) is loopback
    assert is_private_host(host) is private


@pytest.mark.parametrize("url", ["/relative", "https:///missing", "file:///tmp/page"])
def test_destination_without_public_origin_refuses(url: str) -> None:
    assert bare_host(url) is None
    assert not is_public_safe(url)


@pytest.mark.parametrize(
    "host",
    [
        "LOCALTEST.ME",
        "lvh.me",
        "nip.io",
        "sslip.io",
        "xip.io",
        "metadata.google.internal",
        "metadata.goog",
    ],
)
def test_rebinding_hostnames_refuse_without_dns(host: str) -> None:
    assert is_suspicious_hostname(host)
    assert not is_public_safe("https://" + host)


@pytest.mark.parametrize(
    "final,bound,expected",
    [
        ("http://localhost/a", "https://public.test", True),
        ("http://localhost/a", "/relative", True),
        ("https://public.test/a", "http://localhost", False),
        ("http://localhost:9/a", "http://localhost:8", False),
        ("/relative", "https://public.test", False),
    ],
)
def test_cross_origin_internal_classification(
    final: str, bound: str, expected: bool
) -> None:
    assert is_cross_origin_internal(final, bound) is expected


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "https://user:secret@fixture.test:8443/path?q=secret#secret",
            "https://fixture.test:8443/",
        ),
        ("https://[::1]:8443/path", "https://[::1]:8443/"),
        ("/relative", "[invalid-url]"),
        ("https://[", "[invalid-url]"),
    ],
)
def test_authority_envelope_discloses_only_origin(url: str, expected: str) -> None:
    assert redact_target_origin(url) == expected
    assert failure_envelope(AuthorityRequired("click", url)) == {
        "ok": False,
        "code": "grant_required",
        "taint": "page_derived",
        "rung": "un_witnessed_local",
        "refused_operation": "click",
        "refused_target": expected,
    }


@pytest.mark.parametrize("scheme", ["file", "data", "ftp"])
def test_network_metadata_refuses_non_http(scheme: str) -> None:
    with pytest.raises(BrowserError):
        NetworkEntry.from_observation(HttpMethod.GET, scheme + "://fixture.test/a")


def test_network_metadata_preserves_present_zero_values() -> None:
    assert NetworkEntry.from_observation(
        HttpMethod.POST, "https://fixture.test/a", 0, 0
    ).to_dict() == {
        "method": "post",
        "location": "https://fixture.test/a",
        "status": 0,
        "encoded_bytes": 0,
    }


@pytest.mark.parametrize(
    "value,expected",
    [
        ("[inline-data-redacted]", "[inline-data-redacted]"),
        ("data:text/plain,secret", "[inline-data-redacted]"),
        ("https://[", "[invalid-url]"),
        ("https:///missing", "[invalid-url]"),
    ],
)
def test_url_unusable_or_inline_input_is_closed(value: str, expected: str) -> None:
    assert redact_url_keep_path(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (r"bad\path", "[invalid-url]"),
        ("//[", "[invalid-url]"),
        ("//fixture.test/a", "//fixture.test/a"),
        ("https://fixture.test/a", "https://fixture.test/a"),
        ("#paint", "#paint"),
    ],
)
def test_reference_url_contract(value: str, expected: str) -> None:
    assert redact_url_reference_keep_fragment(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("url(DATA:secret)", "[inline-data-redacted]"),
        (r"bad\path", "[invalid-url]"),
        ("/*comment*/red", "[invalid-url]"),
        ("*/red", "[invalid-url]"),
        ("https://fixture.test/a", "https://fixture.test/a"),
        ("//fixture.test/a", "//fixture.test/a"),
        ("12px", "12px"),
    ],
)
def test_css_custom_property_reference_contract(value: str, expected: str) -> None:
    assert redact_css_custom_property_value(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (r"bad\path", "[invalid-svg-iri]"),
        ("/*paint*/red", "[invalid-svg-iri]"),
        ("url('#paint')", "url(#paint)"),
        ("URL(https://fixture.test/a)", "url(https://fixture.test/a)"),
        ("url(#paint", "[invalid-svg-iri]"),
        ("https://fixture.test/a", "[invalid-svg-iri]"),
        ("a@b", "[invalid-svg-iri]"),
        ("red", "red"),
    ],
)
def test_svg_paint_reference_contract(value: str, expected: str) -> None:
    assert redact_svg_paint_reference(value) == expected
