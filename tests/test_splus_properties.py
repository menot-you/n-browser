"""Executed invariants, with bounded generators and independent result oracles."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_capture import _double_server

from nbrowser.content_custody import FixtureContentResolver
from nbrowser.egress_guard import is_public_safe
from nbrowser.errors import BrowserError, FailureCode, InputFailure


@settings(max_examples=100, derandomize=True, deadline=None)
@given(body=st.binary(max_size=8192))
def test_capture_bytes_have_exactly_one_concurrent_consumer(body: bytes) -> None:
    resolver = FixtureContentResolver()
    resolver.store_bytes("capture:test", body)
    barrier = threading.Barrier(2)

    def consume() -> bytes | FailureCode | InputFailure:
        barrier.wait(timeout=5)
        try:
            return resolver.resolve_once("capture:test")
        except BrowserError as error:
            assert error.code is FailureCode.CONTENT_UNAVAILABLE
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert results.count(body) == 1
    assert results.count(FailureCode.CONTENT_UNAVAILABLE) == 1
    assert not resolver.holds("capture:test")
    assert resolver.store == resolver.kinds == {}


@settings(max_examples=100, derandomize=True, deadline=None)
@given(
    text=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=512),
    page_size=st.integers(min_value=1, max_value=128),
)
def test_text_paging_preserves_unicode_and_consumes_only_the_final_page(
    text: str, page_size: int
) -> None:
    resolver = FixtureContentResolver()
    resolver.store_bytes("artifact:test", text.encode(), kind="text")
    fragments: list[str] = []
    offset = 0
    while True:
        fragment, next_offset, total = resolver.resolve_text_page(
            "artifact:test", offset, page_size
        )
        assert total == len(text)
        assert fragment == text[offset : offset + page_size]
        fragments.append(fragment)
        if next_offset is None:
            assert not resolver.holds("artifact:test")
            break
        assert next_offset == offset + page_size
        assert resolver.holds("artifact:test")
        offset = next_offset
    assert "".join(fragments) == text
    with pytest.raises(BrowserError) as refused:
        resolver.resolve_once("artifact:test")
    assert refused.value.code is FailureCode.CONTENT_UNAVAILABLE


@settings(max_examples=100, derandomize=True, deadline=None)
@given(
    address=st.ip_addresses(v=4).filter(
        lambda ip: ip.is_private and not (ip.is_loopback or ip.is_unspecified)
    ),
    scheme=st.sampled_from(["http", "https"]),
    port=st.integers(min_value=1, max_value=65535),
)
def test_private_ipv4_destinations_never_pass_the_runtime_guard(
    address: object, scheme: str, port: int
) -> None:
    assert not is_public_safe(f"{scheme}://{address}:{port}/")


@settings(max_examples=100, derandomize=True, deadline=None)
@given(secret=st.text(min_size=1, max_size=128))
def test_console_events_never_disclose_page_arguments(secret: str) -> None:
    server, _ = _double_server()
    try:
        server.on_cdp_event(
            {
                "method": "Runtime.consoleAPICalled",
                "params": {
                    "type": "log",
                    "args": [{"type": "string", "value": secret}],
                },
            }
        )
        observed = server.handle_tool_call("nbrowser_console_show", {})
        assert json.loads(json.dumps(observed)) == {
            "entries": [{"level": "info", "category": "log"}],
            "taint": "page_derived",
            "rung": "un_witnessed_local",
        }
    finally:
        server.close()
