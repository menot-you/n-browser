"""Provider lanes: merge core (Canonical own test semantics), allowlist, and the door."""

import json
import os
import sys

import pytest
from test_door import drive_door

from nbrowser.providers import firecrawl, minimax, tavily, zai
from nbrowser.providers.base import (
    HttpResponse,
    ProviderKey,
    ProviderTransportError,
    SearchHit,
    bearer_post,
    validate_provider_url,
)
from nbrowser.providers.merge import (
    SNIPPET_CAP,
    clamp_snippet,
    fan_out_search,
    merge_search,
    url_key,
)

PORT_CMD = [
    sys.executable,
    "-c",
    "import sys; from nbrowser.cli import main; sys.exit(main())",
    "mcp",
    "serve",
]


def hit(url: str, title: str) -> SearchHit:
    return SearchHit(title=title, url=url)


def test_url_key_strips_fragment_and_trailing_slash() -> None:
    assert url_key("https://x.com/a#frag") == "https://x.com/a"
    assert url_key("https://x.com/a/") == "https://x.com/a"
    assert url_key("https://x.com/a///") == "https://x.com/a"


def test_snippet_clamp_appends_ellipsis_at_byte_boundary() -> None:
    big = "a" * (SNIPPET_CAP + 100)
    out = clamp_snippet(big)
    assert out.endswith("…")
    assert len(out.encode("utf-8")) == SNIPPET_CAP + len("…".encode())
    prefix = "a" * (SNIPPET_CAP - 1)
    crab = prefix + "🦀extra"
    out = clamp_snippet(crab)
    assert out.endswith("…")
    assert out.startswith(prefix)


def test_merge_dedupes_by_url_and_tracks_providers() -> None:
    z = [hit("https://x.com/a", "Z a")]
    m = [hit("https://x.com/a", "M a")]
    out = merge_search([z, m], ["zai", "minimax"], 10)
    assert len(out) == 1
    assert out[0].providers == ["zai", "minimax"]
    assert out[0].title == "Z a"


def test_merge_enforces_max_hits_cap_and_interleaves() -> None:
    l1 = [
        hit("https://x.com/1", "1"),
        hit("https://x.com/2", "2"),
        hit("https://x.com/3", "3"),
    ]
    l2 = [hit("https://x.com/4", "4"), hit("https://x.com/5", "5")]
    out = merge_search([l1, l2], ["lane1", "lane2"], 3)
    assert [h.url for h in out] == [
        "https://x.com/1",
        "https://x.com/4",
        "https://x.com/2",
    ]


def test_allowlist_refuses_before_any_socket() -> None:
    assert validate_provider_url("http://api.tavily.com/search") == (
        "unapproved_scheme: only https is allowed"
    )
    assert validate_provider_url("https://evil.example.com/x") == (
        "unapproved_host: evil.example.com"
    )
    key = ProviderKey.from_value("k" * 12)
    assert key is not None
    # A loopback stand-in provider host is refused by the allowlist itself.
    with pytest.raises(ProviderTransportError) as exc_info:
        bearer_post("http://127.0.0.1:1", "/search", key, {"q": "x"})
    assert exc_info.value.args[0] == "unapproved_scheme: only https is allowed"


def test_provider_key_bounds_and_redaction() -> None:
    assert ProviderKey.from_value("short") is None
    assert ProviderKey.from_value("k" * 5000) is None
    key = ProviderKey.from_value("k" * 12)
    assert key is not None
    assert "k" not in repr(key)
    assert str(key) == "[redacted]"


def test_parsers_pin_semantics() -> None:
    hits = tavily.parse_tavily_hits(
        '{"results":[{"url":"https://e.com/1","title":"T","content":"c","published_date":"2026-08-22"}]}'
    )
    assert hits[0].url == "https://e.com/1"
    assert hits[0].date == "2026-08-22"

    with pytest.raises(ProviderTransportError):
        tavily.parse_tavily_hits('{"nope": 1}')

    fh = firecrawl.parse_firecrawl_hits(
        '{"data":{"web":[{"url":"https://e.com/2","description":"d"}]}}'
    )
    assert fh[0].url == "https://e.com/2"
    assert fh[0].snippet == "d"


def test_fan_out_without_keys_reports_skipped_lanes() -> None:
    for env in (
        "ZAI_API_KEY",
        "MINIMAX_API_KEY",
        "TAVILY_API_KEY",
        "FIRECRAWL_API_KEY",
    ):
        os.environ.pop(env, None)
    hits, lanes = fan_out_search("anything", 5)
    assert hits == []
    assert len(lanes) == 4
    assert all(l.status == "skipped_no_key" for l in lanes)


def test_door_search_refusals() -> None:
    lines = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                }
            ),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_web_search",
                        "arguments": {"query": "pytest"},
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "nbrowser_web_search", "arguments": {}},
                }
            ),
        ]
    )
    responses = drive_door(
        lines.split("\n"),
        drop=("ZAI_API_KEY", "MINIMAX_API_KEY", "TAVILY_API_KEY", "FIRECRAWL_API_KEY"),
    )

    # search without keys: valid response, 4 skipped lanes, zero hits.
    result = responses[2]["result"]
    assert result.get("isError") is not True
    payload = json.loads(result["content"][0]["text"])
    assert payload["hits"] == []
    assert len(payload["lanes"]) == 4
    assert all(l["status"] == "skipped_no_key" for l in payload["lanes"])

    # search without a query: typed refusal.
    assert responses[3]["result"]["isError"] is True
    envelope = json.loads(responses[3]["result"]["content"][0]["text"])
    assert envelope["code"] == "invalid_input"


def test_door_search_null_max_results_uses_the_default() -> None:
    lines = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                }
            ),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nbrowser_web_search",
                        "arguments": {"query": "pytest", "max_results": None},
                    },
                }
            ),
        ]
    )
    responses = drive_door(
        lines.split("\n"),
        drop=("ZAI_API_KEY", "MINIMAX_API_KEY", "TAVILY_API_KEY", "FIRECRAWL_API_KEY"),
    )

    # An advertised default must not answer as an untyped internal error.
    result = responses[2]["result"]
    assert result.get("isError") is not True
    payload = json.loads(result["content"][0]["text"])
    assert payload["hits"] == []
    assert len(payload["lanes"]) == 4
    assert all(l["status"] == "skipped_no_key" for l in payload["lanes"])


def test_parsers_refuse_non_string_snippet() -> None:
    with pytest.raises(ProviderTransportError):
        tavily.parse_tavily_hits(
            '{"results":[{"url":"https://e.com/a","content":{"nested":1}}]}'
        )
    with pytest.raises(ProviderTransportError):
        zai.parse_search_prime_hits(
            '{"results":[{"url":"https://e.com/a","snippet":{"nested":1}}]}'
        )
    with pytest.raises(ProviderTransportError):
        minimax.parse_minimax_hits(
            '{"data":[{"link":"https://e.com/a","content":{"nested":1}}]}', 10
        )
    with pytest.raises(ProviderTransportError):
        firecrawl.parse_firecrawl_hits(
            '{"data":[{"url":"https://e.com/a","description":{"nested":1}}]}'
        )


def test_parsers_refuse_non_string_title() -> None:
    with pytest.raises(ProviderTransportError):
        tavily.parse_tavily_hits('{"results":[{"url":"https://e.com/a","title":5}]}')
    with pytest.raises(ProviderTransportError):
        zai.parse_search_prime_hits('{"results":[{"url":"https://e.com/a","title":5}]}')
    with pytest.raises(ProviderTransportError):
        minimax.parse_minimax_hits(
            '{"data":[{"link":"https://e.com/a","title":5}]}', 10
        )
    with pytest.raises(ProviderTransportError):
        firecrawl.parse_firecrawl_hits('{"data":[{"url":"https://e.com/a","title":5}]}')


def test_firecrawl_title_fallback_reads_metadata_before_it_refuses_the_lane() -> None:
    # Documented fallback: a non-string title errors the lane only when
    # metadata carries no string title either.
    hits = firecrawl.parse_firecrawl_hits(
        '{"data":[{"url":"https://e.com/a","title":5,"metadata":{"title":"x"}}]}'
    )
    assert hits == [SearchHit(title="x", url="https://e.com/a")]
    with pytest.raises(ProviderTransportError, match="^title_not_string$"):
        firecrawl.parse_firecrawl_hits(
            '{"data":[{"url":"https://e.com/a","title":5,"metadata":{"title":7}}]}'
        )


def test_parsers_refuse_a_falsy_non_string_snippet() -> None:
    # A falsy non-string snippet ([]) must not fall through the `or` default to
    # an ok lane with no snippet; it errors the lane, as tavily already does.
    with pytest.raises(ProviderTransportError):
        zai.parse_search_prime_hits(
            '{"results":[{"url":"https://e.com/a","snippet":[]}]}'
        )
    with pytest.raises(ProviderTransportError):
        minimax.parse_minimax_hits(
            '{"data":[{"link":"https://e.com/a","snippet":[]}]}', 10
        )
    with pytest.raises(ProviderTransportError):
        firecrawl.parse_firecrawl_hits(
            '{"data":[{"url":"https://e.com/a","description":[]}]}'
        )


def test_fan_out_records_poisoned_lane_as_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAVILY_API_KEY", "t" * 12)
    monkeypatch.setenv("MINIMAX_API_KEY", "m" * 12)
    monkeypatch.delenv("ZAI_API_KEY", raising=False)
    monkeypatch.delenv("FIRECRAWL_API_KEY", raising=False)
    monkeypatch.setattr(
        tavily,
        "bearer_post",
        lambda *args, **kwargs: HttpResponse(
            200, '{"results":[{"url":"https://e.com/a","content":{"nested":1}}]}'
        ),
    )
    monkeypatch.setattr(
        minimax,
        "bearer_post",
        lambda *args, **kwargs: HttpResponse(
            200, '{"data":[{"link":"https://e.com/b","title":"B","snippet":"good"}]}'
        ),
    )

    hits, lanes = fan_out_search("query", 10)
    status = {lane.provider: lane.status for lane in lanes}
    assert status["tavily"] == "error"
    assert status["minimax"] == "ok"
    assert status["zai"] == "skipped_no_key"
    assert status["firecrawl"] == "skipped_no_key"
    assert [hit.url for hit in hits] == ["https://e.com/b"]
