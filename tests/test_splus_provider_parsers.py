"""Native JSON decoding contracts, without provider calls or socket fixtures."""

import json

import pytest

from nbrowser.providers.base import ProviderTransportError, SearchHit
from nbrowser.providers.minimax import base_url, parse_minimax_hits
from nbrowser.providers.tavily import parse_tavily_hits
from nbrowser.providers.zai import (
    extract_mcp_content,
    parse_search_prime_hits,
    unwrap_double_json,
)


@pytest.mark.parametrize("shape", ["array", "data", "results"])
def test_minimax_supported_containers_and_limit(shape: str) -> None:
    entries = [
        None,
        {"link": 4},
        {"link": "https://fixture.test/a", "title": "A", "snippet": "S", "date": "D"},
        {"url": "https://fixture.test/b", "content": "C"},
        {"url": "https://fixture.test/c"},
    ]
    bodies = {
        "array": entries,
        "data": {"data": entries},
        "results": {"data": {"results": entries}},
    }
    assert parse_minimax_hits(json.dumps(bodies[shape]), 4) == [
        SearchHit("A", "https://fixture.test/a", "S", "D"),
        SearchHit("", "https://fixture.test/b", "C"),
    ]
    assert parse_minimax_hits(json.dumps(bodies[shape]), 0) == []


@pytest.mark.parametrize(
    "body", [None, 4, "s", {}, {"data": {}}, {"data": {"results": 4}}]
)
def test_minimax_refuses_missing_results(body: object) -> None:
    with pytest.raises(ProviderTransportError, match="^missing_data_array$"):
        parse_minimax_hits(json.dumps(body), 10)


@pytest.mark.parametrize(
    "response", [None, "invalid", {}, {"status_code": 0}, {"status_code": None}]
)
def test_minimax_success_status_variants(response: object) -> None:
    assert parse_minimax_hits(json.dumps({"base_resp": response, "data": []}), 10) == []


def test_minimax_explicit_failure_precedes_results() -> None:
    with pytest.raises(ProviderTransportError, match="^minimax_status_2013$"):
        parse_minimax_hits('{"base_resp":{"status_code":2013},"data":[]}', 10)


def test_minimax_host_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MINIMAX_API_HOST", raising=False)
    assert base_url() == "https://api.minimax.io"
    monkeypatch.setenv("MINIMAX_API_HOST", "")
    assert base_url() == "https://api.minimax.io"
    monkeypatch.setenv("MINIMAX_API_HOST", "api.fixture.test")
    assert base_url() == "https://api.fixture.test"


@pytest.mark.parametrize("shape", ["array", "results", "wrapped"])
def test_prime_supported_containers_skip_invalid_entries(shape: str) -> None:
    entries = [
        None,
        {"url": 7},
        {"url": "https://fixture.test/a", "title": "A", "snippet": "S", "date": "D"},
        {"link": "https://fixture.test/b", "content": "C"},
    ]
    bodies = {
        "array": entries,
        "results": {"results": entries},
        "wrapped": {"result": json.dumps(entries)},
    }
    assert parse_search_prime_hits(json.dumps(bodies[shape])) == [
        SearchHit("A", "https://fixture.test/a", "S", "D"),
        SearchHit("", "https://fixture.test/b", "C"),
    ]


@pytest.mark.parametrize("body", [None, 4, "s", {}, {"results": {}}])
def test_prime_refuses_missing_results(body: object) -> None:
    with pytest.raises(ProviderTransportError, match="^missing_results_array$"):
        parse_search_prime_hits(json.dumps(body))


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        {},
        {"content": None},
        {"content": []},
        {"content": [None]},
        {"content": [{"text": 5}]},
    ],
)
def test_mcp_content_absence(result: object) -> None:
    assert extract_mcp_content(json.dumps({"result": result})) is None


def test_mcp_content_first_text() -> None:
    assert (
        extract_mcp_content(
            '{"result":{"content":[{"text":"first"},{"text":"second"}]}}'
        )
        == "first"
    )


@pytest.mark.parametrize(
    "body,expected",
    [
        ('"inner"', "inner"),
        ('{"result":"inner"}', "inner"),
        ("{}", None),
        ("[]", None),
        ("4", None),
        ("invalid", None),
    ],
)
def test_double_json_contract(body: str, expected: str | None) -> None:
    assert unwrap_double_json(body) == expected


def test_tavily_preserves_content_and_date_skips_invalid_entries() -> None:
    assert parse_tavily_hits(
        json.dumps(
            {
                "results": [
                    None,
                    {"url": 4},
                    {
                        "url": "https://fixture.test/a",
                        "title": "A",
                        "content": "C",
                        "published_date": "D",
                    },
                    {"url": "https://fixture.test/b"},
                ]
            }
        )
    ) == [
        SearchHit("A", "https://fixture.test/a", "C", "D"),
        SearchHit("", "https://fixture.test/b"),
    ]


@pytest.mark.parametrize("body", [{}, {"results": None}, {"results": {}}])
def test_tavily_refuses_missing_results(body: object) -> None:
    with pytest.raises(ProviderTransportError, match="^missing_results_array$"):
        parse_tavily_hits(json.dumps(body))
