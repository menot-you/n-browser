"""Provider body decoding uses disposable JSON fixtures and no egress."""

import json

import pytest

from nbrowser.providers.base import ProviderTransportError, SearchHit
from nbrowser.providers.firecrawl import parse_firecrawl_hits


@pytest.mark.parametrize("shape", ["array", "data", "web", "results"])
def test_firecrawl_accepts_each_supported_result_container(shape: str) -> None:
    entries = [
        None,
        {"url": None},
        {
            "url": "https://fixture.test/a",
            "metadata": {"title": "A"},
            "description": "body",
        },
        {"url": "https://fixture.test/b", "title": "B", "snippet": "other"},
        {"url": "https://fixture.test/c"},
    ]
    bodies = {
        "array": entries,
        "data": {"data": entries},
        "web": {"data": {"web": entries}},
        "results": {"results": entries},
    }
    assert parse_firecrawl_hits(json.dumps(bodies[shape])) == [
        SearchHit(title="A", url="https://fixture.test/a", snippet="body"),
        SearchHit(title="B", url="https://fixture.test/b", snippet="other"),
        SearchHit(title="", url="https://fixture.test/c"),
    ]


@pytest.mark.parametrize(
    "body", [None, True, 3, "text", {}, {"data": {}}, {"data": "invalid"}]
)
def test_firecrawl_invalid_container_is_a_typed_transport_failure(body: object) -> None:
    with pytest.raises(ProviderTransportError, match="^missing_data_array$"):
        parse_firecrawl_hits(json.dumps(body))


@pytest.mark.parametrize(
    "body,detail",
    [
        ({"success": False}, "vendor_reported_failure"),
        ({"success": False, "error": "quota"}, "quota"),
    ],
)
def test_firecrawl_explicit_failure_wins_over_results(
    body: dict[str, object], detail: str
) -> None:
    with pytest.raises(ProviderTransportError, match=f"^firecrawl_error: {detail}$"):
        parse_firecrawl_hits(json.dumps({**body, "data": []}))
