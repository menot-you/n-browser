"""Native JSON decoding contracts, without provider calls or socket fixtures."""

import json

import pytest

from nbrowser.providers.base import ProviderTransportError, SearchHit
from nbrowser.providers.tavily import parse_tavily_hits


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
