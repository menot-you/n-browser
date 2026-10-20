"""Tavily REST: /search /extract + /usage."""

import json

from .base import (
    ProviderKey,
    ProviderTransportError,
    SearchHit,
    bearer_post,
)

BASE = "https://api.tavily.com"


def parse_tavily_hits(body: str) -> list[SearchHit]:
    v = json.loads(body)
    arr = v.get("results")
    if not isinstance(arr, list):
        raise ProviderTransportError("missing_results_array")
    hits: list[SearchHit] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        title = item.get("title")
        snippet = item.get("content")
        if title is not None and not isinstance(title, str):
            raise ProviderTransportError("title_not_string")
        if snippet is not None and not isinstance(snippet, str):
            raise ProviderTransportError("snippet_not_string")
        hits.append(
            SearchHit(
                title=title or "",
                url=url,
                snippet=snippet,
                date=item.get("published_date"),
            )
        )
    return hits


def lane_search(query: str, max: int, key: ProviderKey) -> list[SearchHit]:
    resp = bearer_post(BASE, "/search", key, {"query": query, "max_results": max})
    if resp.status != 200:
        raise ProviderTransportError(f"http_{resp.status}")
    return parse_tavily_hits(resp.body)
