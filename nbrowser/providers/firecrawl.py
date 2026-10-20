"""Firecrawl REST: /v2/search."""

import json

from .base import (
    ProviderKey,
    ProviderTransportError,
    SearchHit,
    bearer_post,
)

BASE = "https://api.firecrawl.dev"


def parse_firecrawl_hits(body: str) -> list[SearchHit]:
    v = json.loads(body)
    if isinstance(v, list):
        v = {"data": v}
    if not isinstance(v, dict):
        raise ProviderTransportError("missing_data_array")
    if v.get("success") is False:
        raise ProviderTransportError(
            f"firecrawl_error: {v.get('error', 'vendor_reported_failure')}"
        )
    data = v.get("data")
    arr = None
    if isinstance(data, dict):
        arr = data.get("web") if isinstance(data.get("web"), list) else None
    if arr is None and isinstance(data, list):
        arr = data
    if arr is None and isinstance(v.get("results"), list):
        arr = v["results"]
    if arr is None:
        raise ProviderTransportError("missing_data_array")
    hits: list[SearchHit] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        title = item.get("title")
        if not isinstance(title, str) and isinstance(item.get("metadata"), dict):
            title = item["metadata"].get("title")
        snippet = item.get("description")
        if title is not None and not isinstance(title, str):
            raise ProviderTransportError("title_not_string")
        if snippet is not None and not isinstance(snippet, str):
            raise ProviderTransportError("snippet_not_string")
        if not snippet:
            fallback = item.get("snippet")
            if fallback is not None and not isinstance(fallback, str):
                raise ProviderTransportError("snippet_not_string")
            snippet = fallback
        hits.append(
            SearchHit(
                title=title or "",
                url=url,
                snippet=snippet,
            )
        )
    return hits


def lane_search(query: str, max: int, key: ProviderKey) -> list[SearchHit]:
    resp = bearer_post(BASE, "/v2/search", key, {"query": query, "limit": max})
    if resp.status != 200:
        raise ProviderTransportError(f"http_{resp.status}")
    return parse_firecrawl_hits(resp.body)
