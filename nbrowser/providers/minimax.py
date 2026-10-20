"""MiniMax REST: /v1/coding_plan/search + remains."""

import json
import os

from .base import (
    ProviderKey,
    ProviderTransportError,
    SearchHit,
    bearer_post,
)


def base_url() -> str:
    host = os.environ.get("MINIMAX_API_HOST", "")
    if host:
        return f"https://{host}"
    return "https://api.minimax.io"


def parse_minimax_hits(body: str, max: int) -> list[SearchHit]:
    v = json.loads(body)
    base_resp = v.get("base_resp") if isinstance(v, dict) else None
    if isinstance(base_resp, dict) and base_resp.get("status_code") not in (0, None):
        raise ProviderTransportError(f"minimax_status_{base_resp.get('status_code')}")
    data = v.get("data") if isinstance(v, dict) else v
    arr = data if isinstance(data, list) else None
    if arr is None and isinstance(data, dict):
        arr = data.get("results") if isinstance(data.get("results"), list) else None
    if arr is None:
        raise ProviderTransportError("missing_data_array")
    hits: list[SearchHit] = []
    for item in arr[:max]:
        if not isinstance(item, dict):
            continue
        url = item.get("link") or item.get("url")
        if not isinstance(url, str):
            continue
        title = item.get("title")
        snippet = item.get("snippet")
        if title is not None and not isinstance(title, str):
            raise ProviderTransportError("title_not_string")
        if snippet is not None and not isinstance(snippet, str):
            raise ProviderTransportError("snippet_not_string")
        if not snippet:
            fallback = item.get("content")
            if fallback is not None and not isinstance(fallback, str):
                raise ProviderTransportError("snippet_not_string")
            snippet = fallback
        hits.append(
            SearchHit(
                title=title or "",
                url=url,
                snippet=snippet,
                date=item.get("date"),
            )
        )
    return hits


def lane_search(query: str, max: int, key: ProviderKey) -> list[SearchHit]:
    resp = bearer_post(
        base_url(), "/v1/coding_plan/search", key, {"q": query, "query": query}
    )
    if resp.status != 200:
        raise ProviderTransportError(f"http_{resp.status}")
    return parse_minimax_hits(resp.body, max)
