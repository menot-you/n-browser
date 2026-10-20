"""Z.ai MCP lane: web_search_prime over JSON-RPC."""

import json

from .base import ProviderKey, ProviderTransportError, SearchHit, bearer_post

BASE = "https://api.z.ai"


def extract_mcp_content(body: str) -> str | None:
    v = json.loads(body)
    result = v.get("result")
    if not isinstance(result, dict):
        return None
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        text = content[0].get("text")
        if isinstance(text, str):
            return str(text)
    return None


def unwrap_double_json(text: str) -> str | None:
    try:
        inner = json.loads(text)
    except json.JSONDecodeError, ValueError:
        return None
    if isinstance(inner, str):
        return str(inner)
    if isinstance(inner, dict) and isinstance(inner.get("result"), str):
        return str(inner["result"])
    return None


def parse_search_prime_hits(body: str) -> list[SearchHit]:
    v = json.loads(body)
    if isinstance(v, dict) and isinstance(v.get("result"), str):
        v = json.loads(v["result"])
    arr = v.get("results") if isinstance(v, dict) else v
    if not isinstance(arr, list):
        raise ProviderTransportError("missing_results_array")
    hits: list[SearchHit] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("link")
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
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "web_search_prime",
            "arguments": {"search_query": query[:400]},
        },
        "id": 1,
    }
    resp = bearer_post(BASE, "/api/mcp/web_search_prime/mcp", key, payload)
    if resp.status != 200:
        raise ProviderTransportError(f"http_{resp.status}")
    content_text = extract_mcp_content(resp.body) or resp.body
    inner = unwrap_double_json(content_text) or content_text
    return parse_search_prime_hits(inner)
