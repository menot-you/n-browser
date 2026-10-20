"""Pure merge/dedupe/interleave for cross-provider results. No I/O.

url_key, clamp_snippet and merge_search are the merge.rs;
SearchHit lives in base (the contract keeps it in mod.rs for the same reason:
the lane modules and the merge core share it without a cycle).
including its own tests' semantics. fan_out_search is the
thread-door fan-out (sync core, ThreadPoolExecutor at the boundary).
"""

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import firecrawl, minimax, tavily, zai
from .base import LaneReport, LaneStatus, ProviderKey, SearchHit

SNIPPET_CAP = 2 * 1024


def url_key(u: str) -> str:
    s = u.split("#")[0]
    return s.rstrip("/")


def clamp_snippet(s: str) -> str:
    """Byte cap at a UTF-8 boundary with ellipsis, as the contract measures bytes."""
    raw = s.encode("utf-8")
    if len(raw) <= SNIPPET_CAP:
        return s
    return raw[:SNIPPET_CAP].decode("utf-8", errors="ignore") + "…"


def merge_search(
    lanes: list[list[SearchHit]], lane_names: list[str], max_hits: int
) -> list[SearchHit]:
    by_key: dict[str, int] = {}
    out: list[SearchHit] = []
    max_rank = max((len(l) for l in lanes), default=0)

    for rank in range(max_rank):
        for lane, name in zip(lanes, lane_names):
            if rank >= len(lane):
                continue
            hit = lane[rank]
            key = url_key(hit.url)
            if key in by_key:
                idx = by_key[key]
                if name not in out[idx].providers:
                    out[idx].providers.append(name)
            else:
                if len(out) >= max_hits:
                    continue
                by_key[key] = len(out)
                clone = SearchHit(
                    title=hit.title,
                    url=hit.url,
                    snippet=clamp_snippet(hit.snippet)
                    if hit.snippet is not None
                    else None,
                    date=hit.date,
                    providers=list(hit.providers),
                )
                if name not in clone.providers:
                    clone.providers.append(name)
                out.append(clone)
    return out


LANES: list[tuple[str, str, Any]] = [
    ("zai", "ZAI_API_KEY", zai),
    ("minimax", "MINIMAX_API_KEY", minimax),
    ("tavily", "TAVILY_API_KEY", tavily),
    ("firecrawl", "FIRECRAWL_API_KEY", firecrawl),
]


def _run_lane(
    name: str, env_name: str, module: Any, query: str, max: int
) -> tuple[list[SearchHit], LaneReport]:
    key = ProviderKey.from_env(env_name)
    if key is None:
        return [], LaneReport(
            provider=name, status=LaneStatus.SKIPPED_NO_KEY, ms=0, results=0
        )
    started = time.monotonic()
    try:
        hits = module.lane_search(query, max, key)
    except Exception as e:  # noqa: BLE001 — lane errors are data, never fatal
        ms = int((time.monotonic() - started) * 1000)
        return [], LaneReport(
            provider=name,
            status=LaneStatus.ERROR,
            detail=str(e)[:120],
            ms=ms,
            results=0,
        )
    ms = int((time.monotonic() - started) * 1000)
    return hits, LaneReport(
        provider=name, status=LaneStatus.OK, ms=ms, results=len(hits)
    )


def fan_out_search(
    query: str, max_results: int
) -> tuple[list[SearchHit], list[LaneReport]]:
    with ThreadPoolExecutor(max_workers=len(LANES)) as pool:
        results = list(
            pool.map(
                lambda lane: _run_lane(lane[0], lane[1], lane[2], query, max_results),
                LANES,
            )
        )
    lanes_hits = [r[0] for r in results]
    reports = [r[1] for r in results]
    merged = merge_search(lanes_hits, [l[0] for l in LANES], max_results)
    return merged, reports
