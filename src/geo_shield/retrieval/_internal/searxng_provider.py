"""Optional SearXNG JSON search adapter."""

from __future__ import annotations

from .fetcher import make_http_client
from .models import SearchResult


def search_searxng(
    query: str, searxng_url: str, max_results: int = 10, timeout: float = 15.0
) -> list[SearchResult]:
    endpoint = f"{searxng_url.rstrip('/')}/search"
    with make_http_client(endpoint, timeout=timeout, follow_redirects=True) as client:
        resp = client.get(endpoint, params={"q": query, "format": "json"})
        resp.raise_for_status()
        payload = resp.json()

    results: list[SearchResult] = []
    for idx, item in enumerate(payload.get("results", []), start=1):
        url = str(item.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        results.append(
            SearchResult(
                title=str(item.get("title") or url),
                url=url,
                snippet=str(item.get("content") or ""),
                rank=idx,
                engine="searxng",
            )
        )
        if len(results) >= max_results:
            break
    return results
