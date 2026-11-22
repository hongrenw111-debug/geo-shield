"""Public interface for geo_shield.retrieval."""

import os
import shutil

from ._internal.agent_reach_provider import search_agent_reach
from ._internal.ddg_provider import search_duckduckgo
from ._internal.fetcher import fetch_remote_page
from ._internal.models import FetchedPage, SearchResult
from ._internal.searxng_provider import search_searxng

__all__ = [
    "FetchedPage",
    "SearchResult",
    "fetch_page",
    "search_web",
]


def fetch_page(url: str, timeout: float = 15.0) -> FetchedPage:
    """Safely fetch a public HTTP/HTTPS web page with SSRF and size protections."""
    return fetch_remote_page(url, timeout=timeout)


def search_web(
    query: str, max_results: int = 10, searxng_url: str | None = None
) -> list[SearchResult]:
    """Search the web via SearXNG -> agent-reach Exa -> DuckDuckGo fallback."""
    sx = (searxng_url or os.getenv("GEOSHIELD_SEARXNG_URL", "")).strip()
    if sx:
        return search_searxng(query, sx, max_results=max_results)

    disable_ar = os.getenv("GEOSHIELD_DISABLE_AGENT_REACH", "").strip() == "1"
    if not disable_ar and shutil.which("agent-reach"):
        try:
            ar_results = search_agent_reach(query, max_results=max_results)
            if ar_results:
                return ar_results
        except Exception:  # noqa: BLE001 - graceful fallback to DDG
            pass

    return search_duckduckgo(query, max_results=max_results)
