"""Zero-key DuckDuckGo HTML search adapter."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlparse

from bs4 import BeautifulSoup

from .fetcher import make_http_client
from .models import SearchResult

_DDG_HTML_ENDPOINT = "https://html.duckduckgo.com/html/"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _unwrap_ddg_url(href: str) -> str:
    if href.startswith("//"):
        href = f"https:{href}"
    parsed = urlparse(href)
    if "duckduckgo.com" in (parsed.hostname or "") and parsed.path.startswith("/l/"):
        qs = parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
    return href


def search_duckduckgo(query: str, max_results: int = 10, timeout: float = 15.0) -> list[SearchResult]:
    with make_http_client(_DDG_HTML_ENDPOINT, timeout=timeout, follow_redirects=True) as client:
        resp = client.post(
            _DDG_HTML_ENDPOINT,
            data={"q": query},
            headers={"User-Agent": _UA},
        )
        resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    results: list[SearchResult] = []
    for idx, node in enumerate(soup.select(".result"), start=1):
        link_el = node.select_one("a.result__a")
        if not link_el or not link_el.get("href"):
            continue
        raw_href = str(link_el["href"])
        clean_url = _unwrap_ddg_url(raw_href)
        if not clean_url.startswith(("http://", "https://")):
            continue
        snippet_el = node.select_one(".result__snippet")
        results.append(
            SearchResult(
                title=link_el.get_text(" ", strip=True),
                url=clean_url,
                snippet=snippet_el.get_text(" ", strip=True) if snippet_el else "",
                rank=idx,
                engine="duckduckgo",
            )
        )
        if len(results) >= max_results:
            break
    return results
