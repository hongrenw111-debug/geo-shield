"""Data contracts for geo_shield.retrieval."""

from __future__ import annotations

from pydantic import BaseModel


class FetchedPage(BaseModel):
    url: str
    final_url: str = ""
    status_code: int = 0
    content_type: str = ""
    body: str = ""
    is_html: bool = True
    ok: bool = True
    error: str = ""


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str = ""
    full_text: str = ""
    rank: int = 1
    engine: str = "duckduckgo"
