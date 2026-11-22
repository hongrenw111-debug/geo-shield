"""Data contracts for geo_shield.verify."""

from __future__ import annotations

from pydantic import BaseModel, Field

from geo_shield.geo_score import GeoScoreReport
from geo_shield.sanitize import SanitizeReport


class SourceInput(BaseModel):
    url: str
    title: str = ""
    content: str = ""
    is_html: bool = False
    snippet: str = ""


class SyndicationCluster(BaseModel):
    cluster_id: str
    member_urls: list[str]
    avg_similarity: float
    note: str


class AuditReport(BaseModel):
    url: str = ""
    title: str = ""
    content_source: str = "inline"
    fetch_ok: bool = True
    fetch_error: str = ""
    sanitize: SanitizeReport
    geo: GeoScoreReport
    combined_risk: int = Field(ge=0, le=100, default=0)
    verdict: str = ""
    syndication_cluster_id: str | None = None
    syndication_penalty: int = 0
    original_rank: int | None = None
    purified_rank: int | None = None
    safe_excerpt: str = ""


class CleanSearchReport(BaseModel):
    query: str
    total_sources: int
    clusters: list[SyndicationCluster] = Field(default_factory=list)
    results: list[AuditReport] = Field(default_factory=list)
    safe_context_xml: str = ""
    summary: str = ""
