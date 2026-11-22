"""Public interface for geo_shield.verify."""

from geo_shield.geo_score import LlmAuditConfig

from ._internal.cross_check import (
    audit_remote_url,
    audit_single_text,
    audit_source_list,
    run_clean_search,
)
from ._internal.models import (
    AuditReport,
    CleanSearchReport,
    SourceInput,
    SyndicationCluster,
)

__all__ = [
    "AuditReport",
    "CleanSearchReport",
    "SourceInput",
    "SyndicationCluster",
    "audit_sources",
    "audit_text",
    "audit_url",
    "clean_search",
]


def audit_text(
    content: str,
    is_html: bool = False,
    title: str = "",
    url: str = "",
    llm_config: LlmAuditConfig | None = None,
) -> AuditReport:
    """Sanitize and score raw HTML or plain text for GEO and prompt injection threats."""
    return audit_single_text(
        content=content, is_html=is_html, title=title, url=url, llm_config=llm_config
    )


def audit_url(url: str, llm_config: LlmAuditConfig | None = None) -> AuditReport:
    """Fetch, sanitize, and score a remote URL."""
    return audit_remote_url(url, llm_config=llm_config)


def audit_sources(
    query: str,
    sources: list[SourceInput],
    llm_config: LlmAuditConfig | None = None,
) -> CleanSearchReport:
    """Cross-verify, cluster syndication duplicates, re-rank, and wrap sources safely."""
    return audit_source_list(query=query, sources=sources, llm_config=llm_config)


def clean_search(
    query: str,
    max_results: int = 8,
    llm_config: LlmAuditConfig | None = None,
    searxng_url: str | None = None,
) -> CleanSearchReport:
    """Search the web and return purified, anti-GEO re-ranked results and safe XML context."""
    return run_clean_search(
        query=query,
        max_results=max_results,
        llm_config=llm_config,
        searxng_url=searxng_url,
    )
