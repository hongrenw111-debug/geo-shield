"""Public interface for geo_shield.geo_score."""

from ._internal.domain_reputation import DomainRegistry
from ._internal.lexical_signals import _classify_level, compute_local_geo_score
from ._internal.llm_auditor import resolve_llm_config, run_llm_semantic_audit
from ._internal.models import (
    DimensionBreakdown,
    GeoScoreReport,
    LlmAuditConfig,
    LlmAuditResult,
    SignalHit,
    SourceTrustTier,
)

__all__ = [
    "DimensionBreakdown",
    "DomainRegistry",
    "GeoScoreReport",
    "LlmAuditConfig",
    "LlmAuditResult",
    "SignalHit",
    "SourceTrustTier",
    "is_llm_audit_configured",
    "score_document",
]


def is_llm_audit_configured(llm_config: LlmAuditConfig | None = None) -> bool:
    """Return True if OpenAI-compatible semantic audit credentials are configured."""
    resolved = resolve_llm_config(llm_config)
    return bool(resolved.base_url and resolved.api_key and resolved.model)


def score_document(
    text: str,
    title: str = "",
    url: str = "",
    links: list[str] | None = None,
    llm_config: LlmAuditConfig | None = None,
    registry: DomainRegistry | None = None,
) -> GeoScoreReport:
    """Score a document for GEO soft-ad manipulation using local heuristics + optional LLM audit."""
    report = compute_local_geo_score(
        text=text,
        title=title,
        url=url,
        links=links,
        registry=registry,
    )
    llm_result = run_llm_semantic_audit(title=title, url=url, text=text, config=llm_config)
    report.llm_audit = llm_result

    if llm_result.status == "applied" and llm_result.advertorial_score is not None:
        blended = round(0.60 * report.local_score + 0.40 * llm_result.advertorial_score)
        report.geo_risk = max(0, min(100, blended))
        report.risk_level = _classify_level(report.geo_risk)
        report.summary = (
            f"GEO Risk {report.geo_risk}/100 ({report.risk_level}, "
            f"local={report.local_score}, llm={llm_result.advertorial_score})."
        )

    return report
