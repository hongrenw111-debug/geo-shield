"""Data contracts for geo_shield.geo_score."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class SourceTrustTier(StrEnum):
    HIGH_TRUST = "HIGH_TRUST"
    NEUTRAL = "NEUTRAL"
    PROMO_WATCH = "PROMO_WATCH"


class SignalHit(BaseModel):
    dimension: str
    rule_id: str
    points: int
    evidence: str
    description: str


class LlmAuditConfig(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout: float = 12.0


class LlmAuditResult(BaseModel):
    status: Literal["disabled", "applied", "fallback"] = "disabled"
    advertorial_score: int | None = None
    promoted_entities: list[str] = Field(default_factory=list)
    bias_reasons: list[str] = Field(default_factory=list)
    missing_counterarguments: list[str] = Field(default_factory=list)
    error: str = ""


class DimensionBreakdown(BaseModel):
    domain_reputation: int = Field(ge=0, le=25, default=0)
    affiliate_funnel: int = Field(ge=0, le=25, default=0)
    geo_template_authority: int = Field(ge=0, le=25, default=0)
    one_sided_hype: int = Field(ge=0, le=25, default=0)


class GeoScoreReport(BaseModel):
    geo_risk: int = Field(ge=0, le=100, default=0)
    local_score: int = Field(ge=0, le=100, default=0)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    trust_tier: SourceTrustTier = SourceTrustTier.NEUTRAL
    breakdown: DimensionBreakdown = Field(default_factory=DimensionBreakdown)
    signals: list[SignalHit] = Field(default_factory=list)
    llm_audit: LlmAuditResult = Field(default_factory=LlmAuditResult)
    summary: str = ""
