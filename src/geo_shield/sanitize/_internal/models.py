"""Data contracts for geo_shield.sanitize."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatFinding(BaseModel):
    category: str
    severity: Severity
    description: str
    excerpt: str = ""
    location: str = "body"


class SanitizeReport(BaseModel):
    clean_text: str
    title: str = ""
    extracted_links: list[str] = Field(default_factory=list)
    injection_risk: int = Field(ge=0, le=100, default=0)
    findings: list[ThreatFinding] = Field(default_factory=list)
    hidden_chars_stripped: int = 0
    hidden_dom_blocks_stripped: int = 0
    comments_stripped: int = 0
    injection_lines_stripped: int = 0


class UrlInspectionReport(BaseModel):
    url: str
    host: str = ""
    is_ai_entrypoint: bool = False
    risk_level: Severity = Severity.INFO
    risk_score: int = Field(ge=0, le=100, default=0)
    decoded_params: dict[str, list[str]] = Field(default_factory=dict)
    fragment_decoded: str = ""
    findings: list[ThreatFinding] = Field(default_factory=list)
    verdict: str = "Safe URL"
