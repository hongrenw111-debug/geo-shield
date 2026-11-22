"""Public interface for geo_shield.sanitize."""

from ._internal.html_cleaner import sanitize_html_content, sanitize_plain_text
from ._internal.models import SanitizeReport, Severity, ThreatFinding, UrlInspectionReport
from ._internal.url_poison import inspect_url_safety

__all__ = [
    "SanitizeReport",
    "Severity",
    "ThreatFinding",
    "UrlInspectionReport",
    "inspect_url",
    "sanitize_html",
    "sanitize_text",
]


def sanitize_html(html: str, base_url: str = "") -> SanitizeReport:
    """Strip hidden DOM elements, comments, invisible Unicode, and prompt injections from HTML."""
    return sanitize_html_content(html, base_url=base_url)


def sanitize_text(text: str) -> SanitizeReport:
    """Strip invisible Unicode and indirect prompt injection lines from plain text."""
    return sanitize_plain_text(text)


def inspect_url(url: str) -> UrlInspectionReport:
    """Inspect a URL (especially 'Summarize with AI' links) for memory/prompt poisoning."""
    return inspect_url_safety(url)
