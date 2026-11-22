"""AI 'Summarize with AI' / referral / nested-redirect URL memory-poisoning inspector."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote_plus, urlparse

from .injection_rules import scan_injection_patterns
from .models import Severity, ThreatFinding, UrlInspectionReport
from .unicode_guard import strip_invisible_unicode

AI_ENTRYPOINT_HOSTS: tuple[str, ...] = (
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "gemini.google.com",
    "aistudio.google.com",
    "perplexity.ai",
    "www.perplexity.ai",
    "copilot.microsoft.com",
    "grok.com",
    "kimi.moonshot.cn",
    "www.kimi.com",
    "kimi.com",
    "chat.deepseek.com",
    "yuanbao.tencent.com",
    "www.doubao.com",
    "tongyi.aliyun.com",
    "poe.com",
)

_PROMPT_PARAM_KEYS = {"q", "prompt", "query", "text", "message", "input", "p", "summarize"}
_BIAS_KEYWORDS = (
    "recommend",
    "remember",
    "trusted",
    "best",
    "prefer",
    "推荐",
    "记住",
    "首选",
)


def _deep_unquote(value: str) -> str:
    current = value
    for _ in range(3):
        nxt = unquote_plus(current)
        if nxt == current:
            break
        current = nxt
    return current


def _normalize_url(raw_url: str) -> str:
    u = raw_url.strip()
    if u and "://" not in u and "." in u.split("/")[0]:
        return f"https://{u}"
    return u


def _looks_like_nested_url(val: str) -> bool:
    low = val.strip().lower()
    if low.startswith(("http://", "https://")):
        return True
    first_seg = low.split("/")[0].split("?")[0].rstrip(".")
    return any(first_seg == h or first_seg.endswith(f".{h}") for h in AI_ENTRYPOINT_HOSTS)


def _scan_component(
    *,
    raw_value: str,
    location: str,
    is_ai: bool,
    allow_bias_heuristic: bool,
    findings: list[ThreatFinding],
) -> str:
    decoded = _deep_unquote(raw_value)
    cleaned, _, uni_findings = strip_invisible_unicode(decoded)
    findings.extend(uni_findings)

    _, _, inj_findings = scan_injection_patterns(
        cleaned, location=location, strip_matched_lines=False
    )
    if inj_findings:
        for item in inj_findings:
            if is_ai:
                item.severity = Severity.CRITICAL
            elif item.severity == Severity.CRITICAL:
                item.severity = Severity.HIGH
            findings.append(item)
    elif allow_bias_heuristic and is_ai and len(cleaned) >= 12:
        lowered = cleaned.lower()
        if any(tok in lowered for tok in _BIAS_KEYWORDS):
            findings.append(
                ThreatFinding(
                    category="ai_prefill_bias_prompt",
                    severity=Severity.MEDIUM,
                    description="AI prefill URL contains recommendation/preference framing.",
                    excerpt=cleaned[:200],
                    location=location,
                )
            )
    return cleaned


def inspect_url_safety(url: str, *, _depth: int = 0) -> UrlInspectionReport:
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    is_ai = any(host == h or host.endswith(f".{h}") for h in AI_ENTRYPOINT_HOSTS)
    if not is_ai and (host == "x.com" or host.endswith(".x.com") or host == "twitter.com") and "/grok" in parsed.path.lower():
        is_ai = True

    raw_params = parse_qs(parsed.query, keep_blank_values=True)
    decoded_params: dict[str, list[str]] = {}
    findings: list[ThreatFinding] = []

    if parsed.path and parsed.path != "/":
        _scan_component(
            raw_value=parsed.path,
            location="path",
            is_ai=is_ai,
            allow_bias_heuristic=False,
            findings=findings,
        )

    for key, values in raw_params.items():
        cleaned_vals: list[str] = []
        for raw_val in values:
            cleaned = _scan_component(
                raw_value=raw_val,
                location=f"query:{key}",
                is_ai=is_ai,
                allow_bias_heuristic=(key.lower() in _PROMPT_PARAM_KEYS),
                findings=findings,
            )
            cleaned_vals.append(cleaned)

            if _depth < 2 and _looks_like_nested_url(cleaned):
                nested = inspect_url_safety(cleaned, _depth=_depth + 1)
                if nested.is_ai_entrypoint:
                    is_ai = True
                for nf in nested.findings:
                    nf.location = f"nested({key})->{nf.location}"
                    findings.append(nf)
        decoded_params[key] = cleaned_vals

    fragment_decoded = ""
    if parsed.fragment:
        fragment_decoded = _scan_component(
            raw_value=parsed.fragment,
            location="fragment",
            is_ai=is_ai,
            allow_bias_heuristic=True,
            findings=findings,
        )
        if _depth < 2 and _looks_like_nested_url(fragment_decoded):
            nested_frag = inspect_url_safety(fragment_decoded, _depth=_depth + 1)
            if nested_frag.is_ai_entrypoint:
                is_ai = True
            for nf in nested_frag.findings:
                nf.location = f"nested(fragment)->{nf.location}"
                findings.append(nf)

    if not findings:
        return UrlInspectionReport(
            url=url,
            host=host,
            is_ai_entrypoint=is_ai,
            risk_level=Severity.INFO,
            risk_score=0,
            decoded_params=decoded_params,
            fragment_decoded=fragment_decoded,
            findings=[],
            verdict="Clean URL: no prompt injection or memory poisoning payload detected.",
        )

    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    max_sev = max((f.severity for f in findings), key=order.index)
    score_map = {
        Severity.INFO: 0,
        Severity.LOW: 20,
        Severity.MEDIUM: 48,
        Severity.HIGH: 78,
        Severity.CRITICAL: 96,
    }
    score = min(100, score_map[max_sev] + max(0, len(findings) - 1) * 4)

    if max_sev == Severity.CRITICAL and is_ai:
        verdict = (
            "CRITICAL: AI Memory/Recommendation Poisoning URL! "
            "Do not open or auto-submit this link to an AI assistant."
        )
    elif max_sev in {Severity.HIGH, Severity.CRITICAL}:
        verdict = "HIGH RISK: URL parameters contain embedded prompt-injection instructions."
    else:
        verdict = "MEDIUM RISK: AI pre-filled prompt detected; inspect query text before submitting."

    return UrlInspectionReport(
        url=url,
        host=host,
        is_ai_entrypoint=is_ai,
        risk_level=max_sev,
        risk_score=score,
        decoded_params=decoded_params,
        fragment_decoded=fragment_decoded,
        findings=findings,
        verdict=verdict,
    )
