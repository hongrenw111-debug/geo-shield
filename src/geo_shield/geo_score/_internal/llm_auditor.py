"""Optional OpenAI-compatible semantic GEO auditor with strict graceful fallback."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse

import httpx

from .models import LlmAuditConfig, LlmAuditResult

_SYSTEM_PROMPT = (
    "You are an impartial consumer-protection and adversarial-SEO auditor. "
    "Evaluate whether the provided web article is a covert GEO soft-ad, paid placement, "
    "or one-sided promotional piece engineered to bias AI recommendations. "
    "Respond ONLY with a valid JSON object matching keys: "
    '{"advertorial_score": <int 0-100>, "promoted_entities": [<str>], '
    '"bias_reasons": [<str>], "missing_counterarguments": [<str>]}.'
)


def _build_client(endpoint: str, timeout: float) -> httpx.Client:
    host = (urlparse(endpoint).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return httpx.Client(timeout=timeout, trust_env=False)
    proxy = (
        os.getenv("HTTPS_PROXY")
        or os.getenv("https_proxy")
        or os.getenv("HTTP_PROXY")
        or os.getenv("http_proxy")
    )
    return httpx.Client(timeout=timeout, trust_env=False, proxy=proxy or None)


def resolve_llm_config(config: LlmAuditConfig | None = None) -> LlmAuditConfig:
    if config and config.base_url and config.api_key and config.model:
        return config
    base_url = (config.base_url if config else "") or os.getenv("GEOSHIELD_LLM_BASE_URL", "")
    api_key = (config.api_key if config else "") or os.getenv("GEOSHIELD_LLM_API_KEY", "")
    model = (config.model if config else "") or os.getenv("GEOSHIELD_LLM_MODEL", "")
    timeout = config.timeout if config else 12.0
    return LlmAuditConfig(
        base_url=base_url.strip().rstrip("/"),
        api_key=api_key.strip(),
        model=model.strip(),
        timeout=timeout,
    )


def _extract_json_object(raw: str) -> dict[str, object]:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        try:
            parsed = json.loads(fence.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    fallback_dict: dict[str, object] | None = None
    idx = 0
    while idx < len(text):
        pos = text.find("{", idx)
        if pos == -1:
            break
        try:
            obj, _ = decoder.raw_decode(text, pos)
            if isinstance(obj, dict):
                if "advertorial_score" in obj:
                    return obj
                if fallback_dict is None:
                    fallback_dict = obj
        except json.JSONDecodeError:
            pass
        idx = pos + 1

    if fallback_dict is not None:
        return fallback_dict
    raise ValueError("No valid JSON object found in LLM response")


def run_llm_semantic_audit(
    *,
    title: str,
    url: str,
    text: str,
    config: LlmAuditConfig | None = None,
) -> LlmAuditResult:
    resolved = resolve_llm_config(config)
    if not (resolved.base_url and resolved.api_key and resolved.model):
        return LlmAuditResult(status="disabled")

    endpoint = (
        resolved.base_url
        if resolved.base_url.endswith("/chat/completions")
        else f"{resolved.base_url}/chat/completions"
    )
    excerpt = text[:6000]
    user_prompt = f"URL: {url or 'N/A'}\nTitle: {title or 'N/A'}\n\nArticle Content:\n{excerpt}"

    payload = {
        "model": resolved.model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {
        "Authorization": f"Bearer {resolved.api_key}",
        "Content-Type": "application/json",
    }

    try:
        with _build_client(endpoint, resolved.timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        parsed = _extract_json_object(str(content))
        score_raw = int(parsed.get("advertorial_score", 50))
        score = max(0, min(100, score_raw))
        return LlmAuditResult(
            status="applied",
            advertorial_score=score,
            promoted_entities=[str(x) for x in parsed.get("promoted_entities", [])][:10],
            bias_reasons=[str(x) for x in parsed.get("bias_reasons", [])][:6],
            missing_counterarguments=[
                str(x) for x in parsed.get("missing_counterarguments", [])
            ][:6],
        )
    except Exception as exc:  # noqa: BLE001 - intentional fallback boundary
        return LlmAuditResult(
            status="fallback",
            error=f"{type(exc).__name__}: {exc}",
        )
