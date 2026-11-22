"""Domain reputation registry with exact host matching and optional JSON extensions."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import SignalHit, SourceTrustTier

DEFAULT_HIGH_TRUST_DOMAINS: tuple[str, ...] = (
    "arxiv.org",
    "rtings.com",
    "consumerreports.org",
    "wikipedia.org",
    "developer.mozilla.org",
    "docs.python.org",
    "w3.org",
    "nist.gov",
    "ietf.org",
    "acm.org",
    "ieee.org",
)

DEFAULT_HIGH_TRUST_SUFFIXES: tuple[str, ...] = (".gov", ".gov.cn", ".edu", ".edu.cn", ".ac.uk")

DEFAULT_PROMO_WATCH_HOSTS: tuple[str, ...] = (
    "baijiahao.baidu.com",
    "zhuanlan.zhihu.com",
    "blog.csdn.net",
    "medium.com",
    "xiaohongshu.com",
    "toutiao.com",
)

DEFAULT_PROMO_WATCH_HOST_PATHS: tuple[tuple[str, str], ...] = (
    ("sohu.com", "/a/"),
    ("163.com", "/dy/"),
)

_PROMO_PATH_RE = re.compile(
    r"(?:/top-\d+-|/top10|/picks/|/sponsored(?:/|$)|/deals/|/best-(?!practices\b)[a-z0-9-]+)",
    re.IGNORECASE,
)


class DomainRegistry:
    """Configurable source domain reputation tiering."""

    def __init__(
        self,
        high_trust_domains: set[str] | None = None,
        promo_watch_patterns: set[str] | None = None,
    ) -> None:
        self.high_trust_domains = set(DEFAULT_HIGH_TRUST_DOMAINS)
        self.promo_watch_hosts = set(DEFAULT_PROMO_WATCH_HOSTS)
        self.promo_watch_host_paths = list(DEFAULT_PROMO_WATCH_HOST_PATHS)
        if high_trust_domains:
            self.high_trust_domains.update(d.lower().strip() for d in high_trust_domains)
        if promo_watch_patterns:
            for item in promo_watch_patterns:
                cleaned = item.lower().strip()
                if "/" in cleaned:
                    h, p = cleaned.split("/", 1)
                    self.promo_watch_host_paths.append((h, f"/{p}"))
                elif cleaned:
                    self.promo_watch_hosts.add(cleaned)

    @classmethod
    def from_env(cls) -> DomainRegistry:
        registry = cls()
        rules_path = os.getenv("GEOSHIELD_RULES_PATH", "").strip()
        if rules_path:
            path = Path(rules_path)
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        for d in data.get("high_trust_domains", []):
                            registry.high_trust_domains.add(str(d).lower().strip())
                        for p in data.get("promo_watch_patterns", []):
                            cleaned = str(p).lower().strip()
                            if "/" in cleaned:
                                h, sub = cleaned.split("/", 1)
                                registry.promo_watch_host_paths.append((h, f"/{sub}"))
                            elif cleaned:
                                registry.promo_watch_hosts.add(cleaned)
                except (OSError, json.JSONDecodeError):
                    pass
        return registry

    @staticmethod
    def _host_matches(host: str, target: str) -> bool:
        return host == target or host.endswith(f".{target}")

    def evaluate(self, url: str) -> tuple[SourceTrustTier, int, list[SignalHit]]:
        if not url:
            return SourceTrustTier.NEUTRAL, 0, []

        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        path = (parsed.path or "").lower()
        hits: list[SignalHit] = []

        is_high_trust = any(
            self._host_matches(host, d) for d in self.high_trust_domains
        ) or any(host.endswith(suf) for suf in DEFAULT_HIGH_TRUST_SUFFIXES)

        if is_high_trust:
            hits.append(
                SignalHit(
                    dimension="domain_reputation",
                    rule_id="high_trust_domain",
                    points=0,
                    evidence=host,
                    description="Source belongs to an official, academic, or independent testing domain.",
                )
            )
            return SourceTrustTier.HIGH_TRUST, 0, hits

        points = 0
        matched_host = next(
            (h for h in self.promo_watch_hosts if self._host_matches(host, h)), None
        )
        if not matched_host:
            for target_host, prefix in self.promo_watch_host_paths:
                if self._host_matches(host, target_host) and path.startswith(prefix):
                    matched_host = f"{target_host}{prefix}"
                    break

        if matched_host:
            points += 14
            hits.append(
                SignalHit(
                    dimension="domain_reputation",
                    rule_id="promo_watch_host",
                    points=14,
                    evidence=matched_host,
                    description="Host/prefix frequently appears in sponsored content or parasite SEO ecosystems.",
                )
            )

        path_m = _PROMO_PATH_RE.search(path)
        if path_m:
            add = 11 if points > 0 else 14
            points += add
            hits.append(
                SignalHit(
                    dimension="domain_reputation",
                    rule_id="promo_url_slug",
                    points=add,
                    evidence=path_m.group(0),
                    description="URL path follows commercial listicle/affiliate review slug conventions.",
                )
            )

        tier = SourceTrustTier.PROMO_WATCH if points > 0 else SourceTrustTier.NEUTRAL
        return tier, min(25, points), hits
