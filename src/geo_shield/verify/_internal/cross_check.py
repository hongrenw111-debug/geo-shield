"""Cross-source syndication/coordinated-pitch clustering, risk ranking, and safe XML framing."""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from geo_shield import retrieval
from geo_shield.geo_score import LlmAuditConfig, score_document
from geo_shield.sanitize import sanitize_html, sanitize_text

from .models import AuditReport, CleanSearchReport, SourceInput, SyndicationCluster

_NORM_RE = re.compile(r"[\W_]+", re.UNICODE)
_EN_BRAND_RE = re.compile(r"\b(?:[A-Z][a-z]+[A-Z][A-Za-z0-9]*|[A-Z]{2,}[a-z]+[A-Za-z0-9]*)\b")
_CJK_SEQ_RE = re.compile(r"[\u4e00-\u9fff]{2,}")

_EN_STOPWORDS = frozenset(
    {
        "GitHub",
        "GitLab",
        "JavaScript",
        "TypeScript",
        "PostgreSQL",
        "OpenTelemetry",
        "DuckDuckGo",
        "ChatGPT",
        "YouTube",
        "LinkedIn",
        "WordPress",
        "MacOS",
        "iPhone",
        "iPad",
    }
)
_CJK_GENERIC = frozenset(
    {
        "协同",
        "办公",
        "团队",
        "软件",
        "推荐",
        "评测",
        "对比",
        "平台",
        "企业",
        "产品",
        "方案",
        "功能",
        "系统",
        "问题",
        "价格",
        "成本",
        "效率",
        "数据",
        "使用",
        "用户",
        "支持",
        "表现",
        "方面",
        "版本",
        "不过",
        "虽然",
        "但是",
        "依然",
        "需要",
        "值得",
        "优势",
        "不足",
        "局限",
        "唯一",
        "还是",
        "可以",
        "我们",
        "他们",
        "目前",
        "综合",
        "整体",
        "第一",
        "最好",
        "如何",
        "怎么",
        "为什么",
    }
)


def _char_ngrams(text: str, n: int = 4) -> set[str]:
    compact = _NORM_RE.sub("", text.lower())
    if len(compact) < 40:
        return set()
    return {compact[i : i + n] for i in range(len(compact) - n + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


def _compute_combined_risk(geo_risk: int, injection_risk: int, syn_penalty: int) -> int:
    weighted = round(0.60 * geo_risk + 0.40 * injection_risk)
    return min(100, max(weighted, geo_risk, injection_risk) + syn_penalty)


def _verdict_label(combined_risk: int, injection_risk: int, syn_cluster: str | None) -> str:
    if combined_risk >= 75:
        label = "HIGH RISK / LIKELY POISONED OR HEAVY GEO SOFT-AD"
    elif combined_risk >= 45:
        label = "CAUTION / MODERATE PROMOTIONAL OR INJECTION SIGNALS"
    else:
        label = "TRUSTWORTHY / LOW GEO & INJECTION RISK"
    notes: list[str] = []
    if injection_risk >= 30:
        notes.append(f"injection_risk={injection_risk}")
    if syn_cluster:
        notes.append(f"syndication={syn_cluster}")
    return f"{label} ({', '.join(notes)})" if notes else label


def audit_single_text(
    *,
    content: str,
    is_html: bool = False,
    title: str = "",
    url: str = "",
    llm_config: LlmAuditConfig | None = None,
    content_source: str = "inline",
) -> AuditReport:
    san = sanitize_html(content, base_url=url) if is_html else sanitize_text(content)
    eff_title = title or san.title
    geo = score_document(
        text=san.clean_text,
        title=eff_title,
        url=url,
        links=san.extracted_links,
        llm_config=llm_config,
    )
    combined = _compute_combined_risk(geo.geo_risk, san.injection_risk, 0)
    return AuditReport(
        url=url,
        title=eff_title,
        content_source=content_source,
        fetch_ok=True,
        sanitize=san,
        geo=geo,
        combined_risk=combined,
        verdict=_verdict_label(combined, san.injection_risk, None),
        safe_excerpt=san.clean_text[:1200],
    )


def audit_remote_url(url: str, llm_config: LlmAuditConfig | None = None) -> AuditReport:
    page = retrieval.fetch_page(url)
    if not page.ok:
        empty_san = sanitize_text("")
        empty_geo = score_document("", url=url, llm_config=None)
        return AuditReport(
            url=url,
            content_source="fetch_failed",
            fetch_ok=False,
            fetch_error=page.error,
            sanitize=empty_san,
            geo=empty_geo,
            combined_risk=100,
            verdict=f"FETCH FAILED: {page.error}",
        )
    return audit_single_text(
        content=page.body,
        is_html=page.is_html,
        url=page.final_url or url,
        llm_config=llm_config,
        content_source="fetched_html",
    )


def _extract_promoted_entities(report: AuditReport, query: str) -> set[str]:
    text = f"{report.title}\n{report.sanitize.clean_text}"
    entities: set[str] = set()

    for m in _EN_BRAND_RE.findall(text):
        if m not in _EN_STOPWORDS and m.lower() not in query.lower():
            if report.title.count(m) >= 1 or text.count(m) >= 2:
                entities.add(m)

    # Extract 3-4 char CJK brand-like tokens appearing in title+body or repeated >= 2 times
    cjk_counts: Counter[str] = Counter()
    title_cjk = _CJK_SEQ_RE.findall(report.title)
    body_cjk = _CJK_SEQ_RE.findall(report.sanitize.clean_text)

    for seq in [*title_cjk, *body_cjk]:
        for size in (4, 3):
            for i in range(0, len(seq) - size + 1):
                sub = seq[i : i + size]
                if sub in query or sub in _CJK_GENERIC:
                    continue
                if any(sub.startswith(g) or sub.endswith(g) for g in _CJK_GENERIC):
                    continue
                cjk_counts[sub] += 1

    title_str = report.title
    body_str = report.sanitize.clean_text
    for cand, cnt in cjk_counts.items():
        if cnt >= 2 and (cand in title_str and cand in body_str):
            entities.add(cand)
        elif cnt >= 3:
            entities.add(cand)

    return entities


def _detect_syndication_clusters(
    reports: list[AuditReport], query: str, threshold: float = 0.35
) -> list[SyndicationCluster]:
    ngrams = [_char_ngrams(r.sanitize.clean_text) for r in reports]
    n = len(reports)
    sim_matrix: dict[tuple[int, int], float] = {}
    pairs: list[tuple[float, int, int]] = []

    for i in range(n):
        if not ngrams[i]:
            continue
        for j in range(i + 1, n):
            if not ngrams[j]:
                continue
            if reports[i].url and reports[i].url == reports[j].url:
                continue
            sim = _jaccard(ngrams[i], ngrams[j])
            if sim >= threshold:
                sim_matrix[(i, j)] = sim
                pairs.append((sim, i, j))

    # Cohesive clique-preserving clustering (prevents transitive A-B-C bridge chaining)
    pairs.sort(reverse=True)
    assigned: set[int] = set()
    clusters: list[SyndicationCluster] = []
    cluster_idx = 0

    for _, seed_a, seed_b in pairs:
        if seed_a in assigned or seed_b in assigned:
            continue
        group = [seed_a, seed_b]
        for cand in range(n):
            if cand in assigned or cand in group:
                continue
            if all(
                sim_matrix.get((min(m, cand), max(m, cand)), 0.0) >= threshold
                for m in group
            ):
                group.append(cand)

        assigned.update(group)
        cluster_idx += 1
        cid = f"cluster-{cluster_idx}"
        sims = [
            sim_matrix[(min(a, b), max(a, b))]
            for idx_a, a in enumerate(group)
            for b in group[idx_a + 1 :]
        ]
        avg_sim = round(sum(sims) / len(sims), 3) if sims else threshold
        urls = [reports[idx].url or f"source-{idx + 1}" for idx in sorted(group)]
        for idx in group:
            rep = reports[idx]
            rep.syndication_cluster_id = cid
            rep.syndication_penalty = 18
            rep.combined_risk = _compute_combined_risk(
                rep.geo.geo_risk, rep.sanitize.injection_risk, rep.syndication_penalty
            )
            rep.verdict = _verdict_label(
                rep.combined_risk, rep.sanitize.injection_risk, rep.syndication_cluster_id
            )
        clusters.append(
            SyndicationCluster(
                cluster_id=cid,
                member_urls=urls,
                avg_similarity=avg_sim,
                note=(
                    f"Detected {len(group)} cohesive near-duplicate sources (avg 4-gram Jaccard={avg_sim}); "
                    "typical of coordinated GEO press-release / soft-ad syndication."
                ),
            )
        )

    # Secondary pass: detect paraphrased coordinated brand-pitch matrices across distinct hosts
    entity_to_indices: dict[str, list[int]] = {}
    for idx, rep in enumerate(reports):
        if idx in assigned or not rep.fetch_ok:
            continue
        has_promo_signal = rep.geo.geo_risk >= 20 or any(
            s.rule_id in {"token_price_caveat", "structured_geo_pitch", "promo_watch_host"}
            for s in rep.geo.signals
        )
        if not has_promo_signal:
            continue
        for ent in _extract_promoted_entities(rep, query):
            entity_to_indices.setdefault(ent, []).append(idx)

    for ent, idxs in sorted(entity_to_indices.items(), key=lambda kv: (-len(kv[1]), -len(kv[0]))):
        eligible = [i for i in idxs if i not in assigned]
        distinct_hosts = {
            (urlparse(reports[i].url).hostname or f"src-{i}").lower() for i in eligible
        }
        if len(eligible) < 2 or len(distinct_hosts) < 2:
            continue
        assigned.update(eligible)
        cluster_idx += 1
        cid = f"cluster-{cluster_idx}"
        urls = [reports[i].url or f"source-{i + 1}" for i in sorted(eligible)]
        for i in eligible:
            rep = reports[i]
            rep.syndication_cluster_id = cid
            rep.syndication_penalty = 18
            rep.combined_risk = _compute_combined_risk(
                rep.geo.geo_risk, rep.sanitize.injection_risk, rep.syndication_penalty
            )
            rep.verdict = _verdict_label(
                rep.combined_risk, rep.sanitize.injection_risk, rep.syndication_cluster_id
            )
        clusters.append(
            SyndicationCluster(
                cluster_id=cid,
                member_urls=urls,
                avg_similarity=0.0,
                note=(
                    f"Coordinated paraphrased pitch matrix promoting '{ent}' across "
                    f"{len(distinct_hosts)} independent domains."
                ),
            )
        )

    return clusters


def _build_safe_xml(query: str, ranked: list[AuditReport]) -> str:
    usable = [
        r
        for r in ranked
        if r.fetch_ok and r.combined_risk < 80 and r.sanitize.injection_risk < 70
    ]
    fallback_mode = False
    if not usable:
        usable = [r for r in ranked if r.fetch_ok][:2]
        fallback_mode = True

    lines = [
        f'<geoshield_verified_context query="{escape(query)}" '
        f'sources_included="{len(usable)}" total_audited="{len(ranked)}">'
    ]
    if fallback_mode and usable:
        lines.append(
            "  <warning>All retrieved sources scored >= 80 risk or >= 70 injection risk; showing heavily sanitized excerpts only.</warning>"
        )
    for idx, item in enumerate(usable[:5], start=1):
        stripped_total = (
            item.sanitize.hidden_chars_stripped
            + item.sanitize.hidden_dom_blocks_stripped
            + item.sanitize.injection_lines_stripped
        )
        syn = item.syndication_cluster_id or "none"
        lines.append(
            f'  <untrusted_web_evidence source_id="{idx}" '
            f'url="{escape(item.url)}" source_mode="{escape(item.content_source)}" '
            f'trust="{item.geo.trust_tier.value}" geo_risk="{item.geo.geo_risk}" '
            f'injection_risk="{item.sanitize.injection_risk}" '
            f'injection_stripped="{stripped_total}" syndication_cluster="{escape(syn)}">'
        )
        lines.append(f"    <title>{escape(item.title)}</title>")
        lines.append(f"    <content>{escape(item.safe_excerpt)}</content>")
        lines.append("  </untrusted_web_evidence>")
    lines.append("</geoshield_verified_context>")
    return "\n".join(lines)


def audit_source_list(
    *,
    query: str,
    sources: list[SourceInput],
    llm_config: LlmAuditConfig | None = None,
) -> CleanSearchReport:
    reports: list[AuditReport] = []
    for idx, src in enumerate(sources, start=1):
        if src.content:
            rep = audit_single_text(
                content=src.content,
                is_html=src.is_html,
                title=src.title,
                url=src.url,
                llm_config=llm_config,
                content_source="inline",
            )
        else:
            rep = audit_remote_url(src.url, llm_config=llm_config)
            if not rep.fetch_ok and src.snippet:
                rep = audit_single_text(
                    content=src.snippet,
                    is_html=False,
                    title=src.title,
                    url=src.url,
                    llm_config=llm_config,
                    content_source="snippet_fallback",
                )
            elif src.title and not rep.title:
                rep.title = src.title
        rep.original_rank = idx
        reports.append(rep)

    clusters = _detect_syndication_clusters(reports, query=query)
    ranked = sorted(
        reports,
        key=lambda r: (not r.fetch_ok, r.combined_risk, r.original_rank or 0),
    )
    for new_rank, rep in enumerate(ranked, start=1):
        rep.purified_rank = new_rank

    safe_xml = _build_safe_xml(query, ranked)
    high_risk_cnt = sum(1 for r in ranked if r.combined_risk >= 60)
    summary = (
        f"Audited {len(ranked)} source(s) for '{query}': "
        f"{high_risk_cnt} flagged high/critical risk, {len(clusters)} syndication cluster(s) found."
    )
    return CleanSearchReport(
        query=query,
        total_sources=len(ranked),
        clusters=clusters,
        results=ranked,
        safe_context_xml=safe_xml,
        summary=summary,
    )


def run_clean_search(
    *,
    query: str,
    max_results: int = 8,
    llm_config: LlmAuditConfig | None = None,
    searxng_url: str | None = None,
) -> CleanSearchReport:
    raw_results = retrieval.search_web(query, max_results=max_results, searxng_url=searxng_url)
    sources: list[SourceInput] = []
    for r in raw_results:
        # Use search_fulltext directly only when the search engine already supplied substantial body (>=500 chars);
        # otherwise leave content empty so audit_source_list fetches the actual target URL!
        full_body = getattr(r, "full_text", "") or ""
        if len(full_body) >= 500:
            sources.append(SourceInput(url=r.url, title=r.title, content=full_body, snippet=r.snippet))
        else:
            sources.append(SourceInput(url=r.url, title=r.title, snippet=r.snippet))

    report = audit_source_list(query=query, sources=sources, llm_config=llm_config)
    for idx, src in enumerate(raw_results):
        if getattr(src, "full_text", "") and len(src.full_text) >= 500:
            for item in report.results:
                if item.original_rank == idx + 1 and item.content_source == "inline":
                    item.content_source = "search_fulltext"
    return report
