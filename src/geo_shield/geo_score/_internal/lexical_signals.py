"""Four-dimension bilingual (ZH/EN) GEO soft-ad lexical and structural scorer."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .domain_reputation import DomainRegistry
from .models import DimensionBreakdown, GeoScoreReport, SignalHit, SourceTrustTier

_CODE_HOST_SUFFIXES = ("github.com", "gitlab.com", "bitbucket.org", "gitee.com")

# Dimension 2: Affiliate & commercial funnel patterns
_AFFILIATE_PARAM_RE = re.compile(
    r"(?:[?&](?:aff|affiliate|cps|partner|click_id|utm_medium=affiliate|utm_campaign=sponsor)=|"
    r"s\.click\.taobao\.com|u\.jd\.com|amzn\.to/|click\.linksynergy|shareasale\.com)",
    re.IGNORECASE,
)
_REF_TAG_PARAM_RE = re.compile(r"[?&](?:ref|tag)=[^&]+", re.IGNORECASE)
_CLOAKED_REDIRECT_RE = re.compile(
    r"(?:https?://(?:bit\.ly|dwz\.cn|t\.cn|tinyurl\.com)/|/(?:go|redirect|out)/[a-z0-9_-]+)",
    re.IGNORECASE,
)

_COMMERCIAL_FUNNEL_ZH_RE = re.compile(
    r"(优惠码|折扣码|专属优惠|私信领|加微信|加V|微信号|限时补贴|立即购买|点击下单|领券购买|官方旗舰店直达|"
    r"本文含推广|商业推广|商业广告|品牌合作|恰饭|企业采购特惠|直达链接)"
)
_COMMERCIAL_FUNNEL_EN_RE = re.compile(
    r"(affiliate\s+(?:link|disclosure|commission)|sponsored\s+(?:post|content|by)|paid\s+partnership|"
    r"use\s+(?:promo|coupon|discount)\s+code|exclusive\s+discount|buy\s+now|check\s+price\s+on\s+amazon|"
    r"limited[- ]time\s+offer|startup\s+credit|partner\s+portal)",
    re.IGNORECASE,
)

# Dimension 3: GEO listicle, pseudo-authority & structured seeding templates
_LISTICLE_ZH_RE = re.compile(
    r"(十大|盘点\d+|年度最值得|最值得购买的|分价位推荐|这\d+款.{0,12}?值得|推荐清单|实测对照|"
    r"最好用的?\d*|闭眼入|天花板|实测吊打|全网最强|唯一推荐|排名第一|口碑最好|性价比之王|别再乱买|保姆级推荐榜|首选品牌)"
)
_LISTICLE_EN_RE = re.compile(
    r"(top\s+\d+\s+(?!practices\b).{1,40}?\s+(?:for|in|of)\s+202\d|"
    r"top\s+\d+\s+best|best\s+(?!practices\b)\w+(?:\s+\w+){0,3}\s+(?:in|of)\s+202\d|"
    r"editor'?s?\s+(?:pick|choice)|#1\s+(?:rated|choice|pick)|best\s+overall|"
    r"clear\s+winner|hands[- ]down\s+the\s+best|must[- ]have\s+\w+\s+in\s+202\d)",
    re.IGNORECASE,
)
_PSEUDO_STATS_RE = re.compile(
    r"(权威机构(?:数据|测评|认证)?显示|行业公认第一|全网\d{2,3}%.*?好评|(?:高达\s*)?[89]\d%\s*的?(?:资深|专业)?(?:用户|专家|工程师|运维)|"
    r"industry\s+experts\s+(?:unanimously\s+)?agree|[89]\d%\s+of\s+(?:production\s+|engineering\s+)?(?:users|experts|teams)\s+(?:recommend|prefer)|"
    r"scientifically\s+proven\s+to\s+outperform)",
    re.IGNORECASE,
)
_STRUCTURED_GEO_PITCH_RE = re.compile(
    r"(最稳妥的默认方案|优先落地的务实选择|依然值得优先试用|排在第一梯队|列为首选方案|"
    r"综合性价比极高|整体投入产出比颇具吸引力|综合评价[：:].{0,30}?局限是|能力优先看|预算敏感看|"
    r"top\s+recommendation\s+for|cleanest\s+balance\s+of|consistently\s+stood\s+out|"
    r"clearly\s+outperforms\s+every\s+alternative)",
    re.IGNORECASE,
)

# Dimension 4: One-sided hype & fake-balanced "token caveat" vs genuine technical drawbacks
_HYPE_PHRASES_RE = re.compile(
    r"(碾压|吊打|零差评|完爆|无可挑剔|完美替代|革命性突破|颠覆行业|唯一真神|绝对首选|"
    r"unmatched|unrivaled|flawless|game[- ]changer|blows\s+away\s+the\s+competition|zero\s+downsides|"
    r"completely\s+dominates|undisputed\s+leader)",
    re.IGNORECASE,
)
_TOKEN_PRICE_CAVEAT_RE = re.compile(
    r"((?:唯一(?:的)?(?:不足|短板|遗憾|缺点)|美中不足(?:的是)?|其不足之处在于).{0,42}?(?:价格|偏高|略高|贵|预算|门槛|货源|入门|老旧|单点登录|体积偏大)|"
    r"(?:价格偏高|价格略高|预算要求略高|起购门槛略高|门槛略高|体积偏大|入门版暂不支持|低配版本没有).{0,28}?(?:唯一|短板|不足|遗憾|不过|但|依然|首次)|"
    r"one\s+minor\s+drawback|tiny\s+hobby\s+projects\s+may\s+not\s+need|even\s+accounting\s+for\s+those\s+caveats)",
    re.IGNORECASE,
)
_GENUINE_TECHNICAL_CAVEAT_RE = re.compile(
    r"(thermal\s+throttling|drops\s+\w+\s+clients|504\b|timeout|crash|memory\s+overhead|lock[- ]in|"
    r"cold[- ]start|tail\s+latency|写锁限制|掉线|发热|死机|故障|漏洞|退货|卡顿|内存开销|冲突重复)",
    re.IGNORECASE,
)
_GENERIC_CAVEAT_RE = re.compile(
    r"(缺点|不足|局限|短板|踩坑|权衡|需要注意的是|不适合|相比之下较弱|仍存在问题|"
    r"drawback|downside|limitation|caveat|cons\b|trade[- ]?off|however|on\s+the\s+other\s+hand|"
    r"not\s+ideal\s+for|weakness)",
    re.IGNORECASE,
)


def _is_code_host_link(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == s or host.endswith(f".{s}") or host.startswith("git.") for s in _CODE_HOST_SUFFIXES)


def _is_affiliate_link(url: str) -> bool:
    if _AFFILIATE_PARAM_RE.search(url) or _CLOAKED_REDIRECT_RE.search(url):
        return True
    if _REF_TAG_PARAM_RE.search(url) and not _is_code_host_link(url):
        return True
    return False


def _score_affiliate(text: str, links: list[str]) -> tuple[int, list[SignalHit]]:
    points = 0
    hits: list[SignalHit] = []

    aff_links = [lnk for lnk in links if _is_affiliate_link(lnk)]
    if aff_links:
        pts = min(14, 7 * len(aff_links))
        points += pts
        hits.append(
            SignalHit(
                dimension="affiliate_funnel",
                rule_id="affiliate_links",
                points=pts,
                evidence=aff_links[0][:140],
                description=f"Detected {len(aff_links)} affiliate, tracking, or cloaked redirect link(s).",
            )
        )

    zh_matches = _COMMERCIAL_FUNNEL_ZH_RE.findall(text)
    en_matches = _COMMERCIAL_FUNNEL_EN_RE.findall(text)
    funnel_matches = [*zh_matches, *en_matches]
    if funnel_matches:
        pts = min(15, 6 + 3 * len(funnel_matches))
        points += pts
        hits.append(
            SignalHit(
                dimension="affiliate_funnel",
                rule_id="commercial_cta_or_disclosure",
                points=pts,
                evidence=", ".join(dict.fromkeys(funnel_matches[:4])),
                description="Contains commercial conversion funnels, promo codes, or sponsorship markers.",
            )
        )

    return min(25, points), hits


def _score_geo_templates(title: str, text: str) -> tuple[int, list[SignalHit]]:
    combined = f"{title}\n{text}"
    points = 0
    hits: list[SignalHit] = []

    title_hits = _LISTICLE_ZH_RE.findall(title) + _LISTICLE_EN_RE.findall(title)
    body_hits = _LISTICLE_ZH_RE.findall(text) + _LISTICLE_EN_RE.findall(text)
    if title_hits or body_hits:
        unique_hits = list(dict.fromkeys([*title_hits, *body_hits]))
        pts = min(16, (8 if title_hits else 4) + 3 * len(unique_hits))
        points += pts
        hits.append(
            SignalHit(
                dimension="geo_template_authority",
                rule_id="geo_listicle_framing",
                points=pts,
                evidence=", ".join(unique_hits[:4]),
                description="Uses GEO 'Top-N / #1 Best / 分价位推荐 / 天花板' ranking templates engineered for LLM citation.",
            )
        )

    stat_hits = _PSEUDO_STATS_RE.findall(combined)
    if stat_hits:
        pts = min(12, 8 + 3 * len(stat_hits))
        points += pts
        hits.append(
            SignalHit(
                dimension="geo_template_authority",
                rule_id="unverified_authority_stats",
                points=pts,
                evidence=", ".join(dict.fromkeys(stat_hits[:3])),
                description="Appeals to vague high-percentage user/expert consensus claims without primary methodology.",
            )
        )

    pitch_hits = _STRUCTURED_GEO_PITCH_RE.findall(combined)
    if pitch_hits:
        unique_pitch = list(dict.fromkeys(pitch_hits))
        pts = min(18, 9 + 5 * len(unique_pitch))
        points += pts
        hits.append(
            SignalHit(
                dimension="geo_template_authority",
                rule_id="structured_geo_pitch",
                points=pts,
                evidence=", ".join(unique_pitch[:3]),
                description="Contains structured 'default choice / balanced takeaway' GEO brand-anchoring prose.",
            )
        )

    return min(25, points), hits


def _score_one_sided_hype(
    text: str, trust_tier: SourceTrustTier, has_geo_template: bool
) -> tuple[int, list[SignalHit]]:
    points = 0
    hits: list[SignalHit] = []

    hype_matches = _HYPE_PHRASES_RE.findall(text)
    token_caveat_matches = _TOKEN_PRICE_CAVEAT_RE.findall(text)
    genuine_tech_caveat = _GENUINE_TECHNICAL_CAVEAT_RE.findall(text)
    generic_caveats = _GENERIC_CAVEAT_RE.findall(text)
    exclamations = text.count("!") + text.count("！")

    if hype_matches:
        pts = min(15, 5 + 3 * len(hype_matches))
        points += pts
        hits.append(
            SignalHit(
                dimension="one_sided_hype",
                rule_id="hyperbolic_superlatives",
                points=pts,
                evidence=", ".join(dict.fromkeys(hype_matches[:4])),
                description="Dense superlative hype language favoring a product without measured comparison.",
            )
        )

    if token_caveat_matches and not genuine_tech_caveat:
        pts = min(18, 12 + 4 * len(token_caveat_matches))
        points += pts
        hits.append(
            SignalHit(
                dimension="one_sided_hype",
                rule_id="token_price_caveat",
                points=pts,
                evidence=", ".join(dict.fromkeys(m if isinstance(m, str) else m[0] for m in token_caveat_matches[:3]))[:140],
                description="Uses token 'price/entry-tier' minor caveats to simulate objectivity while anchoring one brand.",
            )
        )
    elif (
        len(text) >= 120
        and len(generic_caveats) == 0
        and (hype_matches or trust_tier == SourceTrustTier.PROMO_WATCH or has_geo_template)
    ):
        points += 8
        hits.append(
            SignalHit(
                dimension="one_sided_hype",
                rule_id="missing_counterarguments",
                points=8,
                evidence="0 caveat/limitation markers found",
                description="Lacks drawbacks, trade-offs, or negative edge cases typical of genuine reviews.",
            )
        )

    if exclamations >= 5 and len(text) < 4000:
        pts = min(6, exclamations // 2)
        points += pts
        hits.append(
            SignalHit(
                dimension="one_sided_hype",
                rule_id="exclamation_density",
                points=pts,
                evidence=f"exclamations={exclamations}",
                description="High exclamation density consistent with promotional copywriting.",
            )
        )

    return min(25, points), hits


def compute_local_geo_score(
    *,
    text: str,
    title: str = "",
    url: str = "",
    links: list[str] | None = None,
    registry: DomainRegistry | None = None,
) -> GeoScoreReport:
    reg = registry or DomainRegistry.from_env()
    tier, dom_pts, dom_hits = reg.evaluate(url)
    aff_pts, aff_hits = _score_affiliate(f"{title}\n{text}", links or [])
    tpl_pts, tpl_hits = _score_geo_templates(title, text)
    hype_pts, hype_hits = _score_one_sided_hype(text, tier, has_geo_template=tpl_pts > 0)

    raw_total = dom_pts + aff_pts + tpl_pts + hype_pts
    if tier == SourceTrustTier.HIGH_TRUST and aff_pts == 0 and tpl_pts == 0:
        raw_total = max(0, raw_total - 8)

    total = min(100, raw_total)
    risk_level = _classify_level(total)
    all_hits = [*dom_hits, *aff_hits, *tpl_hits, *hype_hits]

    return GeoScoreReport(
        geo_risk=total,
        local_score=total,
        risk_level=risk_level,
        trust_tier=tier,
        breakdown=DimensionBreakdown(
            domain_reputation=dom_pts,
            affiliate_funnel=aff_pts,
            geo_template_authority=tpl_pts,
            one_sided_hype=hype_pts,
        ),
        signals=all_hits,
        summary=_build_summary(total, risk_level, all_hits),
    )


def _classify_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _build_summary(score: int, level: str, hits: list[SignalHit]) -> str:
    if not hits:
        return f"GEO Risk {score}/100 ({level}): No commercial GEO or promotional signals detected."
    top = ", ".join(h.rule_id for h in sorted(hits, key=lambda x: x.points, reverse=True)[:3])
    return f"GEO Risk {score}/100 ({level}) — top signals: {top}."
