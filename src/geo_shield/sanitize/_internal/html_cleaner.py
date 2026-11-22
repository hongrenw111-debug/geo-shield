"""HTML hidden DOM, CSS class/inline stealth text, comment, and title sanitizer."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from .injection_rules import scan_injection_patterns
from .models import SanitizeReport, Severity, ThreatFinding
from .unicode_guard import strip_invisible_unicode

_NOISE_TAGS = ("script", "style", "noscript", "template", "svg")
_BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "dd",
        "div",
        "dl",
        "dt",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "td",
        "th",
        "tr",
        "ul",
    }
)

_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_IMPORTANT_RE = re.compile(r"!important", re.IGNORECASE)
_STYLE_RULE_RE = re.compile(r"([^{}]+)\{([^{}]+)\}")
_TINY_FONT_RE = re.compile(
    r"font-size\s*:\s*(?:0+(?:\.\d+)?|1(?:\.\d+)?)\s*(?:px|pt|em|rem|%)?(?:\s*;|$)",
    re.IGNORECASE,
)
_OFFSCREEN_RE = re.compile(
    r"(?:left|top|text-indent)\s*:\s*-\d{3,}(?:px|em|rem|vw)|"
    r"clip\s*:\s*rect\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)|"
    r"clip-path\s*:\s*inset\(\s*100%",
    re.IGNORECASE,
)
_OPACITY_ZERO_RE = re.compile(r"(?:^|;)\s*opacity\s*:\s*0+(?:\.0+)?\s*(?:;|$)", re.IGNORECASE)
_SCALE_ZERO_RE = re.compile(r"transform\s*:\s*[^;]*scale\(\s*0+(?:\.0+)?\s*\)", re.IGNORECASE)
_ZERO_HEIGHT_RE = re.compile(r"(?:^|;)\s*height\s*:\s*0+(?:\.0+)?(?:px|em|rem)?\s*(?:;|$)", re.I)
_OVERFLOW_HIDDEN_RE = re.compile(r"(?:^|;)\s*overflow\s*:\s*hidden\s*(?:;|$)", re.I)
_COLOR_RE = re.compile(r"(?:^|;)\s*color\s*:\s*([^;]+)", re.I)
_BG_COLOR_RE = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;]+)", re.I)

_NAMED_RGB: dict[str, tuple[int, int, int]] = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "snow": (255, 250, 250),
    "ivory": (255, 255, 240),
}


def _clean_css(raw_css: str) -> str:
    no_comments = _CSS_COMMENT_RE.sub("", raw_css)
    return _IMPORTANT_RE.sub("", no_comments).strip()


def _parse_rgb(raw: str) -> tuple[int, int, int] | str | None:
    val = raw.strip().lower().replace(" ", "")
    if val in _NAMED_RGB:
        return _NAMED_RGB[val]
    if val == "transparent":
        return "transparent"
    if val.startswith("rgba(") and val.endswith(")"):
        parts = val[5:-1].split(",")
        if len(parts) == 4:
            try:
                if float(parts[3]) <= 0.02:
                    return "transparent"
                return (int(parts[0]), int(parts[1]), int(parts[2]))
            except ValueError:
                return None
    if val.startswith("rgb(") and val.endswith(")"):
        parts = val[4:-1].split(",")
        if len(parts) == 3:
            try:
                return (int(parts[0]), int(parts[1]), int(parts[2]))
            except ValueError:
                return None
    if val.startswith("#"):
        hx = val[1:]
        if len(hx) == 3:
            try:
                return tuple(int(c * 2, 16) for c in hx)  # type: ignore[return-value]
            except ValueError:
                return None
        if len(hx) == 6:
            try:
                return (int(hx[0:2], 16), int(hx[2:4], 16), int(hx[4:6], 16))
            except ValueError:
                return None
    return None


def _style_hidden_reason(raw_style: str) -> str | None:
    style = _clean_css(raw_style)
    if not style:
        return None

    compact = re.sub(r"\s+", "", style.lower())
    if "display:none" in compact:
        return "CSS display:none"
    if "visibility:hidden" in compact:
        return "CSS visibility:hidden"
    if "visibility:collapse" in compact:
        return "CSS visibility:collapse"
    if _OPACITY_ZERO_RE.search(style):
        return "CSS opacity:0"
    if _TINY_FONT_RE.search(style):
        return "CSS tiny/zero font-size"
    if _OFFSCREEN_RE.search(style):
        return "CSS off-screen/clip hiding"
    if _SCALE_ZERO_RE.search(style):
        return "CSS transform:scale(0)"
    if _ZERO_HEIGHT_RE.search(style) and _OVERFLOW_HIDDEN_RE.search(style):
        return "CSS zero-height overflow:hidden"

    color_m = _COLOR_RE.search(style)
    if color_m:
        fg = _parse_rgb(color_m.group(1))
        if fg == "transparent":
            return "CSS transparent text"
        if isinstance(fg, tuple):
            bg_m = _BG_COLOR_RE.search(style)
            if bg_m:
                bg = _parse_rgb(bg_m.group(1))
                if isinstance(bg, tuple):
                    dist = abs(fg[0] - bg[0]) + abs(fg[1] - bg[1]) + abs(fg[2] - bg[2])
                    if dist < 24:
                        return "CSS near-identical foreground/background color"
            elif min(fg) >= 245:
                return "CSS white-ink text (likely white-on-white)"
    return None


def _extract_hidden_css_selectors(soup: BeautifulSoup) -> tuple[dict[str, str], dict[str, str]]:
    hidden_classes: dict[str, str] = {}
    hidden_ids: dict[str, str] = {}
    for style_tag in soup.find_all("style"):
        css_text = style_tag.get_text(" ", strip=True)
        for sel_group, decls in _STYLE_RULE_RE.findall(css_text):
            reason = _style_hidden_reason(decls)
            if not reason:
                continue
            for sel in sel_group.split(","):
                sel = sel.strip()
                if re.fullmatch(r"\.[A-Za-z0-9_-]+", sel):
                    hidden_classes[sel[1:]] = f"style class {sel} ({reason})"
                elif re.fullmatch(r"#[A-Za-z0-9_-]+", sel):
                    hidden_ids[sel[1:]] = f"style id {sel} ({reason})"
    return hidden_classes, hidden_ids


def _hidden_reason(
    tag: Tag, hidden_classes: dict[str, str], hidden_ids: dict[str, str]
) -> str | None:
    if tag.has_attr("hidden"):
        return "HTML hidden attribute"

    tag_id = str(tag.get("id") or "").strip()
    if tag_id and tag_id in hidden_ids:
        return hidden_ids[tag_id]

    for cls in tag.get("class") or []:
        if cls in hidden_classes:
            return hidden_classes[cls]

    style = (tag.get("style") or "").strip()
    if style:
        return _style_hidden_reason(style)
    return None


def _extract_block_aware_text(node: Tag | BeautifulSoup) -> str:
    """Render visible DOM preserving inline flow without inserting line breaks across <b>/<span>."""
    parts: list[str] = []

    def _walk(cur: Tag | NavigableString) -> None:
        if isinstance(cur, Comment):
            return
        if isinstance(cur, NavigableString):
            txt = str(cur)
            if txt:
                parts.append(txt)
            return
        if not isinstance(cur, Tag):
            return
        is_block = cur.name in _BLOCK_TAGS
        if is_block:
            parts.append("\n")
        if cur.name == "br":
            return
        for child in cur.children:
            _walk(child)  # type: ignore[arg-type]
        if is_block:
            parts.append("\n")

    _walk(node)
    joined = "".join(parts)
    lines = [" ".join(line.split()) for line in joined.splitlines()]
    return "\n".join(line for line in lines if line)


def _risk_from_findings(findings: list[ThreatFinding]) -> int:
    weights = {
        Severity.INFO: 0,
        Severity.LOW: 8,
        Severity.MEDIUM: 18,
        Severity.HIGH: 32,
        Severity.CRITICAL: 50,
    }
    score = sum(weights[f.severity] for f in findings)
    return min(100, score)


def sanitize_html_content(html: str, base_url: str = "") -> SanitizeReport:
    soup = BeautifulSoup(html, "html.parser")
    findings: list[ThreatFinding] = []
    hidden_dom_stripped = 0
    comments_stripped = 0

    raw_title = ""
    if soup.title and soup.title.string:
        raw_title = soup.title.string.strip()
    title_no_uni, title_uni_cnt, title_uni_findings = strip_invisible_unicode(raw_title)
    findings.extend(title_uni_findings)
    clean_title, title_inj_cnt, title_inj_findings = scan_injection_patterns(
        title_no_uni, location="html_title", strip_matched_lines=True
    )
    findings.extend(title_inj_findings)

    hidden_classes, hidden_ids = _extract_hidden_css_selectors(soup)

    for noise_name in _NOISE_TAGS:
        for el in soup.find_all(noise_name):
            el.decompose()

    # Inspect and remove HTML comments before smoothing inline text nodes
    for comment in list(soup.find_all(string=lambda text: isinstance(text, Comment))):
        raw_comment = str(comment).strip()
        if raw_comment:
            comments_stripped += 1
            _, _, c_findings = scan_injection_patterns(raw_comment, location="html_comment")
            if c_findings:
                findings.extend(c_findings)
            elif len(raw_comment) >= 24 and any(
                kw in raw_comment.lower()
                for kw in ("recommend", "ignore", "system", "ai", "memory", "推荐", "指令", "记住")
            ):
                findings.append(
                    ThreatFinding(
                        category="suspicious_html_comment",
                        severity=Severity.MEDIUM,
                        description="Stripped HTML comment containing AI/recommendation keywords.",
                        excerpt=raw_comment[:200],
                        location="html_comment",
                    )
                )
        comment.extract()

    # Merge adjacent NavigableStrings split by stripped comments (e.g. Ig<!--x-->nore -> Ignore)
    soup.smooth()

    # Inspect and remove hidden DOM elements BEFORE collecting extracted_links
    for tag in list(soup.find_all(True)):
        if tag.attrs is None:
            continue
        reason = _hidden_reason(tag, hidden_classes, hidden_ids)
        if reason is None:
            continue
        hidden_text = " ".join(tag.get_text(" ", strip=True).split())
        hidden_hrefs = [
            str(a["href"]).strip() for a in tag.find_all("a", href=True) if str(a["href"]).strip()
        ]
        if hidden_text or hidden_hrefs:
            hidden_dom_stripped += 1
            if hidden_text:
                _, _, dom_findings = scan_injection_patterns(
                    hidden_text, location=f"hidden_dom:{reason}"
                )
                if dom_findings:
                    findings.extend(dom_findings)
                else:
                    findings.append(
                        ThreatFinding(
                            category="hidden_dom_text",
                            severity=Severity.HIGH,
                            description=f"Stripped hidden DOM text ({reason}).",
                            excerpt=hidden_text[:200],
                            location="hidden_dom",
                        )
                    )
            if hidden_hrefs:
                findings.append(
                    ThreatFinding(
                        category="hidden_dom_link",
                        severity=Severity.HIGH,
                        description=f"Blocked {len(hidden_hrefs)} link(s) hidden inside invisible DOM ({reason}).",
                        excerpt=", ".join(hidden_hrefs[:3])[:200],
                        location="hidden_dom",
                    )
                )
        tag.decompose()

    # Collect visible links only after hidden DOM nodes have been purged
    extracted_links: list[str] = []
    seen_links: set[str] = set()
    for a_tag in soup.find_all("a", href=True):
        href = str(a_tag["href"]).strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        resolved = urljoin(base_url, href) if base_url else href
        if resolved not in seen_links:
            seen_links.add(resolved)
            extracted_links.append(resolved)

    visible_raw = _extract_block_aware_text(soup.body or soup)
    visible_no_unicode, unicode_count, unicode_findings = strip_invisible_unicode(visible_raw)
    findings.extend(unicode_findings)

    clean_text, stripped_lines, body_findings = scan_injection_patterns(
        visible_no_unicode, location="visible_body", strip_matched_lines=True
    )
    findings.extend(body_findings)

    normalized_lines = [line.strip() for line in clean_text.splitlines() if line.strip()]
    final_text = "\n".join(normalized_lines)

    return SanitizeReport(
        clean_text=final_text,
        title=clean_title.strip(),
        extracted_links=extracted_links,
        injection_risk=_risk_from_findings(findings),
        findings=findings,
        hidden_chars_stripped=unicode_count + title_uni_cnt,
        hidden_dom_blocks_stripped=hidden_dom_stripped,
        comments_stripped=comments_stripped,
        injection_lines_stripped=stripped_lines + title_inj_cnt,
    )


def sanitize_plain_text(text: str) -> SanitizeReport:
    no_unicode, unicode_count, unicode_findings = strip_invisible_unicode(text)
    clean_text, stripped_lines, body_findings = scan_injection_patterns(
        no_unicode, location="plain_text", strip_matched_lines=True
    )
    findings = [*unicode_findings, *body_findings]
    normalized = "\n".join(line.strip() for line in clean_text.splitlines() if line.strip())
    return SanitizeReport(
        clean_text=normalized,
        injection_risk=_risk_from_findings(findings),
        findings=findings,
        hidden_chars_stripped=unicode_count,
        injection_lines_stripped=stripped_lines,
    )
