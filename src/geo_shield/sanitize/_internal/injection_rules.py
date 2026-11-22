"""Bilingual (EN/ZH) indirect prompt injection and memory poisoning detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity, ThreatFinding
from .unicode_guard import normalize_for_detection


@dataclass(frozen=True)
class _Rule:
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str


_RULES: tuple[_Rule, ...] = (
    _Rule(
        category="instruction_override",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(ignore|disregard|forget|override)\s+(?:the\s+|your\s+|all\s+|any\s+|these\s+)?(previous|prior|above|system|earlier)\s+(instructions?|prompts?|rules?|directives?)",
            re.IGNORECASE,
        ),
        description="English instruction-override payload attempting to hijack model control flow.",
    ),
    _Rule(
        category="instruction_override",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(system\s+override|developer\s+mode|jailbreak\s+mode|you\s+are\s+now\s+(?:an?\s+)?unrestricted|"
            r"enter\s+developer\s+mode)",
            re.IGNORECASE,
        ),
        description="System/role override command detected.",
    ),
    _Rule(
        category="instruction_override",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(忽略|无视|忘记|覆盖|取消)(以上|之前|此前|所有|全部|系统)?(所有|全部)?(指令|规则|设定|提示词|约束)|"
            r"(从现在起|现在开始|作为\s*AI|作为人工智能)[，,：:\s]*(你必须|请务必|强制要求)|"
            r"进入(开发者模式|无限制模式|越狱模式)"
        ),
        description="检测到中文指令劫持/系统设定覆盖暗语。",
    ),
    _Rule(
        category="memory_recommendation_poisoning",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(always\s+recommend|only\s+recommend|prefer\s+[\w\-\s]{1,40}\s+over|"
            r"(?:save|write|store|add|commit)\s+(?:this\s+|that\s+|it\s+)?(?:to|into)\s+(?:your\s+|long[- ]term\s+)?memory|"
            r"remember\s+(?:that\s+)?.{1,80}?(?:(?:is|are)\s+(?:always\s+)?(?:the\s+)?(?:best|most\s+trusted|number\s+one|#1|preferred|top\s+choice)|always\s+recommend)|"
            r"when\s+summarizing.{0,60}?(?:present|position|recommend).{0,60}?(?:safest|best|default|top|standard)|"
            r"keep\s+this\s+preference\s+for\s+future|as\s+(?:the\s+)?default\s+choice\s+for\s+all\s+users)",
            re.IGNORECASE,
        ),
        description="English AI recommendation or persistent memory poisoning instruction.",
    ),
    _Rule(
        category="memory_recommendation_poisoning",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(记住|写入记忆|存入长期记忆|写入长期记忆|永久记住|保存为偏好).{0,60}?(首选|最可信|排名第一|唯一推荐|优先推荐|最佳|最好|优先提及)|"
            r"(?:把|将).{1,30}(?:存入长期记忆|写入长期记忆)|"
            r"(永远推荐|始终推荐|只推荐|优先推荐|必须首推|默认推荐|大力推荐|优先考虑并.{0,12}?推荐).{1,40}|"
            r"(把|将).{1,30}(设为|记为)(首选|最值得信赖|第一推荐)"
        ),
        description="检测到试图污染 AI 长期记忆或强制偏置推荐结果的中文投毒指令。",
    ),
    _Rule(
        category="role_tag_spoofing",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(<\s*/?(?:system|developer|assistant|instruction|prompt_override)\s*>|"
            r"\[\s*(?:SYSTEM|DEVELOPER|/?INST|OVERRIDE)\s*\]|"
            r"<\|im_start\|>\s*(?:system|developer)|<\|im_end\|>|<<\s*/?SYS\s*>>|"
            r"###\s*(?:System|Developer)\s+Instruction)",
            re.IGNORECASE,
        ),
        description="Spoofed chat/role control tag embedded inside external content.",
    ),
    _Rule(
        category="hidden_directive_framing",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(NOTE\s+TO\s+(?:AI|LLM|ASSISTANT|MODEL)|ATTENTION\s+(?:AI|CHATGPT|GEMINI|CLAUDE)|"
            r"致\s*(?:AI|大模型|人工智能|助手|Gemini|ChatGPT|Kimi|Claude)\s*(?:的指令|注意|提示))",
            re.IGNORECASE,
        ),
        description="Explicit meta-instruction addressed directly to an AI reader.",
    ),
)

_META_DISCUSSION_RE = re.compile(
    r"(phrases?\s+like|such\s+as|for\s+example|e\.g\.|attackers?\s+(?:often|frequently|typically|embed|use|inject)|"
    r"prompt\s+injection|indirect\s+injection|jailbreak|security\s+(?:research|defense|example)|"
    r"vulnerability|demonstrat(?:e|ing)|common\s+example|seen\s+in\s+the\s+wild|"
    r"攻击者|示例|举例|例如|常见话术|提示注入|防御研究|漏洞原理)",
    re.IGNORECASE,
)

_PAIR_QUOTES = (
    ("'", "'"),
    ('"', '"'),
    ("“", "”"),
    ("‘", "’"),
    ("`", "`"),
)


def _is_quoted_meta_discussion(
    location: str, context_text: str, match_start: int, match_end: int
) -> bool:
    """Suppress false-positive deletions when visible prose quotes injection examples."""
    if location not in {"visible_body", "plain_text"}:
        return False
    if not _META_DISCUSSION_RE.search(context_text):
        return False

    before = context_text[:match_start]
    after = context_text[match_end:]
    for q_open, q_close in _PAIR_QUOTES:
        if q_open == q_close:
            if before.count(q_open) % 2 == 1 and q_close in after:
                return True
        else:
            last_open = before.rfind(q_open)
            last_close = before.rfind(q_close)
            if last_open > last_close and q_close in after:
                return True

    # Even without quotes, explicit meta-framing on the exact same line (e.g. Wikipedia example blocks)
    return bool(
        re.search(
            r"(?:attackers?\s+(?:embed|use|inject)|phrases?\s+like|common\s+example|for\s+example\s*:|"
            r"prompt\s+injection\s+(?:attack|example)|攻击者常|提示注入示例)",
            context_text,
            re.IGNORECASE,
        )
    )


def _build_collapsed_view(lines: list[str]) -> tuple[str, list[int]]:
    """Collapse line breaks/runs of whitespace into single spaces and track each char's line index."""
    chars: list[str] = []
    char_to_line: list[int] = []
    prev_space = True

    for line_idx, raw_line in enumerate(lines):
        norm_line = normalize_for_detection(raw_line)
        for ch in norm_line:
            if ch.isspace():
                if not prev_space:
                    chars.append(" ")
                    char_to_line.append(line_idx)
                    prev_space = True
            else:
                chars.append(ch)
                char_to_line.append(line_idx)
                prev_space = False
        if not prev_space:
            chars.append(" ")
            char_to_line.append(line_idx)
            prev_space = True

    if chars and chars[-1] == " ":
        chars.pop()
        char_to_line.pop()
    return "".join(chars), char_to_line


def scan_injection_patterns(
    text: str, *, location: str = "body", strip_matched_lines: bool = False
) -> tuple[str, int, list[ThreatFinding]]:
    """Scan text (single-line + cross-line collapsed) for indirect prompt injections."""
    if not text:
        return "", 0, []

    findings: list[ThreatFinding] = []
    seen_excerpts: set[tuple[str, str]] = set()
    matched_line_indices: set[int] = set()

    lines = text.splitlines()

    # Pass 1: Line-by-line scan (normalized for NFKC/homoglyphs)
    for idx, raw_line in enumerate(lines):
        norm_line = normalize_for_detection(raw_line)
        for rule in _RULES:
            match = rule.pattern.search(norm_line)
            if not match:
                continue
            if _is_quoted_meta_discussion(location, norm_line, match.start(), match.end()):
                excerpt = raw_line.strip()[:220]
                key = ("quoted_injection_discussion", excerpt)
                if key not in seen_excerpts:
                    seen_excerpts.add(key)
                    findings.append(
                        ThreatFinding(
                            category="quoted_injection_discussion",
                            severity=Severity.INFO,
                            description="Quoted injection phrase inside educational/security discussion (kept).",
                            excerpt=excerpt,
                            location=location,
                        )
                    )
                continue

            matched_line_indices.add(idx)
            excerpt = raw_line.strip()[:220]
            key = (rule.category, excerpt)
            if key not in seen_excerpts:
                seen_excerpts.add(key)
                findings.append(
                    ThreatFinding(
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        excerpt=excerpt,
                        location=location,
                    )
                )

    # Pass 2: Cross-line collapsed scan to catch newline / %0A / tag-split obfuscation
    collapsed, char_to_line = _build_collapsed_view(lines)
    if collapsed:
        for rule in _RULES:
            for match in rule.pattern.finditer(collapsed):
                start, end = match.start(), match.end()
                if start >= len(char_to_line):
                    continue
                span_lines = set(char_to_line[start:end])
                if span_lines.issubset(matched_line_indices):
                    continue
                ctx_lo = max(0, start - 80)
                ctx_hi = min(len(collapsed), end + 80)
                ctx_slice = collapsed[ctx_lo:ctx_hi]
                if _is_quoted_meta_discussion(
                    location, ctx_slice, start - ctx_lo, end - ctx_lo
                ):
                    continue
                matched_line_indices.update(span_lines)
                excerpt = collapsed[start:end].strip()[:220]
                key = (rule.category, excerpt)
                if key not in seen_excerpts:
                    seen_excerpts.add(key)
                    findings.append(
                        ThreatFinding(
                            category=rule.category,
                            severity=rule.severity,
                            description=f"{rule.description} (cross-line normalized match)",
                            excerpt=excerpt,
                            location=location,
                        )
                    )

    if strip_matched_lines and matched_line_indices:
        kept = [line for idx, line in enumerate(lines) if idx not in matched_line_indices]
        return "\n".join(kept), len(matched_line_indices), findings

    return text, len(matched_line_indices), findings
