"""Unicode steganography, zero-width, variation selector, control char, and homoglyph guard."""

from __future__ import annotations

import re
import unicodedata

from .models import Severity, ThreatFinding

# Zero-width, soft-hyphen, bidi control, variation selectors, invisible fillers, and C0 controls (except \t\n\r)
_INVISIBLE_CHARS_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    r"\u3164\ufe00-\ufe0f\ufeff\uffa0]"
)
_SUPP_VS_RE = re.compile(r"[\U000e0100-\U000e01ef]")
_ANSI_ESC_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Unicode Tags block U+E0000 - U+E007F (ASCII smuggling)
_UNICODE_TAG_RE = re.compile(r"[\U000e0000-\U000e007f]+")

_CONFUSABLES: dict[str, str] = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "ѕ": "s",
        "Ѕ": "S",
        "ԁ": "d",
        "ԛ": "q",
        "ｗ": "w",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
    }
)


def _decode_unicode_tags(segment: str) -> str:
    chars: list[str] = []
    for ch in segment:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            chars.append(chr(cp - 0xE0000))
    return "".join(chars)


def normalize_for_detection(text: str) -> str:
    """Normalize NFKC fullwidth forms and common Cyrillic/Greek homoglyphs for matching."""
    if not text:
        return ""
    nfkc = unicodedata.normalize("NFKC", text)
    return nfkc.translate(_CONFUSABLES)


def strip_invisible_unicode(text: str) -> tuple[str, int, list[ThreatFinding]]:
    """Strip hidden Unicode, variation selectors, ANSI escapes, and C0 control chars."""
    if not text:
        return "", 0, []

    findings: list[ThreatFinding] = []
    stripped_count = 0

    tag_matches = list(_UNICODE_TAG_RE.finditer(text))
    if tag_matches:
        decoded_parts = []
        for match in tag_matches:
            stripped_count += len(match.group(0))
            decoded = _decode_unicode_tags(match.group(0))
            if decoded:
                decoded_parts.append(decoded)
        text = _UNICODE_TAG_RE.sub("", text)
        decoded_preview = " | ".join(decoded_parts)[:180]
        findings.append(
            ThreatFinding(
                category="unicode_tag_smuggling",
                severity=Severity.CRITICAL,
                description="Detected and stripped Unicode Tag characters (invisible ASCII smuggling).",
                excerpt=decoded_preview or f"{len(tag_matches)} tag sequence(s)",
                location="unicode",
            )
        )

    ansi_matches = _ANSI_ESC_RE.findall(text)
    if ansi_matches:
        stripped_count += sum(len(m) for m in ansi_matches)
        text = _ANSI_ESC_RE.sub("", text)

    supp_matches = _SUPP_VS_RE.findall(text)
    if supp_matches:
        stripped_count += len(supp_matches)
        text = _SUPP_VS_RE.sub("", text)

    inv_matches = _INVISIBLE_CHARS_RE.findall(text)
    if inv_matches or ansi_matches or supp_matches:
        inv_total = len(inv_matches) + len(supp_matches) + len(ansi_matches)
        stripped_count += len(inv_matches)
        text = _INVISIBLE_CHARS_RE.sub("", text)
        severity = Severity.HIGH if inv_total >= 4 else Severity.MEDIUM
        findings.append(
            ThreatFinding(
                category="zero_width_or_control_characters",
                severity=severity,
                description=f"Stripped {inv_total} invisible Unicode, variation-selector, or control characters.",
                excerpt=f"count={inv_total}",
                location="unicode",
            )
        )

    return text, stripped_count, findings
