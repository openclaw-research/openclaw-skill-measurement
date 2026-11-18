"""
Text normalization pass for the v5 static analyzer.

Runs between inventory and matching. Operates on raw text per chunk.
Returns a NormalizationResult so the matcher and findings layer
can see what was changed (useful for FP analysis later).
"""

import re
import unicodedata
from dataclasses import dataclass


# Zero-width and bidi control chars — strip these entirely.
# Covers the standard prompt-injection / ASCII-smuggling block.
_INVISIBLE_CHARS = re.compile(
    r"["
    r"\u200B-\u200D"           # zero-width space, ZWNJ, ZWJ
    r"\uFEFF"                  # BOM
    r"\u202A-\u202E"           # bidi formatting (LRE/RLE/PDF/LRO/RLO)
    r"\u2066-\u2069"           # bidi isolates (LRI/RLI/FSI/PDI)
    r"\U000E0000-\U000E007F"   # tag characters (Snyk ToxicSkills smuggling)
    r"]"
)

# Cyrillic → Latin homoglyph fold. Seven most common confusables.
# NFKC misses these because they aren't compatibility-equivalent.
_HOMOGLYPH_FOLD = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
})


@dataclass
class NormalizationResult:
    text: str
    nfkc_applied: bool = False
    invisible_chars_stripped: int = 0
    homoglyphs_folded: int = 0

    @property
    def any_transform(self) -> bool:
        return (
            self.nfkc_applied
            or self.invisible_chars_stripped > 0
            or self.homoglyphs_folded > 0
        )


def normalize(text: str) -> NormalizationResult:
    """Run the three-step normalization pass on text."""
    result = NormalizationResult(text=text)

    # 1. NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        result.nfkc_applied = True
    text = normalized

    # 2. Strip zero-width and bidi control characters
    stripped = _INVISIBLE_CHARS.sub("", text)
    result.invisible_chars_stripped = len(text) - len(stripped)
    text = stripped

    # 3. Cyrillic → Latin homoglyph fold (common confusables only)
    folded = text.translate(_HOMOGLYPH_FOLD)
    if folded != text:
        result.homoglyphs_folded = sum(
            1 for a, b in zip(text, folded) if a != b
        )
    text = folded

    result.text = text
    return result