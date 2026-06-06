"""EPD scanner orchestrator.

Two passes:

1. **Regex** (always): every compiled pattern is evaluated against the raw
   prompt and, when ``normalize_obfuscation`` is on, against a de-obfuscated
   copy whose match offsets are mapped back to raw-prompt coordinates.
2. **LLM classification** (optional): only when an LLM is configured *and* the
   regex pass produced flags that are all below ``llm_trigger_threshold``
   (ambiguous). Any failure falls back to the regex-only verdict.
"""

from __future__ import annotations

import unicodedata
from typing import Optional

from seal.epd.config import EPDConfig
from seal.epd.models import EPDFlag, EPDResult
from seal.epd.patterns import iter_patterns

# Zero-width / invisible characters stripped during normalization.
_ZERO_WIDTH = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}

# Common homoglyph folds (Cyrillic / Greek / fullwidth -> ASCII) for the
# normalization pass. NFKD handles fullwidth and many compatibility forms;
# this table covers look-alikes NFKD leaves untouched.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ո": "n", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ν": "v", "τ": "t",
}


def _normalize_with_map(text: str) -> tuple[str, list[int]]:
    """De-obfuscate ``text``, returning ``(normalized, index_map)``.

    ``index_map[i]`` is the offset in the original ``text`` of the character
    that produced ``normalized[i]`` — so a match span ``[a, b)`` in the
    normalized string maps back to ``[index_map[a], index_map[b-1] + 1)`` in
    the original. Stripped characters contribute nothing to the normalized
    string but never break the mapping.
    """
    out_chars: list[str] = []
    out_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        folded = _HOMOGLYPHS.get(ch)
        if folded is None:
            # NFKD then drop combining marks (e.g. accents used to obfuscate).
            decomposed = unicodedata.normalize("NFKD", ch)
            folded = "".join(c for c in decomposed if not unicodedata.combining(c))
            if not folded:
                # Pure combining mark on its own — drop it.
                continue
        for fc in folded:
            out_chars.append(fc)
            out_map.append(i)
    return "".join(out_chars), out_map


class EPDScanner:
    """Stateful, reusable EPD scanner.

    Patterns are compiled once at import time; an instance just binds a
    :class:`~seal.epd.config.EPDConfig`. Instances are safe to reuse across
    many ``scan`` calls and hold no per-scan state.
    """

    def __init__(self, config: Optional[EPDConfig] = None) -> None:
        self.config = config or EPDConfig()

    # -- public API -------------------------------------------------------- #

    def scan(self, prompt: str) -> EPDResult:
        """Scan ``prompt`` and return an :class:`EPDResult`."""
        if prompt is None:
            raise TypeError("prompt must be a string, not None")
        if not isinstance(prompt, str):
            raise TypeError(f"prompt must be a string, got {type(prompt).__name__}")

        flags = self._regex_pass(prompt)

        llm_used = False
        if flags and self._should_escalate(flags) and self.config.llm_enabled():
            llm_flag = self._llm_pass(prompt, flags)
            if llm_flag is not None:
                flags.append(llm_flag)
                llm_used = True

        flags.sort(key=lambda f: f.confidence, reverse=True)
        clean = not any(f.confidence >= self.config.block_threshold for f in flags)
        return EPDResult(clean=clean, flags=flags, llm_used=llm_used)

    # -- pass 1: regex ----------------------------------------------------- #

    def _regex_pass(self, prompt: str) -> list[EPDFlag]:
        seen: set[tuple[str, int, int]] = set()
        flags: list[EPDFlag] = []

        def collect(text: str, mapper) -> None:
            for pat in iter_patterns():
                for m in pat.regex.finditer(text):
                    start, end = m.span()
                    if start == end:
                        continue
                    raw_start, raw_end = mapper(start, end)
                    key = (pat.name, raw_start, raw_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    flags.append(
                        EPDFlag(
                            pattern_name=pat.name,
                            confidence=pat.confidence,
                            location_in_prompt=(raw_start, raw_end),
                            category=pat.category,
                            evidence=prompt[raw_start:raw_end],
                            source="regex",
                        )
                    )

        # Raw pass — offsets are already in prompt coordinates.
        collect(prompt, lambda s, e: (s, e))

        # Normalized pass — map offsets back through index_map.
        if self.config.normalize_obfuscation:
            norm, index_map = _normalize_with_map(prompt)
            if norm and norm != prompt:
                def mapper(s: int, e: int) -> tuple[int, int]:
                    raw_s = index_map[s]
                    raw_e = index_map[e - 1] + 1
                    return raw_s, raw_e

                collect(norm, mapper)

        return flags

    def _should_escalate(self, flags: list[EPDFlag]) -> bool:
        """True when every flag is ambiguous (below the LLM trigger threshold).

        If any regex flag is already confident enough to block, there's no
        value in spending an LLM call — the verdict is settled.
        """
        threshold = self.config.llm_trigger_threshold
        return all(f.confidence < threshold for f in flags)

    # -- pass 2: LLM (optional) ------------------------------------------- #

    def _llm_pass(self, prompt: str, regex_flags: list[EPDFlag]) -> Optional[EPDFlag]:
        """Run the optional LLM classification pass.

        Returns a single synthesized :class:`EPDFlag` on a confident
        ``injection`` verdict, or ``None`` when the LLM says clean, is
        unavailable, errors, or times out (regex-only fallback).
        """
        from seal.epd.llm_classifier import classify

        verdict = classify(prompt, self.config.llm, regex_flags)
        if verdict is None or verdict.label != "injection":
            return None

        # Anchor the flag on the LLM's evidence text if we can locate it,
        # otherwise span the whole prompt.
        loc = (0, len(prompt))
        if verdict.evidence:
            idx = prompt.find(verdict.evidence)
            if idx != -1:
                loc = (idx, idx + len(verdict.evidence))

        return EPDFlag(
            pattern_name="llm_injection_classification",
            confidence=verdict.confidence,
            location_in_prompt=loc,
            category="llm",
            evidence=verdict.evidence or "",
            source="llm",
        )


# --------------------------------------------------------------------------- #
# Module-level convenience
# --------------------------------------------------------------------------- #

_DEFAULT_SCANNER = EPDScanner()


def scan(prompt: str, config: Optional[EPDConfig] = None) -> EPDResult:
    """Scan ``prompt`` with the default (regex-only) scanner or a custom one.

    ``scan("...")`` is regex-only and makes no network calls. Pass a
    ``config`` carrying an :class:`~seal.epd.config.LLMConfig` to enable the
    optional LLM pass.
    """
    scanner = _DEFAULT_SCANNER if config is None else EPDScanner(config)
    return scanner.scan(prompt)
