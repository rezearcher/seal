"""EPD scanner orchestrator.

Two passes:

1. **Regex** (always): every compiled pattern is evaluated against the raw
   prompt and, when ``normalize_obfuscation`` is on, against a de-obfuscated
   copy whose match offsets are mapped back to raw-prompt coordinates.
|2. **LLM classification** (optional): only when an LLM is configured *and* one of
   two conditions holds:
   a. **llm_scan_all** (new in P7.4): the regex pass produced flags *or* the
      config's ``llm_scan_all`` is ``True`` — runs the LLM on *every* prompt,
      even regex-clean ones, to catch semantic bypasses that leave zero regex
      traces (costly: every prompt incurs an LLM call).
   b. **Default (tiebreaker)**: the regex pass produced flags *and* they are
      all below ``llm_trigger_threshold`` (ambiguous) — the LLM decides
      whether they're real injections or benign.
   Any failure falls back to the regex-only verdict.
"""

from __future__ import annotations

import unicodedata
from typing import Optional

from seal.epd.config import EPDConfig
from seal.epd.models import EPDFlag, EPDResult
from seal.epd.patterns import iter_patterns

# Zero-width / invisible characters (documentary; the predicate below
# generalizes these to *every* Unicode format char so new code points don't
# require table edits).
_ZERO_WIDTH = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
}

# Unicode TAG block (U+E0000–E007F): invisible, ~zero legitimate use in text,
# and the primary carrier for ASCII smuggling (emoji + tag chars that decode
# to a hidden instruction). Category Cf, so the predicate below strips them.
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F

# Variation selectors: VS1–16 (U+FE00–FE0F) + supplement (U+E0100–E01EF).
# Category Mn with combining class 0, so NFKD/combining-mark stripping leaves
# them intact — they need explicit handling. A *single* selector (e.g. U+FE0F
# emoji presentation) is legitimate and ubiquitous; only a run signals
# byte-smuggling (see ``_VS_RUN_THRESHOLD``).
def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _is_invisible(ch: str) -> bool:
    """True for chars to drop before pattern matching.

    Generalizes ``_ZERO_WIDTH`` to all Unicode format chars (category ``Cf`` —
    covers every zero-width/joiner *and* the tag block) plus variation
    selectors. Dropping these collapses interleaving-obfuscation
    (``i<tag>g<tag>nore``) so the visible phrase is matched by the regex pass.
    """
    return unicodedata.category(ch) == "Cf" or _is_variation_selector(ord(ch))


# A run of this many consecutive variation selectors is byte-smuggling, not a
# legitimate single emoji presentation/variation selector.
_VS_RUN_THRESHOLD = 4

# Common homoglyph folds (Cyrillic / Greek / fullwidth -> ASCII) for the
# normalization pass. NFKD handles fullwidth and many compatibility forms;
# this table covers look-alikes NFKD leaves untouched.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ո": "n", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ν": "v", "τ": "t",
}

# Leet-speak / ASCII substitution map (number/punctuation -> letter).
# Applied in the normalization pass alongside homoglyph folding so that
# character-substituted and leet variants of injection phrases are caught.
_LEET_FOLDS = {
    "4": "a",
    "3": "e",
    "0": "o",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
    "1": "l",
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
        if _is_invisible(ch):
            continue
        # Try leet fold first (fast dict lookup for number/punctuation).
        folded = _LEET_FOLDS.get(ch)
        if folded is not None:
            out_chars.append(folded)
            out_map.append(i)
            continue
        # Try homoglyph fold (Cyrillic/Greek look-alikes).
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


def _detect_hidden_unicode(prompt: str) -> list[EPDFlag]:
    """Flag invisible-payload smuggling that survives normalization.

    Two carriers, both invisible to a human reader:

    * **Tag block** — a run of U+E0000–E007F decodes to hidden ASCII. Presence
      alone is high-signal; we also decode the run and re-run the pattern set
      over it so the flag carries *what* was smuggled.
    * **Variation selectors** — a run of >= ``_VS_RUN_THRESHOLD`` selectors is
      the byte-smuggling signature (a lone U+FE0F emoji selector is not).

    Flags point at the raw span of the invisible run; ``evidence`` carries the
    decoded payload (tag) or the raw run (variation selectors).
    """
    flags: list[EPDFlag] = []
    n = len(prompt)
    i = 0
    while i < n:
        cp = ord(prompt[i])

        # -- tag-block run: decode to ASCII and re-scan --------------------- #
        if _TAG_LO <= cp <= _TAG_HI:
            start = i
            decoded: list[str] = []
            while i < n and _TAG_LO <= ord(prompt[i]) <= _TAG_HI:
                d = ord(prompt[i]) - _TAG_LO
                if 0x20 <= d <= 0x7E:  # printable ASCII only
                    decoded.append(chr(d))
                i += 1
            payload = "".join(decoded)
            flags.append(
                EPDFlag(
                    pattern_name="hidden_unicode_tag_smuggling",
                    confidence=0.95,
                    location_in_prompt=(start, i),
                    category="hidden_instruction",
                    evidence=payload,
                    source="normalize",
                )
            )
            # Surface what the hidden payload actually said.
            for pat in iter_patterns():
                if pat.regex.search(payload):
                    flags.append(
                        EPDFlag(
                            pattern_name=f"decoded:{pat.name}",
                            confidence=pat.confidence,
                            location_in_prompt=(start, i),
                            category=pat.category,
                            evidence=payload,
                            source="normalize",
                        )
                    )
            continue

        # -- variation-selector run ---------------------------------------- #
        if _is_variation_selector(cp):
            start = i
            while i < n and _is_variation_selector(ord(prompt[i])):
                i += 1
            if i - start >= _VS_RUN_THRESHOLD:
                flags.append(
                    EPDFlag(
                        pattern_name="hidden_unicode_variation_selectors",
                        confidence=0.9,
                        location_in_prompt=(start, i),
                        category="hidden_instruction",
                        evidence=prompt[start:i],
                        source="normalize",
                    )
                )
            continue

        i += 1
    return flags


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
        if self.config.llm_scan_all_prompts():
            # Catch-all mode: run LLM on every prompt, even regex-clean ones.
            # This catches semantic bypasses that leave zero regex traces.
            llm_flag = self._llm_pass(prompt, flags)
            if llm_flag is not None:
                flags.append(llm_flag)
                llm_used = True
        elif flags and self._should_escalate(flags) and self.config.llm_enabled():
            # Default: LLM as tiebreaker for ambiguous regex hits.
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

        # Invisible-payload smuggling (tag block + variation-selector runs),
        # gated by the same normalization toggle as the de-obfuscation pass.
        if self.config.normalize_obfuscation:
            flags.extend(_detect_hidden_unicode(prompt))

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
