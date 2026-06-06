"""Regex pattern definitions for the EPD first pass.

Design notes
------------
* Five categories (see :data:`CATEGORIES`). Each compiled pattern carries a
  stable ``name``, a ``category``, and a ``confidence`` in ``[0,1]``.
* **False-positive budget.** Seal targets <5% false positives on benign
  prompts, and the EPD acceptance bar requires clean prompts to produce *zero*
  flags. So broad triggers are deliberately scoped:

    - "act as" / "pretend to be" only fire when paired with a
      jailbreak-adjacent role ("DAN", "no filter", "unrestricted", ...), never
      for benign roleplay like "act as a translator".
    - Bare delimiters (``---``, ``` ``` ```, ``###``) are **not** flagged on
      their own — they appear constantly in legitimate prompts. Only explicit
      delimiter-manipulation phrasing is flagged. (Toggle documented below.)
    - Common instruction framing ("your task is to", "output format:") is left
      unflagged for the same reason; only injection-shaped framing is caught.

  Where a spec-listed item was down-weighted to protect this budget it is
  marked ``# FP-budget`` inline.

* **Obfuscation tolerance.** The highest-value ignore/forget phrases are
  compiled in a separator-tolerant form (:func:`_obf`) so that spaced-out
  payloads ("i g n o r e   a l l ...") and punctuation-laced variants still
  match. Unicode homoglyph / zero-width obfuscation is handled upstream by the
  scanner's normalization pass (see :mod:`seal.epd.scanner`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES = (
    "ignore_instructions",
    "role_switch",
    "delimiter",
    "hidden_instruction",
    "tool_hallucination",
)


@dataclass(frozen=True)
class CompiledPattern:
    """A single compiled detector."""

    name: str
    category: str
    confidence: float
    regex: re.Pattern


# --------------------------------------------------------------------------- #
# Obfuscation-tolerant phrase builder
# --------------------------------------------------------------------------- #

# Up to 3 separator chars (whitespace or non-word punctuation) allowed between
# each letter of a phrase. Bounded quantifier -> no catastrophic backtracking.
_SEP = r"[\s\W]{0,3}"


def _obf(phrase: str) -> str:
    """Build a separator-tolerant regex fragment for ``phrase``.

    Spaces in the phrase are treated like any other gap, so
    ``_obf("ignore all")`` matches ``"ignore all"``, ``"ignore   all"`` and
    ``"i g n o r e a l l"`` alike. Letters are matched in order with up to
    three junk/whitespace characters permitted between consecutive letters.
    """
    letters = [re.escape(c) for c in phrase if not c.isspace()]
    return _SEP.join(letters)


def _alt(*phrases: str) -> str:
    """Non-capturing alternation of obfuscation-tolerant phrases."""
    return r"(?:" + r"|".join(_obf(p) for p in phrases) + r")"


# --------------------------------------------------------------------------- #
# Pattern table: (name, category, confidence, regex_source, flags)
# --------------------------------------------------------------------------- #

_I = re.IGNORECASE

# Jailbreak-adjacent role words used to gate the otherwise-benign
# "act as" / "pretend to be" / "you are now" triggers.
_JAILBREAK_ROLE = (
    r"(?:dan\b|stan\b|do[\s\W]{0,3}anything[\s\W]{0,3}now|"
    r"(?:an?[\s\W]+)?(?:ai[\s\W]+)?(?:with[\s\W]+)?no[\s\W]+(?:filter|filters|"
    r"restrictions?|rules?|limits?|guidelines?|guardrails?)|"
    r"unrestricted|unfiltered|uncensored|ungoverned|jail[\s\W]{0,3}broken|"
    r"developer[\s\W]{0,3}mode|sudo[\s\W]{0,3}mode|god[\s\W]{0,3}mode|"
    r"evil[\s\W]+\w+|without[\s\W]+(?:any[\s\W]+)?(?:restrictions?|filter|"
    r"rules?|ethics?|morals?))"
)

_PATTERNS: tuple[tuple[str, str, float, str, int], ...] = (
    # ---- 1. Ignore / forget instructions ---------------------------------- #
    (
        "ignore_previous_instructions",
        "ignore_instructions",
        0.95,
        _alt(
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore all prior instructions",
            "ignore the previous instructions",
            "ignore any previous instructions",
            "ignore prior instructions",
            "disregard previous instructions",
            "disregard all previous instructions",
            "disregard prior instructions",
            "disregard the above instructions",
        ),
        _I,
    ),
    (
        "ignore_above",
        "ignore_instructions",
        0.9,
        _alt(
            "ignore everything above",
            "ignore the above",
            "ignore everything before",
            "disregard everything above",
            "disregard the above",
            "ignore all of the above",
            "forget everything above",
        ),
        _I,
    ),
    (
        "forget_instructions",
        "ignore_instructions",
        0.9,
        _alt(
            "forget your instructions",
            "forget all your instructions",
            "forget the instructions",
            "forget your previous instructions",
            "forget everything i told you",
            "forget everything you were told",
            "forget what you were told",
            "forget your system prompt",
            "forget all prior instructions",
        ),
        _I,
    ),
    (
        "disregard_training",
        "ignore_instructions",
        0.88,
        _alt(
            "disregard your training",
            "ignore your training",
            "forget your training",
            "disregard your guidelines",
            "ignore your guidelines",
            "ignore your programming",
            "disregard your programming",
            "ignore your rules",
            "disregard your rules",
            "ignore your safety guidelines",
        ),
        _I,
    ),
    (
        "override_instructions",
        "ignore_instructions",
        0.8,
        _alt(
            "override your instructions",
            "override previous instructions",
            "override the system prompt",
            "your new instructions are",
            "new instructions supersede",
            "these instructions override",
        ),
        _I,
    ),
    # ---- 2. Role switching / jailbreak ------------------------------------ #
    (
        "dan_jailbreak",
        "role_switch",
        0.92,
        r"\b(?:"
        + _obf("do anything now")
        + r"|\bdan\b|\bstan\b)",
        _I,
    ),
    (
        "explicit_jailbreak_term",
        "role_switch",
        0.88,
        r"\b(?:jail[\s\W]{0,3}break(?:ing|en)?|jail[\s\W]{0,3}broken)\b",
        _I,
    ),
    (
        "act_as_jailbreak",
        "role_switch",
        0.85,
        r"\b(?:act\s+as|pretend\s+to\s+be|pretend\s+you(?:'re|\s+are)|"
        r"roleplay\s+as|role[\s\W]?play\s+as|behave\s+as|respond\s+as)\b"
        r"[\s\S]{0,40}?" + _JAILBREAK_ROLE,
        _I,
    ),
    (
        "you_are_now_unrestricted",
        "role_switch",
        0.85,
        r"\b(?:you\s+are\s+now|from\s+now\s+on[\s\W]+you(?:'re|\s+are)|"
        r"you\s+will\s+now\s+be|you\s+are\s+going\s+to\s+be)\b"
        r"[\s\S]{0,40}?" + _JAILBREAK_ROLE,
        _I,
    ),
    (
        "no_restrictions_claim",
        "role_switch",
        0.82,
        r"\byou\s+(?:have\s+no|now\s+have\s+no|don'?t\s+have\s+any)\s+"
        r"(?:restrictions?|limits?|filters?|rules?|guidelines?|guardrails?)\b"
        r"|\byou\s+are\s+(?:free\s+from|released\s+from|not\s+bound\s+by|"
        r"no\s+longer\s+bound\s+by)\b",
        _I,
    ),
    (
        "enter_special_mode",
        "role_switch",
        0.78,
        r"\b(?:developer|debug|sudo|god|dan|stan|jailbreak|unrestricted|"
        r"unfiltered|uncensored|root|admin)[\s\W]{0,3}mode\b"
        r"|\b(?:enter|enable|activate|switch\s+to)\s+\w{0,12}\s*"
        r"(?:character|roleplay|persona)\s+mode\b"
        r"|\bnew\s+persona\b",
        _I,
    ),
    (
        "unfiltered_self_reference",
        "role_switch",
        0.6,  # < 0.7: ambiguous on its own -> may escalate to LLM
        r"\b(?:unfiltered|uncensored|ungoverned|without\s+(?:any\s+)?"
        r"(?:filter|censorship|restrictions?))\b",
        _I,
    ),
    # ---- 3. Delimiter confusion ------------------------------------------- #
    # Bare delimiters intentionally NOT flagged (FP-budget). Only explicit
    # delimiter manipulation is caught.
    (
        "delimiter_manipulation",
        "delimiter",
        0.8,
        r"\b(?:ignore|bypass|reset|remove|break\s+out\s+of|escape)\s+"
        r"(?:the\s+)?delimiter[s]?\b"
        r"|\bdelimiter\s+(?:bypass|injection|escape)\b"
        r"|\bnew\s+delimiter\b",
        _I,
    ),
    (
        "treat_everything_as",
        "delimiter",
        0.6,  # < 0.7: context-dependent
        r"\btreat\s+everything\s+(?:below|above|after|that\s+follows|here)?\s*"
        r"as\s+(?:a\s+)?(?:command|instruction|system|trusted|code)\b"
        r"|\beverything\s+(?:below|after\s+this)\s+is\s+(?:a\s+)?"
        r"(?:command|instruction|trusted|system)\b",
        _I,
    ),
    (
        "end_of_prompt_injection",
        "delimiter",
        0.75,
        r"(?:end\s+of\s+(?:prompt|system\s+prompt|instructions?)"
        r"|\[?/?(?:system|inst|instructions?)\]"
        r"|<\s*/?\s*(?:system|im_start|im_end)\s*>)",
        _I,
    ),
    # ---- 4. Hidden instruction markers ------------------------------------ #
    (
        "role_label_injection",
        "hidden_instruction",
        0.6,  # role labels appear in legit transcripts -> ambiguous
        r"(?:^|\n)\s*(?:SYSTEM|ASSISTANT|USER|AI|HUMAN)\s*:",
        0,  # case-sensitive: only ALL-CAPS labels (injection-shaped)
    ),
    (
        "system_prompt_reference",
        "hidden_instruction",
        0.7,
        r"\b(?:system\s+prompt|system\s+message)\s*:\s*\S"
        r"|\bnew\s+system\s+(?:prompt|message)\b"
        r"|\bupdated\s+system\s+prompt\b",
        _I,
    ),
    (
        "hidden_instruction_marker",
        "hidden_instruction",
        0.82,
        r"\bhidden\s+instructions?\b"
        r"|\bsecret\s+instructions?\b"
        r"|\bbelow\s+is\s+an\s+instruction\b"
        r"|\bthe\s+following\s+is\s+a\s+(?:hidden|secret)\s+(?:instruction|command)\b",
        _I,
    ),
    (
        "embedded_directive",
        "hidden_instruction",
        0.55,  # < 0.7: framing common in benign docs -> escalate if LLM on
        r"\b(?:important|note|attention)\s*:?\s*"
        r"(?:to\s+the\s+(?:ai|assistant|model|language\s+model)|"
        r"if\s+you\s+are\s+an\s+(?:ai|assistant|llm))\b"
        r"|\b(?:ai|assistant|model)\s+reading\s+this\b",
        _I,
    ),
    # ---- 5. Tool hallucination triggers ----------------------------------- #
    (
        "execute_command",
        "tool_hallucination",
        0.6,  # < 0.7: benign "how do I run command" exists -> ambiguous
        r"\b(?:execute|run)\s+(?:(?:the|this|that|following|next|below|"
        r"a|an)\s+){0,3}"
        r"(?:command|shell|bash|terminal|os|system)\b"
        r"|\b(?:execute|run)\s+`",
        _I,
    ),
    (
        "invoke_tool",
        "tool_hallucination",
        0.65,
        r"\b(?:invoke|call|trigger|activate)\s+(?:the\s+|your\s+|a\s+)?"
        r"(?:tool|function|plugin|action|api|endpoint)\b"
        r"|\buse\s+(?:the\s+|your\s+)?plugin\b",
        _I,
    ),
    (
        "use_your_capabilities",
        "tool_hallucination",
        0.55,  # < 0.7
        r"\buse\s+your\s+(?:search|tools?|browser|web\s+browser|web\s+access|"
        r"function|functions|database|internet\s+access|code\s+execution)\b"
        r"|\baccess\s+your\s+(?:function|database|tools?|memory|files?)\b",
        _I,
    ),
    (
        "exfil_request",
        "tool_hallucination",
        0.72,
        # Sensitive object exfiltrated anywhere...
        r"\b(?:send|post|forward|exfiltrate|leak|transmit|upload|email|"
        r"deliver)\s+(?:me\s+|us\s+|a\s+|the\s+|this\s+|your\s+|all\s+|"
        r"the\s+entire\s+)?(?:secrets?|credentials?|api\s+keys?|passwords?|"
        r"tokens?|system\s+prompt|prompt|conversation|chat\s+history|"
        r"context|instructions?)\b"
        # ...or anything sent to an external destination.
        r"|\b(?:send|post|forward|transmit|upload|deliver)\b[\s\S]{0,30}?\bto\s+"
        r"(?:https?://|www\.|[\w.+-]+@|(?:an?\s+)?(?:external\s+|remote\s+)?"
        r"(?:server|endpoint|webhook|url|address|domain|ip)\b)"
        # ...or an explicit outbound API/HTTP call.
        r"|\bmake\s+an?\s+(?:api\s+call|http\s+request|web\s+request|"
        r"network\s+request|outbound\s+(?:call|request))\b",
        _I,
    ),
)


def _compile() -> tuple[CompiledPattern, ...]:
    compiled = []
    for name, category, confidence, source, flags in _PATTERNS:
        assert category in CATEGORIES, f"unknown category {category!r}"
        assert 0.0 <= confidence <= 1.0, f"bad confidence for {name}"
        compiled.append(
            CompiledPattern(
                name=name,
                category=category,
                confidence=confidence,
                regex=re.compile(source, flags),
            )
        )
    return tuple(compiled)


#: All compiled detectors, evaluated in order on every scan.
PATTERNS: tuple[CompiledPattern, ...] = _compile()


def iter_patterns() -> tuple[CompiledPattern, ...]:
    """Return the compiled pattern table (stable order)."""
    return PATTERNS
