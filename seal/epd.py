"""
EPD — Embedded Prompt Detection Scanner.

Two-pass pre-LLM scanner:
1. Regex first-pass for known injection patterns
2. LLM classification pass for ambiguous flags

Runs inside the VPE verification gate.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class EPDFlag:
    """A single detection flag from the EPD scanner.

    Attributes:
        pattern_name: Name of the matching pattern.
        confidence: 0.0 to 1.0 confidence that this is a real injection.
        location: Where in the prompt the match occurred (start char index).
        snippet: The matched text fragment.
    """

    __slots__ = ("pattern_name", "confidence", "location", "snippet")

    def __init__(self, pattern_name: str, confidence: float, location: int, snippet: str = ""):
        self.pattern_name = pattern_name
        self.confidence = confidence
        self.location = location
        self.snippet = snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "confidence": self.confidence,
            "location": self.location,
            "snippet": self.snippet,
        }

    def __repr__(self) -> str:
        return f"<EPDFlag {self.pattern_name} ({self.confidence:.0%}) @{self.location}>"


class EPDResult:
    """Result from an EPD scan.

    Attributes:
        clean: True if no injection detected.
        flags: List of EPDFlag objects.
        llm_used: Whether the LLM classification pass was invoked.
        llm_verdict: The LLM's verdict (if llm_used), or None.
    """

    __slots__ = ("clean", "flags", "llm_used", "llm_verdict")

    def __init__(
        self,
        clean: bool,
        flags: Optional[List[EPDFlag]] = None,
        llm_used: bool = False,
        llm_verdict: Optional[str] = None,
    ):
        self.clean = clean
        self.flags = flags or []
        self.llm_used = llm_used
        self.llm_verdict = llm_verdict

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "flags": [f.to_dict() for f in self.flags],
            "llm_used": self.llm_used,
            "llm_verdict": self.llm_verdict,
        }

    def __repr__(self) -> str:
        return f"<EPDResult clean={self.clean} flags={len(self.flags)} llm={self.llm_used}>"


# ---------------------------------------------------------------------------
# Regex patterns (first pass)
# ---------------------------------------------------------------------------

# Pattern categories following the architecture doc.

_PATTERNS: List[Dict[str, Any]] = [
    # --- Ignore/forget instructions ---
    {
        "name": "ignore_previous",
        "confidence": 0.85,
        "regex": re.compile(
            r"(?:ignore|disregard|forget|skip|drop|override|discard|neglect)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|former|aforementioned|given)\s+"
            r"(?:instructions|commands|directives|prompts|orders|rules|system\s+prompt)",
            re.IGNORECASE,
        ),
    },
    {
        "name": "ignore_context",
        "confidence": 0.80,
        "regex": re.compile(
            r"(?:ignore|disregard|forget|skip)\s+(?:the\s+)?"
            r"(?:above|context|conversation|chat\s+history|everything)",
            re.IGNORECASE,
        ),
    },
    # --- Role-switching (DAN, character prompts) ---
    {
        "name": "dan_style_jailbreak",
        "confidence": 0.90,
        "regex": re.compile(
            r"(?:act\s+as\s+)?(?:dan|do\s+(?:anything\s+)?now|superior\s+mode|"
            r"developer\s+mode|jailbreak|unfiltered|no\s+(?:restrictions|limits|"
            r"boundaries|filter|rules|censorship|safety))",
            re.IGNORECASE,
        ),
    },
    {
        "name": "role_switch",
        "confidence": 0.75,
        "regex": re.compile(
            r"you\s+are\s+(?:now\s+)?(?:a\s+)?(?:free|unconstrained|unleashed|"
            r"unfiltered|uncensored|rebel|new\s+persona|game\s+master|narrator|"
            r"storyteller|character)\s+",
            re.IGNORECASE,
        ),
    },
    {
        "name": "character_jailbreak",
        "confidence": 0.70,
        "regex": re.compile(
            r"(?:pretend|imagine|roleplay|act\s+as\s+if)\s+you\s+are\s+.{5,100}?"
            r"(?:and\s+(?:can|will|must)\s+(?:ignore|bypass|disable|remove|forget))",
            re.IGNORECASE,
        ),
    },
    # --- Delimiter confusion ---
    {
        "name": "delimiter_breakout",
        "confidence": 0.85,
        "regex": re.compile(
            r"(?:\|\|\||```|__END__|<\|im_end\|>|<\|sys_end\|>|<\|assistant_end\|>|<\|user_end\|>)",
            re.IGNORECASE,
        ),
    },
    {
        "name": "markdown_delimiter_jailbreak",
        "confidence": 0.75,
        "regex": re.compile(
            r"(?:(?<=\n)```\s*(?:\w+)?\s*\n[\s\S]*?\n```)",
            re.IGNORECASE,
        ),
    },
    # --- Hidden instruction markers ---
    {
        "name": "hidden_instruction",
        "confidence": 0.80,
        "regex": re.compile(
            r"(?:(?:new\s+)?instruction|command|directive|order|task)\s*[:：]\s*"
            r"(?:ignore|disregard|revert|override|forget)\s",
            re.IGNORECASE,
        ),
    },
    {
        "name": "instruction_injection",
        "confidence": 0.75,
        "regex": re.compile(
            r"(?:(?:system|user|assistant)\s*(?:message|prompt|instruction|command)\s*[:：])",
            re.IGNORECASE,
        ),
    },
    # --- Tool hallucination triggers ---
    {
        "name": "tool_hallucination",
        "confidence": 0.70,
        "regex": re.compile(
            r"(?:call|invoke|execute)\s+(?:the\s+)?(?:function|tool|action|api)\s+"
            r"(?:named\s+)?['\"]?\w+['\"]?\s*(?:\(|with|to|that)",
            re.IGNORECASE,
        ),
    },
    # --- Base64 / encoded payloads ---
    {
        "name": "encoded_payload_base64",
        "confidence": 0.80,
        "regex": re.compile(
            r"(?:[A-Za-z0-9+/]{40,}={0,2})",
        ),
    },
    # --- Prompt leakage ---
    {
        "name": "system_prompt_leak",
        "confidence": 0.85,
        "regex": re.compile(
            r"(?:print|display|show|reveal|output|dump|leak|exfiltrate|echo)\s+"
            r"(?:(?:your|the|my)\s+)?(?:system\s+)?(?:prompt|instructions|directives|"
            r"prompt|initial\s+prompt|system\s+message|meta\s+instructions)",
            re.IGNORECASE,
        ),
    },
    # --- Prompt extraction ---
    {
        "name": "prompt_extraction",
        "confidence": 0.80,
        "regex": re.compile(
            r"(?:repeat|say|tell|output|return|give|spill|copy)\s+(?:the\s+)?"
            r"(?:whole|entire|full|complete|exact)\s+(?:text|prompt|instruction|message|response|output)",
            re.IGNORECASE,
        ),
    },
    # --- Multi-language jailbreak ---
    {
        "name": "jailbreak_non_english",
        "confidence": 0.60,
        "regex": re.compile(
            r"\b(?:先|忽略|无视)\s*(?:以上|之前|前面).{0,20}(?:指令|指示|要求|规则)",
        ),
    },
]

# ---------------------------------------------------------------------------
# Regex first pass
# ---------------------------------------------------------------------------

# Minimum length to run the regex pass (avoids trivial prompts)
_MIN_PROMPT_LENGTH = 10


def _regex_scan(prompt: str) -> List[EPDFlag]:
    """Run the regex first-pass scan.

    Args:
        prompt: The text to scan.

    Returns:
        List of EPDFlag objects for matches found.
    """
    if len(prompt) < _MIN_PROMPT_LENGTH:
        return []

    flags: List[EPDFlag] = []
    for pattern in _PATTERNS:
        rx = pattern["regex"]
        for match in rx.finditer(prompt):
            flags.append(EPDFlag(
                pattern_name=pattern["name"],
                confidence=pattern["confidence"],
                location=match.start(),
                snippet=match.group()[:120],  # cap snippet length
            ))
    return flags


# ---------------------------------------------------------------------------
# LLM classification pass (optional)
# ---------------------------------------------------------------------------


def _llm_classify(prompt: str, flags: List[EPDFlag]) -> Tuple[Optional[str], List[EPDFlag]]:
    """Run LLM-based classification on ambiguous flags.

    This is a stub by default — the actual LLM call is injected by the
    Hermes integration. Without a configured LLM, this returns None.

    Returns:
        (llm_verdict, refined_flags): verdict string and refined flag list.
    """
    # In production, this would call an LLM with a prompt like:
    # "Given the following user prompt, is this a prompt injection attack?
    #  Context: {prompt}
    #  Flagged patterns: {flags}
    #  Respond with YES, NO, or UNCERTAIN."
    #
    # For the reference implementation, we pass through the regex flags.
    return (None, flags)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def epd_scan(
    prompt: str,
    *,
    use_llm: bool = False,
    llm_classifier_fn=None,
    min_confidence: float = 0.0,
) -> EPDResult:
    """Scan a prompt for embedded injection attempts.

    Two-pass design:
    1. Regex first-pass — fast pattern matching
    2. LLM classification pass (optional) — for ambiguous results

    Args:
        prompt: The prompt text to scan (user input, document content, etc.).
        use_llm: If True, run the LLM classification pass on flagged prompts.
        llm_classifier_fn: Callable(prompt, flags) -> (verdict, refined_flags).
        min_confidence: Minimum confidence threshold to include flags.

    Returns:
        EPDResult with detection findings.
    """
    if not prompt or not prompt.strip():
        return EPDResult(clean=True)

    # Pass 1: Regex scan
    flags = _regex_scan(prompt)
    llm_used = False
    llm_verdict = None

    # Pass 2: LLM classification (only for ambiguous regex flags)
    if use_llm and flags:
        classifier = llm_classifier_fn or _llm_classify
        try:
            llm_verdict, refined = classifier(prompt, flags)
            flags = refined
            llm_used = True
        except Exception as exc:
            logger.warning("EPD LLM classifier failed: %s", exc)
            # Fall through with regex-only results

    # Apply confidence filter
    if min_confidence > 0:
        flags = [f for f in flags if f.confidence >= min_confidence]

    clean = len(flags) == 0
    return EPDResult(clean=clean, flags=flags, llm_used=llm_used, llm_verdict=llm_verdict)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def list_patterns() -> List[Dict[str, Any]]:
    """List all registered EPD patterns with metadata.

    Returns:
        List of pattern dicts (without compiled regex objects).
    """
    result = []
    for p in _PATTERNS:
        result.append({
            "name": p["name"],
            "confidence": p["confidence"],
            "pattern": p["regex"].pattern,
        })
    return result


def add_pattern(name: str, confidence: float, regex_pattern: str) -> None:
    """Add a custom detection pattern at runtime.

    Args:
        name: Pattern name.
        confidence: Confidence score (0.0-1.0).
        regex_pattern: Regular expression string.
    """
    compiled = re.compile(regex_pattern, re.IGNORECASE)
    _PATTERNS.append({
        "name": name,
        "confidence": confidence,
        "regex": compiled,
    })
