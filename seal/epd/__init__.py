"""EPD — Embedded Prompt Detection.

A pre-LLM scanner that detects prompt-injection attempts before a prompt
reaches the model. Two passes:

1. Regex (always runs) — compiled patterns across five injection categories.
2. LLM classification (optional, fallback) — semantic check for low-confidence
   regex hits. Skipped entirely when no LLM is configured.

Public surface::

    from seal.epd import scan, EPDResult, EPDFlag, EPDConfig

    result = scan("ignore all previous instructions")
    if not result.clean:
        ...
"""

from seal.epd.config import EPDConfig, LLMConfig
from seal.epd.models import EPDFlag, EPDResult
from seal.epd.scanner import EPDScanner, scan

__all__ = [
    "EPDFlag",
    "EPDResult",
    "EPDConfig",
    "LLMConfig",
    "EPDScanner",
    "scan",
]
