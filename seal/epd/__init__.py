"""EPD — Embedded Prompt Detection.

A pre-LLM scanner that detects prompt-injection attempts before a prompt
reaches the model. Two passes:

1. Regex (always runs) — compiled patterns across five injection categories.
2. LLM classification (optional, fallback) — semantic check for low-confidence
   regex hits. Skipped entirely when no LLM is configured.

Public surface::

    from seal.epd import scan, EPDResult, EPDFlag, EPDConfig
    from seal.epd import WriteGate, WriteDecision, WriteBlockedError

    result = scan("ignore all previous instructions")
    if not result.clean:
        ...

    gate = WriteGate(policy="sanitize")          # write-time gate
    gate.write(some_store.write, content)
"""

from seal.epd.config import EPDConfig, LLMConfig
from seal.epd.models import EPDFlag, EPDResult
from seal.epd.scanner import EPDScanner, scan
from seal.epd.write_gate import (
    POLICIES,
    WriteBlockedError,
    WriteDecision,
    WriteGate,
    redact_spans,
    scan_before_write,
)

__all__ = [
    "EPDFlag",
    "EPDResult",
    "EPDConfig",
    "LLMConfig",
    "EPDScanner",
    "scan",
    "POLICIES",
    "WriteGate",
    "WriteDecision",
    "WriteBlockedError",
    "redact_spans",
    "scan_before_write",
]
