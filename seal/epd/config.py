"""Configuration for the EPD scanner.

All thresholds and the optional LLM endpoint live here so the scanner itself
stays declarative. Everything has a sensible default; a scanner constructed
with ``EPDConfig()`` runs regex-only with no network access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMConfig:
    """Connection settings for the optional LLM classification pass.

    The scanner only invokes the LLM pass when an :class:`LLMConfig` is
    provided *and* :meth:`is_usable` returns ``True``. No secrets are baked
    in — ``api_key`` is supplied by the caller (typically from an environment
    variable) and never logged.

    Attributes:
        url: Chat-completions-style endpoint URL.
        model: Model identifier to request.
        api_key: Bearer token. Optional for local/keyless endpoints.
        timeout_seconds: Hard timeout for the HTTP call; on timeout the
            scanner falls back to regex-only.
        max_retries: Number of additional attempts on transient failure.
    """

    url: Optional[str] = None
    model: str = "gpt-4o-mini"
    api_key: Optional[str] = None
    timeout_seconds: float = 10.0
    max_retries: int = 0

    def is_usable(self) -> bool:
        """True when enough is configured to attempt an LLM call."""
        return bool(self.url)


@dataclass
class EPDConfig:
    """Top-level EPD configuration.

    Attributes:
        block_threshold: A result is *not* clean if any flag's confidence is
            at or above this value. Default ``0.7``.
        llm_trigger_threshold: Regex flags whose confidence is below this
            value are considered ambiguous and, if an LLM is configured,
            escalated to the LLM pass. Default ``0.7``.
        max_prompt_chars: Prompts longer than this are scanned in full but
            this bound documents the expected operating range; set to ``0``
            to disable any internal length handling. (The regex pass is
            linear and safe on long inputs regardless.)
        llm: Optional LLM connection settings. When ``None`` the LLM pass is
            disabled entirely and scans are regex-only.
        normalize_obfuscation: When ``True`` (default), the regex pass also
            scans a de-obfuscated copy of the prompt (collapsed spacing,
            stripped zero-width characters, homoglyph folding) to catch
            spaced-out / unicode-obfuscated payloads.
    """

    block_threshold: float = 0.7
    llm_trigger_threshold: float = 0.7
    max_prompt_chars: int = 100_000
    llm: Optional[LLMConfig] = None
    normalize_obfuscation: bool = True

    def llm_enabled(self) -> bool:
        """True when an LLM pass could run for this config."""
        return self.llm is not None and self.llm.is_usable()
