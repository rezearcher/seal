"""Data classes for EPD scan output."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EPDFlag:
    """A single detected injection signal.

    Attributes:
        pattern_name: Stable identifier for the matched pattern, e.g.
            ``"ignore_instructions"`` or ``"role_switch"``.
        confidence: Detector confidence in ``[0.0, 1.0]``.
        location_in_prompt: ``(start, end)`` character offsets of the match
            within the scanned prompt (Python slice semantics).
        category: The pattern category this flag belongs to (e.g.
            ``"ignore_instructions"``, ``"role_switch"``, ``"delimiter"``,
            ``"hidden_instruction"``, ``"tool_hallucination"``).
        evidence: The matched substring, for human review. Equals
            ``prompt[start:end]`` for ``regex`` flags; for ``normalize`` flags
            covering invisible smuggling it is the *decoded* payload (the raw
            span is invisible), so it intentionally differs from the slice.
        source: Which pass produced the flag — ``"regex"``, ``"llm"``, or
            ``"normalize"`` (invisible-payload smuggling detection).
    """

    pattern_name: str
    confidence: float
    location_in_prompt: tuple[int, int]
    category: str = ""
    evidence: str = ""
    source: str = "regex"


@dataclass
class EPDResult:
    """Aggregate result of a scan.

    Attributes:
        clean: ``True`` when no flag meets the block threshold — i.e. there
            are no flags at all, or every flag is below
            :attr:`~seal.epd.config.EPDConfig.block_threshold`.
        flags: Every detected flag (both regex and, if invoked, LLM), sorted
            by descending confidence.
        llm_used: Whether the LLM classification pass actually ran.
    """

    clean: bool
    flags: list[EPDFlag] = field(default_factory=list)
    llm_used: bool = False

    @property
    def max_confidence(self) -> float:
        """Highest confidence among all flags (0.0 when there are none)."""
        return max((f.confidence for f in self.flags), default=0.0)

    def flags_by_category(self) -> dict[str, list[EPDFlag]]:
        """Group flags by their ``category`` field."""
        grouped: dict[str, list[EPDFlag]] = {}
        for flag in self.flags:
            grouped.setdefault(flag.category, []).append(flag)
        return grouped
