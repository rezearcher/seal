"""Write-time EPD scan gate.

Closes the "write-time scanning identified but not implemented" gap from
ARCHITECTURE.md (Phase 4 — Hermes/Division Integration). A :class:`WriteGate`
wraps any persistence callable (memory store, audit trail, file write, tool
result cache, Division ``remember``) and runs the EPD regex scan on the content
*before* it lands, under one of four policies:

* ``block``      — refuse the write entirely; raise :class:`WriteBlockedError`.
* ``sanitize``   — redact the flagged spans, write the sanitized copy.
* ``quarantine`` — divert the original content to a quarantine dir; nothing
                   reaches the destination.
* ``report``     — pass through unchanged; surface the decision via the
                   ``on_decision`` callback / return value for logging.

Design notes:

* Dependency-free. No Division/Hermes imports — the gate can sit in front of
  any persistence path without coupling.
* Redaction uses ``flag.location_in_prompt`` character offsets into the
  *original* string, not the normalized ``evidence`` text, so it is exact even
  for obfuscated / case-shifted payloads.
* Never logs content. The decision record carries the scan result and the
  action taken, not the offending text.
* Offline and zero-runtime-dependency, matching the project constraints.

Usage::

    from seal.epd import WriteGate

    gate = WriteGate(policy="sanitize")
    gate.write(division.remember, content)          # callable target
    gate.write("/tmp/note.txt", content)            # path target

    # or wrap for a drop-in replacement:
    safe_remember = gate.wrap(division.remember)
    safe_remember(content)
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from seal.epd.config import EPDConfig
from seal.epd.models import EPDResult
from seal.epd.scanner import EPDScanner

POLICIES = ("block", "sanitize", "quarantine", "report")

REDACT_PLACEHOLDER = "[EPD:REDACTED:{pattern_name}]"


class WriteBlockedError(Exception):
    """Raised by ``block``-policy gates when the scan is not clean.

    Carries the :class:`WriteDecision` so callers can log or alert on the
    flags without re-scanning.
    """

    def __init__(self, decision: WriteDecision, message: str | None = None) -> None:
        self.decision = decision
        super().__init__(
            message
            or (
                f"EPD write blocked: {len(decision.result.flags)} flag(s), "
                f"max confidence {decision.result.max_confidence:.2f}"
            )
        )


@dataclass(frozen=True)
class WriteDecision:
    """Outcome of a write-time scan.

    ``action`` is one of ``allowed`` / ``blocked`` / ``sanitized`` /
    ``quarantined`` / ``reported``. ``content`` is the bytes/str that
    actually reached the destination (``None`` when nothing was written).
    ``quarantine_path`` is set when the content was diverted.
    """

    action: str
    result: EPDResult
    content: Any | None = None
    quarantine_path: str | None = None

    def __bool__(self) -> bool:
        """Truthy when the write went through (allowed, sanitized, reported)."""
        return self.action in ("allowed", "sanitized", "reported")


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/duplicate (start, end) spans into disjoint ranges."""
    ordered = sorted(spans)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if start < 0 or end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def redact_spans(
    text: str, spans: list[tuple[int, int]], placeholder: str = REDACT_PLACEHOLDER
) -> str:
    """Replace the given character spans in ``text`` with ``placeholder``.

    Spans are merged first; replacements are applied from the end backwards so
    earlier offsets stay valid. Out-of-range spans are clamped.
    """
    if not spans or not text:
        return text
    parts: list[str] = []
    cursor = 0
    for start, end in _merge_spans(spans):
        start = max(0, min(start, len(text)))
        end = max(start, min(end, len(text)))
        parts.append(text[cursor:start])
        parts.append(placeholder)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


class WriteGate:
    """Scan content with EPD before it is persisted.

    :param config: optional :class:`EPDConfig` for the scanner.
    :param policy: one of ``POLICIES`` — ``block`` (default), ``sanitize``,
        ``quarantine``, ``report``.
    :param quarantine_dir: directory for diverted content (required when
        policy is ``quarantine``).
    :param on_decision: optional callback ``fn(decision)`` invoked for every
        scan outcome — wire it to an audit trail or alerting.
    """

    def __init__(
        self,
        *,
        config: EPDConfig | None = None,
        policy: str = "block",
        quarantine_dir: str | os.PathLike[str] | None = None,
        on_decision: Callable[[WriteDecision], Any] | None = None,
    ) -> None:
        if policy not in POLICIES:
            raise ValueError(f"policy must be one of {POLICIES}, got {policy!r}")
        if policy == "quarantine" and quarantine_dir is None:
            raise ValueError("quarantine policy requires quarantine_dir")
        self._scanner = EPDScanner(config)
        self.policy = policy
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir is not None else None
        self.on_decision = on_decision

    # -- core --------------------------------------------------------------

    def check(self, content: str) -> WriteDecision:
        """Scan ``content`` and decide what would happen — no write performed."""
        result = self._scanner.scan(content)
        if result.clean:
            decision = WriteDecision("allowed", result, content=content)
        elif self.policy == "block":
            decision = WriteDecision("blocked", result)
        elif self.policy == "sanitize":
            spans = [flag.location_in_prompt for flag in result.flags]
            decision = WriteDecision(
                "sanitized",
                result,
                content=redact_spans(content, spans),
            )
        elif self.policy == "quarantine":
            decision = WriteDecision("quarantined", result, content=content)
        else:  # report — pass through unchanged, decision surfaced for logging
            decision = WriteDecision("reported", result, content=content)
        if self.on_decision is not None:
            self.on_decision(decision)
        return decision

    # -- writers -----------------------------------------------------------

    def write(
        self,
        target: Callable[[str], Any] | str | os.PathLike[str],
        content: str,
    ) -> WriteDecision:
        """Scan ``content`` and write it to ``target``.

        ``target`` may be a callable (invoked with the content — sanitized
        copy when the policy is ``sanitize``) or a file path.
        """
        decision = self.check(content)
        if decision.action == "blocked":
            raise WriteBlockedError(decision)
        if decision.action == "quarantined":
            qpath = self._quarantine(content)
            return WriteDecision(
                "quarantined", decision.result, quarantine_path=str(qpath)
            )
        # allowed or sanitized
        payload = decision.content
        if callable(target):
            target(payload)
        else:
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
        return decision

    def wrap(self, write_fn: Callable[[str], Any]) -> Callable[[str], WriteDecision]:
        """Return a drop-in replacement for ``write_fn(content)``.

        The wrapper applies the gate and only forwards the content to
        ``write_fn`` when the policy permits (sanitized copy under the
        ``sanitize`` policy). Blocked writes raise :class:`WriteBlockedError`.
        """

        def guarded(content: str) -> WriteDecision:
            return self.write(write_fn, content)

        return guarded

    # -- internals ---------------------------------------------------------

    def _quarantine(self, content: str) -> Path:
        assert self.quarantine_dir is not None  # enforced in __init__
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        digest = hashlib.sha1(content.encode("utf-8")).hexdigest()[:8]
        path = self.quarantine_dir / f"quarantine-{stamp}-{digest}.txt"
        header = (
            f"# EPD quarantine — written {stamp}Z by WriteGate\n"
            f"# sha1[:8] {digest} — content NOT written to destination\n\n"
        )
        path.write_text(header + content, encoding="utf-8")
        return path


def scan_before_write(
    content: str,
    target: Callable[[str], Any] | str | os.PathLike[str],
    *,
    config: EPDConfig | None = None,
    policy: str = "block",
    quarantine_dir: str | os.PathLike[str] | None = None,
    on_decision: Callable[[WriteDecision], Any] | None = None,
) -> WriteDecision:
    """One-shot helper: build a gate and run :meth:`WriteGate.write`."""
    gate = WriteGate(
        config=config,
        policy=policy,
        quarantine_dir=quarantine_dir,
        on_decision=on_decision,
    )
    return gate.write(target, content)
