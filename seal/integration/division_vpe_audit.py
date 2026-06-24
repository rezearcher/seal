"""
Division VPE Audit — VPE verification results as Division memory episodes.

Every VPE verification result is stored in Division's shared memory as a
structured episode, making the full audit trail queryable across agents.

Design:
  - Primary path: write to Division memory via MCP remember function
  - Fallback: local JSONL audit log (P6.4a) when Division is unavailable
  - Dual-write: always log locally first, then attempt Division
  - Each episode includes: envelope_hash, issuer, result, reason, timestamp, audit_id

Query patterns:
  - "show me all rejected prompts in the last hour"
    → Division search: query="result:invalid" + recency check
  - "show audit trail for envelope abc123"
    → Recall by key: key="vpe:abc123"
  - "all episodes from issuer agent:hermes"
    → Division search: query="issuer:agent:hermes"

Usage:
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    audit = DivisionVPEAudit()
    audit.record(
        envelope_hash="abc123def456",
        issuer="agent:hermes-default",
        result="invalid",
        reason="signature mismatch",
        tool_name="terminal",
    )
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONVERSATION_ID = "vpe-audit-trail"
"""Division conversation ID for VPE audit episodes."""

AUDIT_DOMAIN = "vpe-audit"
"""Division memory domain for audit entries."""

AUDIT_CATEGORY = "verification"
"""Division memory category for verification results."""

VALID_RESULTS = ("valid", "invalid", "expired", "error", "unverified")
"""Recognized verification result types."""

# ---------------------------------------------------------------------------
# DivisionVPEAudit
# ---------------------------------------------------------------------------


class DivisionVPEAudit:
    """VPE verification audit trail backed by Division memory.

    Records every VPE verification result as a Division memory episode
    with a structured schema. Falls back to local JSONL logging when
    Division is unavailable.

    The class uses dependency injection for the Division ``remember``
    function so it works in both Hermes MCP contexts (where the tool is
    available) and test environments (where a mock is provided).

    Attributes:
        audit_log: Local AuditLog instance for fallback (P6.4a).
        conversation_id: Division conversation ID for audit episodes.
        remember_func: Optional callable to write to Division memory.
            Signature: ``(conversation_id, agent, key, value, **kwargs) -> dict``
    """

    def __init__(
        self,
        audit_log: Any = None,
        conversation_id: str = DEFAULT_CONVERSATION_ID,
        remember_func: Optional[Callable] = None,
    ):
        """Initialize DivisionVPEAudit.

        Args:
            audit_log: Local AuditLog instance. If None, imports from seal.audit.
            conversation_id: Division conversation for audit episodes.
            remember_func: Optional MCP remember function for Division writes.
                When provided, this is the primary write path. When None,
                the class falls back to ``_try_hybrid_write`` which attempts
                an HTTP-API-based write to Division first.
        """
        if audit_log is not None:
            self.audit_log = audit_log
        else:
            from seal.audit import AuditLog
            self.audit_log = AuditLog()

        self.conversation_id = conversation_id
        self._remember_func = remember_func
        self._division_available: Optional[bool] = None  # lazy check

        # Track episode IDs for cross-referencing
        self._last_episode_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        envelope_hash: str,
        issuer: str,
        result: str,
        reason: str = "",
        tool_name: str = "",
        audit_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record a VPE verification result.

        Always writes to the local JSONL audit log first (P6.4a fallback).
        Then attempts to write to Division memory.

        Args:
            envelope_hash: SHA-256 hex digest of the verified envelope.
            issuer: The ``issuer`` field from the envelope (e.g. ``"user:rez"``).
            result: One of ``"valid"``, ``"invalid"``, ``"expired"``,
                    ``"error"``, or ``"unverified"``.
            reason: Human-readable reason / error detail.
            tool_name: The Hermes tool that triggered verification (e.g. ``"terminal"``).
            audit_id: Optional explicit audit ID. Auto-generated if omitted.
            extra: Optional extra metadata to include in the record.

        Returns:
            The audit_id for this entry (for cross-referencing).

        Raises:
            ValueError: If ``result`` is not a recognized value.
        """
        if result not in VALID_RESULTS:
            raise ValueError(
                f"Invalid result '{result}'. Must be one of: {VALID_RESULTS}"
            )

        audit_id = audit_id or _generate_audit_id()
        timestamp = time.time()
        timestamp_iso = datetime.now(timezone.utc).isoformat()

        record: Dict[str, Any] = {
            "audit_id": audit_id,
            "envelope_hash": envelope_hash,
            "issuer": issuer,
            "result": result,
            "reason": reason,
            "tool_name": tool_name,
            "timestamp": timestamp,
            "timestamp_iso": timestamp_iso,
            "agent": "seal-vpe",
        }
        if extra:
            # Merge extra fields, but don't overwrite standard keys
            for k, v in extra.items():
                if k not in record:
                    record[k] = v

        # 1. Always log locally (P6.4a — durable local audit)
        try:
            self.audit_log._append({
                "type": "vpe_verification",
                **record,
            })
        except Exception as exc:
            logger.warning("VPE audit: local log append failed: %s", exc)

        # 2. Attempt Division write
        episode_id = self._write_division(record)

        # 3. If Division write succeeded, append episode_id to local log
        if episode_id:
            try:
                self.audit_log._append({
                    "type": "vpe_division_ref",
                    "audit_id": audit_id,
                    "episode_id": episode_id,
                    "envelope_hash": envelope_hash,
                })
            except Exception:
                pass

        return audit_id

    def record_from_result(
        self,
        envelope: Dict[str, Any],
        result_obj: Any,
        tool_name: str = "",
        audit_id: Optional[str] = None,
    ) -> str:
        """Convenience: record from a VPE envelope + VPEResult.

        Extracts ``envelope_hash``, ``issuer``, and ``result`` from the
        envelope and result, then calls ``record()``.

        Args:
            envelope: The VPE envelope that was verified.
            result_obj: A ``VPEResult`` (or object with ``.valid`` and ``.reason``).
            tool_name: The Hermes tool name, if applicable.
            audit_id: Optional explicit audit ID.

        Returns:
            The audit_id.
        """
        # Compute hash of the canonical envelope
        import hashlib
        from seal.vpe import _canonical_envelope

        try:
            canonical = str(_canonical_envelope(envelope))
            env_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        except (TypeError, ValueError, KeyError):
            env_hash = "degraded:" + envelope.get("nonce", "unknown")[:16]
            logger.warning(
                "DivisionVPE: envelope canonicalization failed for issuer='%s' — "
                "using degraded hash '%s'",
                envelope.get("issuer", "unknown"),
                env_hash,
            )

        issuer = envelope.get("issuer", "unknown")
        result = "valid" if result_obj.valid else "invalid"
        reason = result_obj.reason if hasattr(result_obj, "reason") else ""

        # On degraded hash, mark reason as hash_computation_failed
        # unless result_obj already provided one
        if env_hash.startswith("degraded:") and not reason:
            reason = "hash_computation_failed"

        return self.record(
            envelope_hash=env_hash,
            issuer=issuer,
            result=result,
            reason=reason,
            tool_name=tool_name,
            audit_id=audit_id,
        )

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query_local(
        self,
        result_filter: Optional[str] = None,
        issuer_filter: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query the local JSONL audit log.

        Args:
            result_filter: Filter by result type (e.g. ``"invalid"``).
            issuer_filter: Filter by issuer (substring match).
            since: Unix timestamp — only entries after this time.
            limit: Max results (default 50).

        Returns:
            List of matching audit entries (newest first).
        """
        entries = self.audit_log.query(limit=limit * 2)  # over-fetch for filtering

        # Filter to VPE verification entries
        vpe_entries = [
            e for e in entries
            if e.get("type") in ("vpe_verification", None)  # None for legacy compat
            and "envelope_hash" in e
        ]

        # Apply filters
        if result_filter:
            vpe_entries = [e for e in vpe_entries if e.get("result") == result_filter]
        if issuer_filter:
            vpe_entries = [
                e for e in vpe_entries
                if issuer_filter.lower() in e.get("issuer", "").lower()
            ]
        if since is not None:
            vpe_entries = [
                e for e in vpe_entries
                if e.get("timestamp", 0) >= since
            ]

        # Newest first
        vpe_entries.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return vpe_entries[:limit]

    def query_division(
        self,
        query: str,
        limit: int = 50,
        search_func: Optional[Callable] = None,
    ) -> List[Dict[str, Any]]:
        """Query Division memory for VPE audit episodes.

        Args:
            query: Search query string (e.g. ``"result:invalid"``,
                   ``"issuer:agent:hermes"``).
            limit: Max results.
            search_func: Optional Division search function. If None, queries
                         are unavailable (returns empty list with warning).

        Returns:
            List of matching episode contents (parsed dicts).
        """
        if search_func is None:
            logger.warning(
                "VPE audit: no Division search function available for querying"
            )
            return []

        try:
            result = search_func(
                conversation_id=self.conversation_id,
                query=query,
                limit=limit,
            )
        except Exception as exc:
            logger.warning("VPE audit: Division search failed: %s", exc)
            return []

        # Parse result — search returns episodes with content
        episodes = []
        if isinstance(result, dict):
            raw = result.get("result", "{}")
            if isinstance(raw, str):
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    parsed = raw
            else:
                parsed = raw
            eps = parsed.get("episodes", []) if isinstance(parsed, dict) else []
        elif isinstance(result, str):
            try:
                parsed = json.loads(result)
                eps = parsed.get("episodes", [])
            except (json.JSONDecodeError, TypeError):
                eps = []
        else:
            eps = []

        for ep in eps:
            content = ep.get("episode_content", "{}")
            if isinstance(content, str):
                try:
                    ep["episode_content"] = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    pass
            episodes.append(ep)

        return episodes[:limit]

    def check_division_available(self) -> bool:
        """Check whether Division memory appears reachable.

        Returns True if the remember_func is set (it was injected at
        construction). We don't do a live probe since the function
        existence is the reliable signal.
        """
        return self._remember_func is not None

    # ------------------------------------------------------------------
    # Internal — Division write
    # ------------------------------------------------------------------

    def _write_division(self, record: Dict[str, Any]) -> Optional[str]:
        """Write an audit record to Division memory.

        Returns the episode_id string on success, or None on failure.
        """
        # Build the episode value
        episode_value = {
            "envelope_hash": record["envelope_hash"],
            "issuer": record["issuer"],
            "result": record["result"],
            "reason": record.get("reason", ""),
            "tool_name": record.get("tool_name", ""),
            "audit_id": record["audit_id"],
            "timestamp": record["timestamp"],
            "timestamp_iso": record["timestamp_iso"],
        }

        # Use multiple keys for queryability:
        #   key = "vpe:{result}:{envelope_hash[:12]}"
        #   trace = "vpe-verification" (consistent for grouping)
        env_prefix = record["envelope_hash"][:12] if len(record["envelope_hash"]) >= 12 else record["envelope_hash"]
        episode_key = f"vpe:{record['result']}:{env_prefix}"

        # Try injected remember function first
        if self._remember_func is not None:
            try:
                result = self._remember_func(
                    conversation_id=self.conversation_id,
                    agent="seal-vpe",
                    key=episode_key,
                    value=episode_value,
                    importance=0.8,
                )
                self._division_available = True
                self._extract_episode_id(result)
                return self._last_episode_id
            except Exception as exc:
                logger.debug("VPE audit: Division remember failed: %s", exc)
                self._division_available = False
                return None

        # No remember function available — log and skip
        logger.debug(
            "VPE audit: no Division remember function injected, "
            "falling back to local log only"
        )
        return None

    def _extract_episode_id(self, result: Any) -> None:
        """Extract and store episode_id from a Division response."""
        try:
            if isinstance(result, dict):
                raw = result.get("result", "{}")
                if isinstance(raw, str):
                    parsed = json.loads(raw)
                else:
                    parsed = raw
                if isinstance(parsed, dict):
                    self._last_episode_id = parsed.get("episode_id")
            elif isinstance(result, str):
                parsed = json.loads(result)
                if isinstance(parsed, dict):
                    self._last_episode_id = parsed.get("episode_id")
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_audit_id() -> str:
    """Generate a unique audit ID (UUID4 hex, 32 chars)."""
    return uuid.uuid4().hex


def _canonical_hash(envelope: Dict[str, Any]) -> str:
    """Compute the SHA-256 hash of a canonicalized VPE envelope.

    Args:
        envelope: A VPE envelope dict.

    Returns:
        Hex SHA-256 digest.
    """
    import hashlib

    try:
        from seal.vpe import _canonical_envelope
        canonical = _canonical_envelope(envelope)
    except Exception:
        canonical = str(json.dumps(envelope, sort_keys=True, default=str))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
