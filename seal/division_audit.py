"""Division Audit Trail — Store and query VPE verification results in Division memory.

Every VPE verification result (valid, invalid, expired, unverified) is stored as
a Division memory episode, enabling tamper-evident audit history that survives
restarts and is queryable via natural language.

Dependencies:
    - Division MCP server running on localhost:7070
    - Python stdlib only (urllib, json, hashlib, time)

Usage:
    from seal.division_audit import DivisionAuditTrail

    audit = DivisionAuditTrail()
    audit.record_verification(
        envelope_hash="abc123...",
        issuer="user:rez",
        audience="agent:hermes-default",
        result="valid",
        reason="ok",
        source="middleware",
    )

    # Query recent results
    results = audit.query_recent(limit=20)

    # Query rejected prompts in the last hour
    rejected = audit.query_rejected(after_ts=time.time() - 3600)

    # Text search
    results = audit.search("rejected prompt terminal")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DIVISION_BASE_URL = os.getenv("DIVISION_BASE_URL", "http://localhost:7070")
"""Base URL for Division's HTTP API."""

AUDIT_CONVERSATION_ID = "seal-audit"
"""Dedicated Division conversation for VPE verification audit records."""

AUDIT_DOMAIN = "seal.audit"
"""Division domain for audit trail episodes."""

AUDIT_AGENT = "seal-vpe"
"""Agent name that writes audit episodes."""

AUDIT_IMPORTANCE = 0.5
"""Default importance for audit records."""

# HTTP request timeout (seconds)
_REQUEST_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Result type constants — used as Division category field
# ---------------------------------------------------------------------------

CATEGORY_VALID = "valid"
CATEGORY_INVALID = "invalid"
CATEGORY_EXPIRED = "expired"
CATEGORY_UNVERIFIED = "unverified"
CATEGORY_ERROR = "error"

_ALL_CATEGORIES = [CATEGORY_VALID, CATEGORY_INVALID, CATEGORY_EXPIRED, CATEGORY_UNVERIFIED, CATEGORY_ERROR]


# ---------------------------------------------------------------------------
# Audit record model
# ---------------------------------------------------------------------------


class AuditRecord:
    """A single VPE verification audit record.

    Attributes:
        envelope_hash: SHA-256 hex digest of the envelope JSON.
        issuer: Who authorized the prompt (e.g. "user:rez").
        audience: Which agent was targeted (e.g. "agent:hermes-default").
        result: Verification outcome: "valid", "invalid", "expired", "unverified", "error".
        reason: Human-readable reason string.
        timestamp: Unix epoch seconds when verification occurred.
        source: Where verification happened ("middleware", "cli", "integration", etc.).
        episode_id: Division episode ID for this record (populated after store).
    """

    __slots__ = (
        "envelope_hash",
        "issuer",
        "audience",
        "result",
        "reason",
        "timestamp",
        "source",
        "episode_id",
        "_extra",
    )

    def __init__(
        self,
        envelope_hash: str = "",
        issuer: str = "",
        audience: str = "",
        result: str = "",
        reason: str = "",
        timestamp: Optional[float] = None,
        source: str = "",
        episode_id: str = "",
        **extra: Any,
    ) -> None:
        self.envelope_hash = envelope_hash
        self.issuer = issuer
        self.audience = audience
        self.result = result
        self.reason = reason
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.source = source
        self.episode_id = episode_id
        self._extra = extra

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a dict for Division storage."""
        d: Dict[str, Any] = {
            "envelope_hash": self.envelope_hash,
            "issuer": self.issuer,
            "audience": self.audience,
            "result": self.result,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "source": self.source,
        }
        if self.episode_id:
            d["episode_id"] = self.episode_id
        if self._extra:
            d.update(self._extra)
        return d

    @classmethod
    def from_episode(cls, episode: Dict[str, Any]) -> "AuditRecord":
        """Reconstruct an AuditRecord from a Division EpisodeModel dict.

        The episode_content holds the audit record dict; episode_metadata
        carries summary fields for quick filtering.
        """
        content = episode.get("episode_content", {})
        if isinstance(content, str):
            try:
                content = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                content = {}
        meta = episode.get("episode_metadata", {}) or {}
        return cls(
            envelope_hash=content.get("envelope_hash", meta.get("envelope_hash", "")),
            issuer=content.get("issuer", meta.get("issuer", "")),
            audience=content.get("audience", meta.get("audience", "")),
            result=content.get("result", meta.get("result_type", "")),
            reason=content.get("reason", ""),
            timestamp=content.get("timestamp", meta.get("ts", episode.get("episode_created_at", 0))),
            source=content.get("source", ""),
            episode_id=episode.get("episode_id", ""),
        )

    def __repr__(self) -> str:
        return (
            f"<AuditRecord {self.result}: "
            f"issuer={self.issuer!r} "
            f"hash={self.envelope_hash[:16] or 'N/A'}...>"
        )


# ---------------------------------------------------------------------------
# Division HTTP client (simple, no external deps)
# ---------------------------------------------------------------------------


class _DivisionClient:
    """Minimal HTTP client for Division's memory API.

    Uses Python stdlib (urllib) so the module has zero external dependencies.
    """

    def __init__(self, base_url: str = DIVISION_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, path: str, body: dict) -> Optional[dict]:
        """POST JSON to Division and return parsed response."""
        import urllib.request
        import urllib.error

        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            logger.warning(
                "Division HTTP %s on POST %s: %s",
                exc.code, path, exc.read().decode()[:200],
            )
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Division connection error on POST %s: %s", path, exc)
            return None

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        """GET from Division and return parsed response."""
        import urllib.request
        import urllib.parse
        import urllib.error

        url = f"{self.base_url}{path}"
        if params:
            qs = urllib.parse.urlencode(params)
            url = f"{url}?{qs}"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            logger.warning(
                "Division HTTP %s on GET %s: %s",
                exc.code, path, exc.read().decode()[:200],
            )
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Division connection error on GET %s: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Memory API
    # ------------------------------------------------------------------

    def remember(
        self,
        conversation_id: str,
        value: Any,
        *,
        agent: Optional[str] = None,
        key: Optional[str] = None,
        domain: Optional[str] = None,
        category: Optional[str] = None,
        trace: Optional[str] = None,
        importance: float = 0.5,
        metadata: Optional[dict] = None,
    ) -> Optional[str]:
        """Store a memory episode.

        Returns the episode_id on success, None on failure.
        """
        body: Dict[str, Any] = {
            "conversation_id": conversation_id,
            "value": value,
            "importance": importance,
        }
        if agent is not None:
            body["agent"] = agent
        if key is not None:
            body["key"] = key
        if domain is not None:
            body["domain"] = domain
        if category is not None:
            body["category"] = category
        if trace is not None:
            body["trace"] = trace
        if metadata is not None:
            body["metadata"] = metadata

        result = self._post("/memory/remember", body)
        if result is None:
            return None
        return result.get("episode_id")

    def recall(
        self,
        conversation_id: str,
        *,
        agent: Optional[str] = None,
        key: Optional[str] = None,
        domain: Optional[str] = None,
        category: Optional[str] = None,
        trace: Optional[str] = None,
        after_ts: Optional[float] = None,
        before_ts: Optional[float] = None,
        limit: int = 50,
        order_by: str = "time",
    ) -> List[Dict[str, Any]]:
        """Recall memory episodes matching the given filters.

        Returns list of EpisodeModel dicts, newest first when order_by='time'.
        """
        body: Dict[str, Any] = {
            "conversation_id": conversation_id,
            "limit": min(limit, 100),
            "order_by": order_by,
        }
        if agent is not None:
            body["agent"] = agent
        if key is not None:
            body["key"] = key
        if domain is not None:
            body["domain"] = domain
        if category is not None:
            body["category"] = category
        if trace is not None:
            body["trace"] = trace
        if after_ts is not None:
            body["after_ts"] = after_ts
        if before_ts is not None:
            body["before_ts"] = before_ts

        result = self._post("/memory/recall", body)
        if result is None:
            return []
        return result.get("episodes", [])

    def search(
        self,
        conversation_id: str,
        query: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Full-text search memory episodes.

        Returns list of EpisodeModel dicts.
        """
        params = {
            "conversation_id": conversation_id,
            "query": query,
            "limit": limit,
        }
        result = self._get("/memory/search", params)
        if result is None:
            return []
        return result.get("results", [])


# ---------------------------------------------------------------------------
# Division Audit Trail
# ---------------------------------------------------------------------------


class DivisionAuditTrail:
    """Records and queries VPE verification results in Division memory.

    Every call to ``record_verification()`` creates a Division episode in the
    ``seal-audit`` conversation. Episodes are indexed by:
      - domain="seal.audit"
      - category = result type (valid/invalid/expired/unverified/error)
      - key = envelope_hash (for dedup / fast lookup by hash)

    Query methods filter by these fields to answer questions like:
      - "Show me all rejected prompts in the last hour"
      - "What did this envelope hash verify to?"
      - "How many valid vs invalid verifications today?"
    """

    def __init__(
        self,
        base_url: str = DIVISION_BASE_URL,
        conversation_id: str = AUDIT_CONVERSATION_ID,
        domain: str = AUDIT_DOMAIN,
        agent: str = AUDIT_AGENT,
    ) -> None:
        """Initialize the audit trail.

        Args:
            base_url: Division HTTP API base URL.
            conversation_id: Division conversation for audit records.
            domain: Division domain for audit episodes.
            agent: Agent name for audit episodes.
        """
        self._client = _DivisionClient(base_url)
        self._conversation_id = conversation_id
        self._domain = domain
        self._agent = agent

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_verification(
        self,
        *,
        envelope_hash: str,
        issuer: str,
        audience: str,
        result: str,
        reason: str = "",
        source: str = "unspecified",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Record a VPE verification result as a Division memory episode.

        Args:
            envelope_hash: SHA-256 hex digest of the envelope JSON.
            issuer: Envelope issuer field (e.g. "user:rez").
            audience: Envelope audience field (e.g. "agent:hermes-default").
            result: Verification outcome: "valid", "invalid", "expired",
                    "unverified", or "error".
            reason: Human-readable reason string.
            source: Where verification happened (e.g. "middleware", "cli").
            extra: Optional additional fields to include in the stored value.

        Returns:
            Episode ID on success, None on failure.
        """
        result = result.lower()
        if result not in _ALL_CATEGORIES:
            result = CATEGORY_ERROR

        now = time.time()
        record = AuditRecord(
            envelope_hash=envelope_hash,
            issuer=issuer,
            audience=audience,
            result=result,
            reason=reason,
            timestamp=now,
            source=source,
        )

        # The value stored in Division
        value = record.to_dict()
        if extra:
            value.update(extra)

        # Metadata for quick filtering at the Division level
        metadata: Dict[str, Any] = {
            "envelope_hash": envelope_hash,
            "issuer": issuer,
            "audience": audience,
            "result_type": result,
            "ts": now,
            "source": source,
        }

        episode_id = self._client.remember(
            conversation_id=self._conversation_id,
            value=value,
            agent=self._agent,
            key=envelope_hash,
            domain=self._domain,
            category=result,
            importance=AUDIT_IMPORTANCE,
            metadata=metadata,
        )

        if episode_id:
            logger.debug(
                "Audit: recorded %s verification for issuer=%s hash=%s episode=%s",
                result, issuer, envelope_hash[:16], episode_id,
            )
        else:
            logger.warning(
                "Audit: failed to record verification for issuer=%s hash=%s",
                issuer, envelope_hash[:16],
            )

        return episode_id

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query_recent(
        self,
        limit: int = 20,
        *,
        after_ts: Optional[float] = None,
        before_ts: Optional[float] = None,
    ) -> List[AuditRecord]:
        """Get the most recent verification records.

        Args:
            limit: Max records to return (1-100).
            after_ts: Optional — only records after this timestamp.
            before_ts: Optional — only records before this timestamp.

        Returns:
            List of AuditRecord, newest first.
        """
        episodes = self._client.recall(
            conversation_id=self._conversation_id,
            agent=self._agent,
            domain=self._domain,
            after_ts=after_ts,
            before_ts=before_ts,
            limit=limit,
            order_by="time",
        )
        return [AuditRecord.from_episode(ep) for ep in episodes]

    def query_by_hash(self, envelope_hash: str) -> List[AuditRecord]:
        """Find all verification records for a specific envelope hash.

        Args:
            envelope_hash: SHA-256 hex digest to search for.

        Returns:
            List of matching AuditRecord, newest first.
        """
        episodes = self._client.recall(
            conversation_id=self._conversation_id,
            agent=self._agent,
            domain=self._domain,
            key=envelope_hash,
            limit=100,
            order_by="time",
        )
        return [AuditRecord.from_episode(ep) for ep in episodes]

    def query_by_issuer(self, issuer: str, limit: int = 50) -> List[AuditRecord]:
        """Find verification records for a specific issuer.

        Args:
            issuer: Issuer string to search (e.g. "user:rez").
            limit: Max records to return.

        Returns:
            List of matching AuditRecord, newest first.
        """
        episodes = self._client.recall(
            conversation_id=self._conversation_id,
            agent=self._agent,
            domain=self._domain,
            limit=limit,
            order_by="time",
        )
        records = [AuditRecord.from_episode(ep) for ep in episodes]
        return [r for r in records if r.issuer == issuer]

    def query_by_result(
        self,
        result: str,
        limit: int = 50,
        *,
        after_ts: Optional[float] = None,
        before_ts: Optional[float] = None,
    ) -> List[AuditRecord]:
        """Find verification records by result type.

        Args:
            result: Result type: "valid", "invalid", "expired", "unverified", "error".
            limit: Max records to return.
            after_ts: Optional — only records after this timestamp.
            before_ts: Optional — only records before this timestamp.

        Returns:
            List of matching AuditRecord, newest first.
        """
        result = result.lower()
        episodes = self._client.recall(
            conversation_id=self._conversation_id,
            agent=self._agent,
            domain=self._domain,
            category=result,
            after_ts=after_ts,
            before_ts=before_ts,
            limit=limit,
            order_by="time",
        )
        return [AuditRecord.from_episode(ep) for ep in episodes]

    def query_rejected(
        self,
        limit: int = 50,
        *,
        after_ts: Optional[float] = None,
    ) -> List[AuditRecord]:
        """Find all rejected/invalid/expired verifications.

        This is the "show me all rejected prompts" query.

        Args:
            limit: Max records to return.
            after_ts: Optional — only records after this timestamp.

        Returns:
            List of rejected AuditRecord, newest first.
        """
        invalid = self.query_by_result(CATEGORY_INVALID, limit=limit, after_ts=after_ts)
        expired = self.query_by_result(CATEGORY_EXPIRED, limit=limit, after_ts=after_ts)
        error = self.query_by_result(CATEGORY_ERROR, limit=limit, after_ts=after_ts)
        all_rejected = invalid + expired + error
        all_rejected.sort(key=lambda r: r.timestamp, reverse=True)
        return all_rejected[:limit]

    def search(self, query: str, limit: int = 20) -> List[AuditRecord]:
        """Full-text search across audit records.

        Args:
            query: Free-text search query.
            limit: Max results to return.

        Returns:
            List of matching AuditRecord.
        """
        episodes = self._client.search(
            conversation_id=self._conversation_id,
            query=query,
            limit=limit,
        )
        return [AuditRecord.from_episode(ep) for ep in episodes]

    # ------------------------------------------------------------------
    # Summary / stats
    # ------------------------------------------------------------------

    def get_summary(
        self,
        *,
        after_ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Get a summary of verification activity.

        Args:
            after_ts: Optional — only count records after this timestamp.

        Returns:
            Dict with counts per result type and total.
        """
        counts: Dict[str, int] = {}
        total = 0
        for cat in _ALL_CATEGORIES:
            records = self.query_by_result(cat, limit=100, after_ts=after_ts)
            count = len(records)
            if count > 0:
                counts[cat] = count
                total += count
        return {
            "total": total,
            "counts": counts,
            "after_ts": after_ts,
        }

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> bool:
        """Check if Division is reachable.

        Returns:
            True if Division health endpoint responds OK.
        """
        import urllib.request
        import urllib.error

        url = f"{self._client.base_url}/health"
        try:
            with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "ok"
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            return False


# ---------------------------------------------------------------------------
# Convenience functions for CLI / integration use
# ---------------------------------------------------------------------------


def record_vpe_verification(
    envelope_hash: str,
    issuer: str,
    audience: str,
    result: str,
    reason: str = "",
    source: str = "unspecified",
    audit_trail: Optional[DivisionAuditTrail] = None,
) -> Optional[str]:
    """Convenience wrapper to record a VPE verification result.

    Creates a DivisionAuditTrail on first call (lazy init) and reuses it.

    Args:
        envelope_hash: SHA-256 hex digest of the envelope JSON.
        issuer: Envelope issuer field.
        audience: Envelope audience field.
        result: Verification outcome.
        reason: Human-readable reason string.
        source: Where verification happened.
        audit_trail: Reusable audit trail instance (created if None).

    Returns:
        Episode ID on success, None on failure.
    """
    if audit_trail is None:
        _audit = DivisionAuditTrail()
    else:
        _audit = audit_trail
    return _audit.record_verification(
        envelope_hash=envelope_hash,
        issuer=issuer,
        audience=audience,
        result=result,
        reason=reason,
        source=source,
    )
