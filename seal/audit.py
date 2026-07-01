"""Audit log — append-only JSONL record of credential access.

Records *that* a credential was accessed, by whom, and whether it was granted.
It never records the credential value itself.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

DEFAULT_AUDIT_PATH = "~/.seal/audit.jsonl"
MAX_ENTRIES = 10000
MAX_AGE_DAYS = 30


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditLog:
    """Append-only JSONL audit log with size-bounded auto-rotation."""

    def __init__(
        self,
        path: str = DEFAULT_AUDIT_PATH,
        max_entries: int = MAX_ENTRIES,
        max_age_days: int = MAX_AGE_DAYS,
    ) -> None:
        self.path = Path(path).expanduser()
        self.max_entries = max_entries
        self.max_age_days = max_age_days
        self._lock = threading.Lock()

    # -------------------------------------------------------------- helpers
    def _ensure_dir(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            parent.chmod(0o700)
        except OSError:  # pragma: no cover
            pass

    def _append(self, entry: dict) -> None:
        self._ensure_dir()
        with self._lock:
            existed = self.path.exists()
            # Open with 0600; O_APPEND keeps writes atomic per line.
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            if not existed:
                try:
                    self.path.chmod(0o600)
                except OSError:  # pragma: no cover
                    pass
            self._rotate_locked()

    def _rotate_locked(self) -> None:
        """Prune lines so the file stays within count and age bounds.

        Entries are pruned when they exceed ``max_entries`` (count-based) or are
        older than ``max_age_days`` (time-based). Caller must hold ``self._lock``.
        """
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except FileNotFoundError:  # pragma: no cover
            return

        original_len = len(lines)
        kept = lines

        # Time-based pruning. Entries are appended in chronological order, so the
        # oldest live at the front: walk forward only until the first entry still
        # inside the retention window, then slice. O(pruned), not O(total).
        if self.max_age_days is not None and kept:
            cutoff = datetime.now(UTC) - timedelta(days=self.max_age_days)
            drop = 0
            for line in kept:
                stripped = line.strip()
                if not stripped:
                    drop += 1
                    continue
                try:
                    ts = datetime.fromisoformat(json.loads(stripped)["timestamp"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    # Can't parse this entry's age — stop pruning to be safe.
                    break
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                if ts >= cutoff:
                    break
                drop += 1
            if drop:
                kept = kept[drop:]

        # Count-based pruning.
        if len(kept) > self.max_entries:
            kept = kept[-self.max_entries:]

        if len(kept) == original_len:
            return
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, "".join(kept).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

    # --------------------------------------------------------------- public
    def log_access(self, label: str, caller: str, action: str = "get") -> None:
        """Record a granted credential access."""
        self._append(
            {
                "timestamp": _utc_now_iso(),
                "label": label,
                "caller": caller,
                "action": action,
                "result": "granted",
            }
        )

    def log_denial(
        self, label: str, caller: str, reason: str = "label_not_found"
    ) -> None:
        """Record a denied credential access."""
        self._append(
            {
                "timestamp": _utc_now_iso(),
                "label": label,
                "caller": caller,
                "action": "get",
                "result": "denied",
                "reason": reason,
            }
        )

    def log_vpe_verification(
        self,
        envelope_hash: str,
        issuer: str,
        audience: str,
        result: str,  # "valid" | "invalid" | "expired"
        reason: str = "",
    ) -> None:
        """Record a VPE (Verifiable Provenance Envelope) verification event."""
        self._append(
            {
                "timestamp": _utc_now_iso(),
                "type": "vpe_verification",
                "envelope_hash": envelope_hash,
                "issuer": issuer,
                "audience": audience,
                "result": result,
                "reason": reason,
            }
        )

    def query(
        self,
        label: str | None = None,
        limit: int = 50,
        *,
        status: str | None = None,
        since: str | None = None,
        tail: int | None = None,
    ) -> list[dict]:
        """Return up to ``tail`` (or ``limit``) most-recent entries, newest last.

        Filters (all optional, AND-combined):
          - ``label``  — match credential-audit ``label`` field exactly.
          - ``status`` — match the ``result`` field (e.g. valid/invalid/expired).
          - ``since``  — ISO timestamp; keep entries with ``timestamp >= since``.

        ``tail`` is the preferred name for the count cap; ``limit`` is kept as a
        backward-compatible alias and used when ``tail`` is not given. Malformed
        lines are skipped.
        """
        n = tail if tail is not None else limit

        since_dt: datetime | None = None
        if since is not None:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                since_dt = None
            else:
                if since_dt.tzinfo is None:
                    since_dt = since_dt.replace(tzinfo=UTC)

        with self._lock:
            try:
                with self.path.open("r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except FileNotFoundError:
                return []
        entries: list[dict] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if label is not None and entry.get("label") != label:
                continue
            if status is not None and entry.get("result") != status:
                continue
            if since_dt is not None:
                try:
                    ts = datetime.fromisoformat(entry.get("timestamp"))
                except (TypeError, ValueError):
                    continue
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                if ts < since_dt:
                    continue
            entries.append(entry)
        if n is not None and n >= 0:
            return entries[-n:]
        return entries
