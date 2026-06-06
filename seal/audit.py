"""Audit log — append-only JSONL record of credential access.

Records *that* a credential was accessed, by whom, and whether it was granted.
It never records the credential value itself.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUDIT_PATH = "~/.seal/audit.jsonl"
MAX_ENTRIES = 10000


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    """Append-only JSONL audit log with size-bounded auto-rotation."""

    def __init__(self, path: str = DEFAULT_AUDIT_PATH, max_entries: int = MAX_ENTRIES) -> None:
        self.path = Path(path).expanduser()
        self.max_entries = max_entries
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
        """Prune oldest lines so the file holds at most ``max_entries``.

        Caller must hold ``self._lock``.
        """
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except FileNotFoundError:  # pragma: no cover
            return
        if len(lines) <= self.max_entries:
            return
        kept = lines[-self.max_entries:]
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

    def query(self, label: str | None = None, limit: int = 50) -> list[dict]:
        """Return up to ``limit`` most-recent entries, newest last.

        Optionally filtered by ``label``. Malformed lines are skipped.
        """
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
            entries.append(entry)
        if limit is not None and limit >= 0:
            return entries[-limit:]
        return entries
