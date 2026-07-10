"""Persistent NonceStore and CounterStore using SQLite.

Thread-safe. Survives restarts. Auto-cleanup of expired nonces.

Path: ~/.seal/store.db (configurable via SealPaths).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_SEAL_DIR = Path.home() / ".seal"
_DEFAULT_DB_PATH = _SEAL_DIR / "store.db"
_DEFAULT_CLEANUP_TTL = 3600  # 1 hour — nonces older than this get pruned


# ---------------------------------------------------------------------------
# NonceStore
# ---------------------------------------------------------------------------


class NonceStore:
    """Persistent store for seen nonces (replay prevention).

    Stores the nonce string along with an insertion timestamp so expired
    entries can be cleaned up automatically.
    """

    def __init__(
        self,
        db_path: str | Path = _DEFAULT_DB_PATH,
        cleanup_ttl: int = _DEFAULT_CLEANUP_TTL,
    ):
        self._db_path = str(db_path)
        self._cleanup_ttl = cleanup_ttl

        # Per-thread connections (thread-safe via threading.local)
        self._local = threading.local()

        self._ensure_dir()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        """Get a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nonces (
                nonce       TEXT PRIMARY KEY,
                created_at  INTEGER NOT NULL
            )
            """
        )
        conn.commit()

    def _cleanup(self) -> None:
        """Remove nonces older than ``cleanup_ttl`` seconds."""
        cutoff = int(time.time()) - self._cleanup_ttl
        conn = self._conn()
        conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
        conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, nonce: str) -> bool:
        """Record a nonce.

        Returns:
            True if the nonce was newly recorded.
            False if it already exists (replay detected).
        """
        self._cleanup()
        conn = self._conn()
        now = int(time.time())
        try:
            conn.execute(
                "INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                (nonce, now),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # already exists (replay)

    def contains(self, nonce: str) -> bool:
        """Check if a nonce has already been recorded."""
        cursor = self._conn().execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
        return cursor.fetchone() is not None

    def remove(self, nonce: str) -> bool:
        """Remove a single nonce entry.

        Returns True if a row was deleted, False if not found.
        """
        cursor = self._conn().execute("DELETE FROM nonces WHERE nonce = ?", (nonce,))
        self._conn().commit()
        return cursor.rowcount > 0

    def force_cleanup(self) -> int:
        """Explicitly purge expired nonces.

        Returns:
            Number of rows deleted.
        """
        conn = self._conn()
        cutoff = int(time.time()) - self._cleanup_ttl
        cursor = conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
        conn.commit()
        return cursor.rowcount

    @property
    def size(self) -> int:
        """Number of nonces currently in the store."""
        return self._conn().execute("SELECT COUNT(*) FROM nonces").fetchone()[0]

    def close(self) -> None:
        """Close the thread-local connection (if open)."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None


# ---------------------------------------------------------------------------
# CounterStore
# ---------------------------------------------------------------------------


class CounterStore:
    """Persistent store for monotonic counters keyed by (issuer, audience).

    Each (issuer, audience) pair tracks the last counter value seen, enabling
    detection of skipped or reordered prompts.
    """

    def __init__(self, db_path: str | Path = _DEFAULT_DB_PATH):
        self._db_path = str(db_path)
        self._local = threading.local()
        self._ensure_dir()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS counters (
                issuer        TEXT NOT NULL,
                audience      TEXT NOT NULL,
                last_counter  INTEGER NOT NULL,
                PRIMARY KEY (issuer, audience)
            )
            """
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, issuer: str, audience: str) -> int | None:
        """Get the last counter value for (issuer, audience).

        Returns:
            The last counter value, or None if never seen.
        """
        cursor = self._conn().execute(
            "SELECT last_counter FROM counters WHERE issuer = ? AND audience = ?",
            (issuer, audience),
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def set(self, issuer: str, audience: str, counter: int) -> None:
        """Record a counter value, overwriting any previous value."""
        self._conn().execute(
            """INSERT INTO counters (issuer, audience, last_counter)
               VALUES (?, ?, ?)
               ON CONFLICT(issuer, audience) DO UPDATE SET last_counter = ?""",
            (issuer, audience, counter, counter),
        )
        self._conn().commit()

    def delete(self, issuer: str, audience: str) -> bool:
        """Remove a counter entry.

        Returns True if a row was deleted, False if not found.
        """
        cursor = self._conn().execute(
            "DELETE FROM counters WHERE issuer = ? AND audience = ?",
            (issuer, audience),
        )
        self._conn().commit()
        return cursor.rowcount > 0

    @property
    def size(self) -> int:
        """Number of counter entries."""
        return self._conn().execute("SELECT COUNT(*) FROM counters").fetchone()[0]

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
