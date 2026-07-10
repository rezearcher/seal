"""KeyStore — persistent key lifecycle store for Seal/VPE.

Stores Ed25519 keys with time-based metadata (not_before, not_after)
and lifecycle status tracking. Thread-safe SQLite backend consistent
with NonceStore / CounterStore patterns.

Schema:
    keys(id TEXT PK, label TEXT, public_key BLOB, private_key BLOB,
         not_before INT, not_after INT, status TEXT, rotation_days INT,
         created_at INT, UNIQUE(label, status_active) partial index)

Status values:
    active    — current signing key (at most one per label)
    expiring  — still valid but rotation-eligible; still verifies
    retired   — past not_after; can still verify old signatures
    revoked   — explicitly invalidated; verification fails
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from seal.core import _load_private_key, generate_key_pair

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_SEAL_DIR = Path.home() / ".seal"
_DEFAULT_DB_PATH = _SEAL_DIR / "keys.db"


# ---------------------------------------------------------------------------
# KeyInfo — data class
# ---------------------------------------------------------------------------


@dataclass
class KeyInfo:
    """A single key record with lifecycle metadata."""

    key_id: str
    label: str
    public_key: bytes
    private_key: bytes | None
    not_before: int  # Unix epoch seconds (0 = no restriction)
    not_after: int  # Unix epoch seconds (0 = no expiry)
    status: str  # active | expiring | retired | revoked
    rotation_days: int  # N days before not_after to auto-rotate (0 = manual)
    created_at: int  # Unix epoch seconds

    @property
    def is_expired(self, now: int | None = None) -> bool:
        """Check if current time is past not_after."""
        if self.not_after == 0:
            return False
        now = now or int(time.time())
        return now > self.not_after

    @property
    def is_premature(self, now: int | None = None) -> bool:
        """Check if current time is before not_before."""
        if self.not_before == 0:
            return False
        now = now or int(time.time())
        return now < self.not_before

    def is_valid_at(self, now: int | None = None) -> bool:
        """Check if the key is valid for signing/verification at given time."""
        now = now or int(time.time())
        if self.status == "revoked":
            return False
        if self.not_before > 0 and now < self.not_before:
            return False
        if self.not_after > 0 and now > self.not_after:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "label": self.label,
            "public_key_hex": self.public_key.hex(),
            "has_private_key": self.private_key is not None,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "status": self.status,
            "rotation_days": self.rotation_days,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------


class KeyStore:
    """Persistent store for key lifecycle metadata.

    Thread-safe. Each label can have at most one ``active`` key.
    Rotating transitions the old key to ``retired`` and creates a new
    ``active`` key.
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
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS keys (
                key_id        TEXT PRIMARY KEY,
                label         TEXT NOT NULL,
                public_key    BLOB NOT NULL,
                private_key   BLOB,
                not_before    INTEGER NOT NULL DEFAULT 0,
                not_after     INTEGER NOT NULL DEFAULT 0,
                status        TEXT NOT NULL DEFAULT 'active'
                              CHECK(status IN ('active','expiring','retired','revoked')),
                rotation_days INTEGER NOT NULL DEFAULT 0,
                created_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_keys_label ON keys(label);
            CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);
        """)
        conn.commit()

    @staticmethod
    def _new_key_id() -> str:
        """Short hex identifier — 8 bytes = 16 hex chars."""
        return secrets.token_hex(8)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_key(
        self,
        label: str,
        *,
        not_before: int | None = None,
        not_after: int | None = None,
        rotation_days: int = 0,
        now: int | None = None,
        private_key: bytes | None = None,
    ) -> KeyInfo:
        """Generate and store a new Ed25519 key pair with time metadata.

        If a key with this label is currently ``active``, it transitions
        to ``expiring`` (retain for verification, but new signing uses
        the new key).

        Args:
            label: Human-friendly name for this key (e.g. ``hermes-prod``).
            not_before: Unix epoch seconds when the key becomes valid.
                        Defaults to ``now``.
            not_after: Unix epoch seconds when the key expires.
                       Defaults to ``now + 365*86400`` (1 year).
            rotation_days: Days before ``not_after`` to auto-rotate.
            now: Current time override (for testing).
            private_key: Optional raw private key bytes. If omitted, a new
                         Ed25519 key pair is generated.

        Returns:
            KeyInfo for the newly created key.
        """
        now = now or int(time.time())
        not_before = not_before if not_before is not None else now
        not_after = not_after if not_after is not None else (now + 365 * 86400)

        conn = self._conn()

        # If there's an active key for this label, demote to expiring
        existing_active = self.get_active_key(label)
        if existing_active is not None:
            conn.execute(
                "UPDATE keys SET status = 'expiring' WHERE key_id = ?",
                (existing_active.key_id,),
            )

        key_id = self._new_key_id()

        if private_key is not None:
            # Derive public key from the provided private key
            sk = _load_private_key(private_key)
            pk = sk.public_key()
            pub_bytes = pk.public_bytes_raw()
            priv_bytes = private_key
        else:
            pair = generate_key_pair()
            pub_bytes = pair["public_key"]
            priv_bytes = pair["private_key"]

        conn.execute(
            """INSERT INTO keys
               (key_id, label, public_key, private_key, not_before, not_after,
                status, rotation_days, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)""",
            (key_id, label, pub_bytes, priv_bytes, not_before, not_after, rotation_days, now),
        )
        conn.commit()

        return KeyInfo(
            key_id=key_id,
            label=label,
            public_key=pub_bytes,
            private_key=priv_bytes,
            not_before=not_before,
            not_after=not_after,
            status="active",
            rotation_days=rotation_days,
            created_at=now,
        )

    def get_key(self, key_id: str) -> KeyInfo | None:
        """Look up a key by its unique ID."""
        row = self._conn().execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_info(row)

    def get_key_by_label(self, label: str) -> KeyInfo | None:
        """Get the most recently created key for a label (any status)."""
        row = (
            self._conn()
            .execute(
                "SELECT * FROM keys WHERE label = ? ORDER BY created_at DESC LIMIT 1",
                (label,),
            )
            .fetchone()
        )
        if row is None:
            return None
        return self._row_to_info(row)

    def get_active_key(self, label: str, now: int | None = None) -> KeyInfo | None:
        """Get the currently active signing key for a label.

        Returns the key with status ``active`` that is valid at ``now``.
        If none is strictly ``active``, returns the most recent key that
        is still within its time bounds (status ``expiring`` or ``active``).
        """
        now = now or int(time.time())
        conn = self._conn()

        # First try: strictly active
        row = conn.execute(
            "SELECT * FROM keys WHERE label = ? AND status = 'active' AND "
            "(not_before = 0 OR not_before <= ?) AND "
            "(not_after = 0 OR not_after > ?) "
            "ORDER BY created_at DESC LIMIT 1",
            (label, now, now),
        ).fetchone()
        if row is not None:
            return self._row_to_info(row)

        # Second try: any valid key (active or expiring, within time bounds)
        row = conn.execute(
            "SELECT * FROM keys WHERE label = ? AND status IN ('active','expiring') AND "
            "(not_before = 0 OR not_before <= ?) AND "
            "(not_after = 0 OR not_after > ?) "
            "ORDER BY created_at DESC LIMIT 1",
            (label, now, now),
        ).fetchone()
        if row is not None:
            return self._row_to_info(row)

        return None

    def list_keys(
        self,
        label: str | None = None,
        status_filter: str | None = None,
    ) -> list[KeyInfo]:
        """List stored keys, optionally filtered."""
        sql = "SELECT * FROM keys WHERE 1=1"
        params: list = []
        if label is not None:
            sql += " AND label = ?"
            params.append(label)
        if status_filter is not None:
            sql += " AND status = ?"
            params.append(status_filter)
        sql += " ORDER BY created_at DESC"

        rows = self._conn().execute(sql, params).fetchall()
        return [self._row_to_info(r) for r in rows]

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key. Revoked keys fail verification.

        Returns True if the key existed and was revoked.
        """
        conn = self._conn()
        cursor = conn.execute(
            "UPDATE keys SET status = 'revoked' WHERE key_id = ? AND status != 'revoked'",
            (key_id,),
        )
        conn.commit()
        return cursor.rowcount > 0

    def rotate_key(
        self,
        label: str,
        rotation_days: int = 30,
        now: int | None = None,
    ) -> KeyInfo | None:
        """Rotate keys for a label: create a new active key.

        The new key's ``not_before`` is set to ``now`` and its
        ``not_after`` to ``now + rotation_days * 86400``.

        Returns the new KeyInfo, or None if no prior key exists
        (in which case use ``generate_key`` instead).
        """
        existing = self.get_key_by_label(label)
        if existing is None:
            return None

        now = now or int(time.time())
        not_after = now + rotation_days * 86400

        return self.generate_key(
            label=label,
            not_before=now,
            not_after=not_after,
            rotation_days=rotation_days,
            now=now,
        )

    def needs_rotation(self, now: int | None = None) -> list[KeyInfo]:
        """Return all active/expiring keys whose not_after is within
        their rotation_days window (or already past it)."""
        now = now or int(time.time())
        rows = (
            self._conn()
            .execute(
                """SELECT * FROM keys
               WHERE status IN ('active', 'expiring')
               AND rotation_days > 0
               AND not_after > 0
               AND not_after <= ? + rotation_days * 86400
               ORDER BY not_after ASC""",
                (now,),
            )
            .fetchall()
        )
        return [self._row_to_info(r) for r in rows]

    def delete_key(self, key_id: str) -> bool:
        """Permanently remove a key record. Use with caution."""
        cursor = self._conn().execute("DELETE FROM keys WHERE key_id = ?", (key_id,))
        self._conn().commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_info(row: sqlite3.Row) -> KeyInfo:
        return KeyInfo(
            key_id=row["key_id"],
            label=row["label"],
            public_key=row["public_key"],
            private_key=row["private_key"],
            not_before=row["not_before"],
            not_after=row["not_after"],
            status=row["status"],
            rotation_days=row["rotation_days"],
            created_at=row["created_at"],
        )

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
