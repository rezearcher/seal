"""Key lifecycle management — SQLite-backed Ed25519 key registry.

Implements the key lifecycle for the Seal VPE::

    generated → active → expiring → retired → revoked

A single registry (``~/.seal/keys.db``) tracks every key the local agent has
ever held.  At most one key is ``active`` at a time — that is the signing key.
Retired keys are kept so that envelopes signed *before* a rotation still verify
(graceful verification).  Revoked keys are never used for signing or
verification again.

Private keys are encrypted at rest with **Fernet** (``cryptography.fernet``).
The encryption key lives in ``~/.seal/master.key`` (auto-generated on first
use, ``chmod 600``).  An optional second factor XORs the Fernet key with the
host's ``/etc/machine-id`` (when ``use_machine_id=True``).

The store is plain ``sqlite3`` (stdlib only).  Connections use WAL journalling
and a 5s busy timeout so concurrent CLI invocations don't trip over each other.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
import time
import warnings
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from seal.core import generate_key_pair, vpe_verify, vpe_verify_hmac

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEAL_DIR = Path.home() / ".seal"
DEFAULT_DB_PATH = SEAL_DIR / "keys.db"
DEFAULT_MASTER_KEY_PATH = SEAL_DIR / "master.key"

# Lifecycle states.
STATUS_GENERATED = "generated"
STATUS_ACTIVE = "active"
STATUS_EXPIRING = "expiring"
STATUS_RETIRED = "retired"
STATUS_REVOKED = "revoked"

VALID_STATUSES = (
    STATUS_GENERATED,
    STATUS_ACTIVE,
    STATUS_EXPIRING,
    STATUS_RETIRED,
    STATUS_REVOKED,
)

# Default validity window for a freshly generated key.
DEFAULT_EXPIRY_DAYS = 90
_SECONDS_PER_DAY = 86_400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    kid TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    not_before INTEGER DEFAULT 0,
    not_after INTEGER DEFAULT 0,
    rotated_at INTEGER,
    revoked_at INTEGER,
    revoke_reason TEXT,
    fingerprint TEXT NOT NULL
);
"""

# Columns in declaration order — used to build plain dicts from rows.
_COLUMNS = (
    "kid",
    "public_key",
    "private_key",
    "status",
    "created_at",
    "not_before",
    "not_after",
    "rotated_at",
    "revoked_at",
    "revoke_reason",
    "fingerprint",
)

# Fernet tokens (v0 / v1) always start with this base64 prefix.
_FERNET_PREFIX = b"gAAAA"

# Known machine-id locations, tried in order.
_MACHINE_ID_PATHS = (
    Path("/etc/machine-id"),
    Path("/var/lib/dbus/machine-id"),
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Master key management
# ---------------------------------------------------------------------------


def _ensure_seal_dir() -> None:
    """Create ``~/.seal`` with ``0700`` perms."""
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SEAL_DIR.chmod(0o700)
    except OSError:  # pragma: no cover - non-POSIX or restricted FS
        pass


def _load_or_create_master_key(path: Path | None = None) -> bytes:
    """Return the Fernet key from *path*, generating one if absent.

    The key file is created with ``0600`` permissions.  Returns the raw
    44-byte URL-safe-base64 key suitable for ``Fernet()``.
    """
    keyfile = (path or DEFAULT_MASTER_KEY_PATH).expanduser()
    if keyfile.exists():
        return keyfile.read_bytes().strip()
    _ensure_seal_dir()
    key = Fernet.generate_key()
    # Write with 0600 from the start: create exclusively, then chmod.
    fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        keyfile.chmod(0o600)
    except OSError:  # pragma: no cover
        pass
    return key


def _read_machine_id() -> bytes | None:
    """Return the first 44 bytes of machine-id, or None."""
    for p in _MACHINE_ID_PATHS:
        try:
            raw = p.read_bytes().strip()
            return raw[:44]
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return None


def _derive_fernet_key(
    master_key_bytes: bytes, use_machine_id: bool = False
) -> bytes:
    """Derive the effective Fernet key, optionally XOR'd with machine-id.

    XOR provides a cheap second factor: a key stolen from a different host
    (or without filesystem access to ``/etc/machine-id``) cannot decrypt the
    store.

    The XOR operates on the raw 32-byte key material (base64 decoded) then
    re-encodes to URL-safe base64 so the result is always a valid Fernet key.
    """
    if not use_machine_id:
        return master_key_bytes

    mid = _read_machine_id()
    if mid is None:
        log.warning("use_machine_id=True but no machine-id found; falling back to master key alone")
        return master_key_bytes

    # Decode to raw 32 bytes, XOR with machine-id, re-encode.
    import base64

    raw_key = base64.urlsafe_b64decode(master_key_bytes)
    # XOR byte-by-byte, cycling machine-id if shorter.
    xored = bytes(a ^ b for a, b in zip(raw_key, mid))
    return base64.urlsafe_b64encode(xored)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fingerprint_of(public_key: bytes) -> str:
    """Return the hex fingerprint of a public key (sha256, first 12 hex chars)."""
    return hashlib.sha256(public_key).hexdigest()[:12]


def _make_kid(created_at: int) -> str:
    """Build a key identifier, e.g. ``k_20260607_a1b2c3d4e5f6a7b8``.

    The date component is derived from ``created_at`` (UTC) so a kid is
    self-describing; the random suffix guarantees uniqueness.
    """
    datestamp = time.strftime("%Y%m%d", time.gmtime(created_at))
    return f"k_{datestamp}_{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Fernet helpers for private key encryption
# ---------------------------------------------------------------------------


def _is_encrypted(private_key_blob: bytes) -> bool:
    """Return True if the blob looks like a Fernet ciphertext."""
    return private_key_blob.startswith(_FERNET_PREFIX)


def _encrypt_private_key(raw: bytes, fernet: Fernet) -> bytes:
    """Encrypt a raw private key with Fernet."""
    return fernet.encrypt(raw)


def _decrypt_private_key(blob: bytes, fernet: Fernet) -> bytes:
    """Decrypt a private key blob.

    If the blob is not Fernet-encrypted (i.e. a legacy raw key), a warning
    is issued and the blob is returned as-is.

    Returns:
        Decrypted (or raw) private key bytes.
    """
    if not _is_encrypted(blob):
        warnings.warn(
            "Private key at rest is NOT encrypted — this is a security risk. "
            "Regenerate or rotate keys to encrypt them with the master key.",
            stacklevel=2,
        )
        return blob
    try:
        return fernet.decrypt(blob)
    except InvalidToken:
        warnings.warn(
            "Private key decryption FAILED — master key mismatch or corrupt "
            "data.  Using raw bytes as fallback (may cause signing errors).",
            stacklevel=2,
        )
        return blob


def _row_to_dict(row: sqlite3.Row | tuple | None, fernet: Fernet | None = None) -> dict | None:
    """Convert a sqlite row into a plain dict (or None).

    If *fernet* is provided and the row has an encrypted ``private_key``, it
    is transparently decrypted.  Legacy raw keys are passed through with a
    warning.
    """
    if row is None:
        return None
    d = {col: row[col] for col in _COLUMNS}
    if fernet is not None and "private_key" in d:
        d["private_key"] = _decrypt_private_key(d["private_key"], fernet)
    return d


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------


class KeyManager:
    """SQLite-backed registry of Ed25519 keys with lifecycle management.

    Private keys are encrypted at rest with Fernet.  See module docstring
    for details on the master key setup.
    """

    def __init__(
        self,
        db_path: str | None = None,
        master_key: bytes | str | None = None,
        use_machine_id: bool = False,
    ):
        """Initialize the key manager.

        Args:
            db_path: Path to the SQLite store. Defaults to ``~/.seal/keys.db``.
                     The parent directory is created if missing.
            master_key: Fernet key as bytes, a file path (str), or None to
                        auto-load/create ``~/.seal/master.key``.
            use_machine_id: If True, XOR the Fernet key with the host's
                            ``/etc/machine-id`` for an additional factor.
        """
        self.db_path = str(db_path) if db_path is not None else str(DEFAULT_DB_PATH)
        parent = Path(self.db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            parent.chmod(0o700)
        except OSError:
            pass

        # Resolve the Fernet key.
        if master_key is None:
            master_key_bytes = _load_or_create_master_key()
        elif isinstance(master_key, str):
            # Treat as a file path.
            master_key_bytes = Path(master_key).expanduser().read_bytes().strip()
        elif isinstance(master_key, bytes):
            master_key_bytes = master_key
        else:
            raise TypeError(f"master_key must be bytes, str (path), or None, got {type(master_key)}")

        effective = _derive_fernet_key(master_key_bytes, use_machine_id=use_machine_id)
        self._fernet = Fernet(effective)

        self.init_registry()
        self.migrate_legacy_keys()

    # -- connection -------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open a fresh connection (WAL, 5s busy timeout, Row factory).

        A new connection per call keeps the manager safe to share across
        threads — sqlite3 connections are not thread-safe to reuse.
        """
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def init_registry(self) -> None:
        """Create the ``keys`` table if it does not already exist."""
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _migrate_legacy_keys(self) -> None:
        """Re-encrypt any legacy (raw) private keys in the store.

        Scans all rows; if a private_key column contains raw bytes (32-byte
        Ed25519) instead of a Fernet token, it is re-encrypted in-place.
        This runs once at ``__init__`` so migration is transparent.
        """
        conn = self._connect()
        try:
            rows = conn.execute("SELECT kid, private_key FROM keys").fetchall()
            updates = []
            for row in rows:
                blob = row["private_key"]
                if blob is not None and not _is_encrypted(blob):
                    # Raw key — encrypt it.
                    encrypted = _encrypt_private_key(blob, self._fernet)
                    updates.append((encrypted, row["kid"]))
                    log.info(
                        "Migrated legacy raw key %s to Fernet encryption",
                        row["kid"],
                    )
            for encrypted, kid in updates:
                conn.execute(
                    "UPDATE keys SET private_key=? WHERE kid=?", (encrypted, kid)
                )
            if updates:
                conn.commit()
        finally:
            conn.close()

    def migrate_legacy_keys(self) -> int:
        """Encrypt any raw (unencrypted) private keys in the store.

        Scans all rows for private_key blobs that do not start with the
        Fernet prefix and re-encrypts them with ``self._fernet``.

        Returns:
            The number of keys migrated.
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT kid, private_key FROM keys WHERE length(private_key) < 64",
            ).fetchall()
            if not rows:
                return 0

            migrated = 0
            for row in rows:
                kid, raw = row["kid"], row["private_key"]
                encrypted = _encrypt_private_key(raw, self._fernet)
                conn.execute(
                    "UPDATE keys SET private_key=? WHERE kid=?",
                    (encrypted, kid),
                )
                migrated += 1
            conn.commit()
            log.info("Migrated %d legacy raw keys to Fernet-encrypted", migrated)
            return migrated
        finally:
            conn.close()

    # -- generation / rotation -------------------------------------------

    def generate_key(self, **metadata) -> dict:
        """Generate a new Ed25519 key pair and register it as ``active``.

        Any previously active key is retired (status ``retired``,
        ``rotated_at`` set to now) so that exactly one key is active.

        The private key is **encrypted with Fernet** before being stored in
        the SQLite database.

        Keyword Args (all optional):
            not_before: Unix timestamp when the key becomes usable (default 0).
            not_after: Unix timestamp when the key expires. Defaults to
                       ``now + DEFAULT_EXPIRY_DAYS`` days. Pass ``0`` for a
                       key that never expires.

        Returns:
            The full row for the new active key as a dict.  The
            ``private_key`` field is the **decrypted** raw bytes (encrypted
            at rest).
        """
        now = int(time.time())
        pair = generate_key_pair()
        public_key = pair["public_key"]
        private_key = pair["private_key"]

        kid = _make_kid(now)
        not_before = int(metadata.get("not_before", 0))
        if "not_after" in metadata:
            not_after = int(metadata["not_after"])
        else:
            not_after = now + DEFAULT_EXPIRY_DAYS * _SECONDS_PER_DAY
        fingerprint = fingerprint_of(public_key)

        # Encrypt private key for storage.
        encrypted_private = _encrypt_private_key(private_key, self._fernet)

        conn = self._connect()
        try:
            # Retire whatever is currently active so only one key is active.
            conn.execute(
                "UPDATE keys SET status=?, rotated_at=? WHERE status=?",
                (STATUS_RETIRED, now, STATUS_ACTIVE),
            )
            conn.execute(
                """
                INSERT INTO keys (
                    kid, public_key, private_key, status, created_at,
                    not_before, not_after, rotated_at, revoked_at,
                    revoke_reason, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kid,
                    public_key,
                    encrypted_private,  # ← encrypted
                    STATUS_ACTIVE,
                    now,
                    not_before,
                    not_after,
                    None,
                    None,
                    None,
                    fingerprint,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()
        finally:
            conn.close()
        return _row_to_dict(row, fernet=self._fernet)

    def rotate_key(self) -> dict:
        """Rotate the active key.

        Retires the current active key (``rotated_at`` set) and generates a
        fresh active key. Equivalent to :meth:`generate_key` — the retirement
        of the prior active key is handled there.

        Returns:
            The new active key dict.
        """
        return self.generate_key()

    def rotate_if_expiring(self, days_before: int = 30) -> dict | None:
        """Auto-rotate if the active key expires within ``days_before`` days.

        Returns:
            The new active key dict if a rotation happened, else None.
        """
        expiring = self.get_expiring_keys(days_before=days_before)
        active = self.get_active_key()
        if active is None:
            return None
        if any(k["kid"] == active["kid"] for k in expiring):
            return self.rotate_key()
        return None

    # -- revocation -------------------------------------------------------

    def revoke_key(self, kid: str, reason: str = "") -> dict:
        """Revoke a key (status ``revoked``, ``revoked_at`` set).

        If the revoked key was the currently ``active`` signing key, a fresh
        key is auto-generated so the agent always has a valid signing key —
        revoking the active key must never leave the registry without one.

        Returns:
            dict: ``{"ok": bool, "rotated": bool, "new_kid": str | None}``.
            ``ok`` is False if no key with ``kid`` existed. ``rotated`` is True
            iff a replacement key was generated, with its kid in ``new_kid``.
        """
        now = int(time.time())
        conn = self._connect()
        try:
            # Capture the prior status so we know whether to auto-rotate.
            prior = conn.execute(
                "SELECT status FROM keys WHERE kid=?", (kid,)
            ).fetchone()
            cur = conn.execute(
                "UPDATE keys SET status=?, revoked_at=?, revoke_reason=? WHERE kid=?",
                (STATUS_REVOKED, now, reason, kid),
            )
            conn.commit()
            existed = cur.rowcount > 0
        finally:
            conn.close()

        if not existed:
            return {"ok": False, "rotated": False, "new_kid": None}

        was_active = prior is not None and prior["status"] == STATUS_ACTIVE
        # Belt-and-suspenders: only rotate if no active key remains.
        if was_active and self.get_active_key() is None:
            new_key = self.generate_key()
            return {"ok": True, "rotated": True, "new_kid": new_key["kid"]}
        return {"ok": True, "rotated": False, "new_kid": None}

    # -- queries ----------------------------------------------------------

    def get_active_key(self) -> dict | None:
        """Return the currently active signing key, or None.

        The ``private_key`` field is decrypted transparently.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM keys WHERE status=? ORDER BY created_at DESC LIMIT 1",
                (STATUS_ACTIVE,),
            ).fetchone()
        finally:
            conn.close()
        return _row_to_dict(row, fernet=self._fernet)

    def get_signing_key(self) -> dict | None:
        """Return the active key for signing new envelopes.

        Belt-and-suspenders: never hand back a revoked key. ``get_active_key``
        already filters on ``status='active'``, but we re-check here so a key
        revoked out from under us can never be used to sign.

        The ``private_key`` field is decrypted transparently.
        """
        key = self.get_active_key()
        if key is not None and key["status"] == STATUS_REVOKED:
            return None
        return key

    def get_key(self, kid: str) -> dict | None:
        """Return a specific key by kid, or None.

        The ``private_key`` field is decrypted transparently.
        """
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()
        finally:
            conn.close()
        return _row_to_dict(row, fernet=self._fernet)

    def list_keys(self, status: str | None = None) -> list[dict]:
        """List keys (newest first), optionally filtered by status.

        The ``private_key`` field is decrypted transparently on each key.
        """
        conn = self._connect()
        try:
            if status is None:
                rows = conn.execute(
                    "SELECT * FROM keys ORDER BY created_at DESC, kid DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM keys WHERE status=? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
        finally:
            conn.close()
        return [_row_to_dict(r, fernet=self._fernet) for r in rows]

    def get_verification_keys(self) -> list[dict]:
        """Return keys usable for verifying signatures: active + retired.

        Revoked keys are excluded. Order: the active key first, then retired
        keys by ``created_at`` descending. This lets old envelopes (signed by a
        since-rotated key) still verify.

        The ``private_key`` field is decrypted transparently on each key.
        """
        conn = self._connect()
        try:
            # ``status='active'`` sorts before ``'retired'`` lexicographically,
            # but we order explicitly to be robust: active first, then retired
            # newest-first.
            rows = conn.execute(
                """
                SELECT * FROM keys
                WHERE status IN (?, ?)
                ORDER BY CASE status WHEN ? THEN 0 ELSE 1 END,
                         created_at DESC
                """,
                (STATUS_ACTIVE, STATUS_RETIRED, STATUS_ACTIVE),
            ).fetchall()
        finally:
            conn.close()
        return [_row_to_dict(r, fernet=self._fernet) for r in rows]

    def get_expiring_keys(self, days_before: int = 30) -> list[dict]:
        """Return active keys that expire within ``days_before`` days.

        Keys with ``not_after == 0`` (no expiry) are excluded.

        The ``private_key`` field is decrypted transparently on each key.
        """
        now = int(time.time())
        threshold = now + days_before * _SECONDS_PER_DAY
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM keys
                WHERE status=? AND not_after > 0 AND not_after <= ?
                ORDER BY not_after ASC
                """,
                (STATUS_ACTIVE, threshold),
            ).fetchall()
        finally:
            conn.close()
        return [_row_to_dict(r, fernet=self._fernet) for r in rows]

    # -- lifecycle-aware verification -------------------------------------

    def verify_with_lifecycle(self, envelope_str: str) -> dict:
        """Verify a VPE envelope using the key manager's key store.

        Checks all active and retired verification keys, applying each
        key's ``not_before`` / ``not_after`` time constraints.  This
        supports graceful transition: envelopes signed by a since-rotated
        key still verify as long as the key was valid at signing time.

        Returns:
            dict: ``{"valid": bool, "reason": str, "kid": str | None}``
        """
        keys = self.get_verification_keys()
        if not keys:
            return {"valid": False, "reason": "no_verification_keys", "kid": None}

        for key in keys:
            result = vpe_verify(
                envelope_str,
                public_key=key["public_key"],
                not_before=key.get("not_before") or None,
                not_after=key.get("not_after") or None,
            )
            if result["valid"]:
                return {"valid": True, "reason": "ok", "kid": key["kid"]}

        # Last attempt: try without time constraints (fully expired keys
        # that haven't been revoked yet — audit trail purposes).
        for key in keys:
            result = vpe_verify(
                envelope_str,
                public_key=key["public_key"],
            )
            if result["valid"]:
                return {
                    "valid": True,
                    "reason": "ok_but_key_expired",
                    "kid": key["kid"],
                }

        return {"valid": False, "reason": "no_key_verifies", "kid": None}

    def check_expired_active_key(self) -> dict | None:
        """Check if the active key has expired.

        Returns:
            The expired key dict if expired, or None if the active key
            is still valid (or there is no active key).
        """
        active = self.get_active_key()
        if active is None:
            return None
        not_after = active.get("not_after", 0)
        if not_after > 0 and int(time.time()) >= not_after:
            return active
        return None

    def check_premature_key(self) -> dict | None:
        """Check if the active key's ``not_before`` is in the future.

        Returns:
            The premature key dict if not yet valid, or None.
        """
        active = self.get_active_key()
        if active is None:
            return None
        not_before = active.get("not_before", 0)
        if not_before > 0 and int(time.time()) < not_before:
            return active
        return None

    # -- rotation daemon --------------------------------------------------

    @staticmethod
    def run_rotation_daemon(
        db_path: str | None = None,
        days_before: int = 30,
        interval_seconds: int = 3600,
        once: bool = False,
    ) -> None:
        """Run the automatic key rotation daemon.

        Periodically checks if the active key is nearing expiry and
        rotates it if needed.  Can run as a one-shot (for cron) or
        as a persistent daemon.

        Args:
            db_path: Path to the key database.
            days_before: Rotate when this many days remain before expiry.
            interval_seconds: Seconds between checks (daemon mode only).
            once: If True, check once and return (cron mode).
        """
        km = KeyManager(db_path=db_path)

        while True:
            now = int(time.time())
            active = km.get_active_key()
            if active:
                not_after = active.get("not_after", 0)
                remaining_days = (
                    (not_after - now) / _SECONDS_PER_DAY if not_after > 0 else float("inf")
                )
                if not_after > 0 and remaining_days <= days_before:
                    new_key = km.rotate_key()
                    print(
                        f"[seal-rotator] rotated key {active['kid']} → "
                        f"{new_key['kid']} "
                        f"(had {remaining_days:.1f}d remaining)"
                    )
                elif not_after > 0 and now >= not_after:
                    # Already expired — rotate immediately
                    new_key = km.rotate_key()
                    print(
                        f"[seal-rotator] rotated expired key {active['kid']} → "
                        f"{new_key['kid']}"
                    )
                else:
                    print(
                        f"[seal-rotator] key {active['kid']} OK "
                        f"({remaining_days:.1f}d remaining)"
                    )
            else:
                # No active key — generate one
                new_key = km.generate_key()
                print(
                    f"[seal-rotator] no active key — generated {new_key['kid']}"
                )

            if once:
                break
            time.sleep(interval_seconds)
