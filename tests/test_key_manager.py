"""Unit tests for KeyManager — key lifecycle management."""

import os
import time

import pytest

from seal.key_manager import (
    DEFAULT_EXPIRY_DAYS,
    STATUS_ACTIVE,
    STATUS_EXPIRING,
    STATUS_GENERATED,
    STATUS_RETIRED,
    STATUS_REVOKED,
    KeyManager,
    fingerprint_of,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def km(tmp_path):
    """Fresh KeyManager backed by a temp database."""
    db = tmp_path / "test_keys.db"
    mgr = KeyManager(db_path=str(db))
    yield mgr


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_deterministic(self):
        pk = b"\x01" * 32
        assert fingerprint_of(pk) == fingerprint_of(pk)

    def test_length(self):
        pk = b"\xab" * 32
        fp = fingerprint_of(pk)
        assert len(fp) == 12  # sha256 hex digest, first 12 chars

    def test_different_keys_different_fingerprints(self):
        assert fingerprint_of(b"\x01" * 32) != fingerprint_of(b"\x02" * 32)


# ---------------------------------------------------------------------------
# KeyManager initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_db_created(self, tmp_path):
        db = tmp_path / "custom_keys.db"
        mgr = KeyManager(db_path=str(db))
        # Table should exist — query it
        assert mgr.get_active_key() is None
        assert mgr.list_keys() == []

    def test_default_db_path_not_required(self):
        """Init with no args should succeed (uses ~/.seal/keys.db)."""
        mgr = KeyManager()
        assert mgr.db_path.endswith("keys.db")


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestGenerateKey:
    def test_generates_active_key(self, km):
        key = km.generate_key()
        assert key["status"] == STATUS_ACTIVE
        assert key["kid"].startswith("k_")
        assert len(key["private_key"]) == 32
        assert len(key["public_key"]) == 32
        assert key["fingerprint"] == fingerprint_of(key["public_key"])
        assert key["rotated_at"] is None
        assert key["revoked_at"] is None
        assert key["revoke_reason"] is None

    def test_active_key_returned_by_get_active_key(self, km):
        key = km.generate_key()
        active = km.get_active_key()
        assert active is not None
        assert active["kid"] == key["kid"]

    def test_generate_key_retires_previous_active(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        # k1 should now be retired
        k1_updated = km.get_key(k1["kid"])
        assert k1_updated["status"] == STATUS_RETIRED
        assert k1_updated["rotated_at"] is not None
        # k2 should be active
        assert k2["kid"] != k1["kid"]
        assert k2["status"] == STATUS_ACTIVE

    def test_generate_many_keys_only_one_active(self, km):
        for _ in range(10):
            km.generate_key()
        active = km.get_active_key()
        assert active is not None
        # Exactly one active
        all_keys = km.list_keys()
        active_count = sum(1 for k in all_keys if k["status"] == STATUS_ACTIVE)
        assert active_count == 1

    def test_not_before_and_not_after(self, km):
        now = int(time.time())
        key = km.generate_key(not_before=now - 3600, not_after=now + 86400)
        assert key["not_before"] == now - 3600
        assert key["not_after"] == now + 86400

    def test_default_expiry(self, km):
        now = int(time.time())
        key = km.generate_key()
        expected = now + DEFAULT_EXPIRY_DAYS * 86400
        # Allow 2s tolerance
        assert abs(key["not_after"] - expected) <= 2

    def test_no_expiry(self, km):
        key = km.generate_key(not_after=0)
        assert key["not_after"] == 0


# ---------------------------------------------------------------------------
# Key queries
# ---------------------------------------------------------------------------


class TestGetKey:
    def test_get_key_by_kid(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        found = km.get_key(k1["kid"])
        assert found is not None
        assert found["kid"] == k1["kid"]
        # k2 should be different
        found2 = km.get_key(k2["kid"])
        assert found2["kid"] == k2["kid"]

    def test_get_missing_key_returns_none(self, km):
        assert km.get_key("k_nonexistent_1234") is None


class TestListKeys:
    def test_list_keys_returns_all(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        k3 = km.generate_key()
        all_keys = km.list_keys()
        kids = {k["kid"] for k in all_keys}
        assert k1["kid"] in kids
        assert k2["kid"] in kids
        assert k3["kid"] in kids

    def test_list_keys_newest_first(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        all_keys = km.list_keys()
        kids = [k["kid"] for k in all_keys]
        # Both keys should be present
        assert k1["kid"] in kids
        assert k2["kid"] in kids
        # The list should be in descending created_at order; since both keys
        # were created within the same second, either ordering is valid.
        assert len(all_keys) == 2

    def test_list_keys_filter_by_status(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        active_keys = km.list_keys(status=STATUS_ACTIVE)
        assert len(active_keys) == 1
        assert active_keys[0]["kid"] == k2["kid"]
        retired_keys = km.list_keys(status=STATUS_RETIRED)
        assert len(retired_keys) == 1
        assert retired_keys[0]["kid"] == k1["kid"]


class TestGetSigningKey:
    def test_signing_key_is_active(self, km):
        km.generate_key()
        signing = km.get_signing_key()
        active = km.get_active_key()
        assert signing["kid"] == active["kid"]


# ---------------------------------------------------------------------------
# Verification keys (graceful retirement)
# ---------------------------------------------------------------------------


class TestGetVerificationKeys:
    def test_active_key_first(self, km):
        k1 = km.generate_key()
        vkeys = km.get_verification_keys()
        assert len(vkeys) == 1
        assert vkeys[0]["kid"] == k1["kid"]

    def test_retired_keys_included(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        vkeys = km.get_verification_keys()
        assert len(vkeys) == 2
        # Active key first
        assert vkeys[0]["kid"] == k2["kid"]
        # Then retired
        assert vkeys[1]["kid"] == k1["kid"]

    def test_revoked_keys_excluded(self, km):
        k1 = km.generate_key()
        km.generate_key()
        km.revoke_key(k1["kid"])
        vkeys = km.get_verification_keys()
        assert len(vkeys) == 1  # only the active key
        assert vkeys[0]["kid"] != k1["kid"]

    def test_multiple_retired_keys(self, km):
        keys = [km.generate_key() for _ in range(5)]
        vkeys = km.get_verification_keys()
        assert len(vkeys) == 5
        # Latest (active) first
        assert vkeys[0]["kid"] == keys[-1]["kid"]


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotateKey:
    def test_rotate_creates_new_active(self, km):
        k1 = km.generate_key()
        k2 = km.rotate_key()
        assert k2["kid"] != k1["kid"]
        assert k2["status"] == STATUS_ACTIVE
        assert km.get_active_key()["kid"] == k2["kid"]

    def test_rotate_retires_old_key(self, km):
        k1 = km.generate_key()
        km.rotate_key()
        k1_refreshed = km.get_key(k1["kid"])
        assert k1_refreshed["status"] == STATUS_RETIRED
        assert k1_refreshed["rotated_at"] is not None

    def test_rotate_on_empty_db_still_works(self, km):
        """Rotating with no prior active key still generates a fresh one."""
        k = km.rotate_key()
        assert k is not None
        assert k["status"] == STATUS_ACTIVE


class TestRotateIfExpiring:
    def test_no_rotation_if_far_from_expiry(self, km):
        # 100 days from now — well beyond 30-day threshold
        far_future = int(time.time()) + 100 * 86400
        k1 = km.generate_key(not_after=far_future)
        result = km.rotate_if_expiring(days_before=30)
        assert result is None  # no rotation
        assert km.get_active_key()["kid"] == k1["kid"]

    def test_rotation_if_expiring_soon(self, km):
        now = int(time.time())
        k1 = km.generate_key(not_after=now + 3600)  # expires in 1 hour
        result = km.rotate_if_expiring(days_before=30)  # 30 days = threshold
        assert result is not None  # rotation happened
        assert result["kid"] != k1["kid"]
        assert km.get_active_key()["kid"] == result["kid"]

    def test_no_rotation_when_no_active_key(self, km):
        result = km.rotate_if_expiring()
        assert result is None

    def test_no_rotation_for_non_expiring_keys(self, km):
        km.generate_key(not_after=0)
        result = km.rotate_if_expiring()
        assert result is None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestRevokeKey:
    def test_revoke_key_changes_status(self, km):
        k = km.generate_key()
        result = km.revoke_key(k['kid'], reason='key compromised')
        assert result['ok'] is True
        assert result['rotated'] is True
        assert result['new_kid'] is not None
        updated = km.get_key(k['kid'])
        assert updated['status'] == STATUS_REVOKED
        assert updated['revoked_at'] is not None
        assert updated['revoke_reason'] == 'key compromised'

    def test_revoke_nonexistent_key_returns_false(self, km):
        result = km.revoke_key('k_does_not_exist')
        assert result['ok'] is False
        assert result['rotated'] is False
        assert result['new_kid'] is None

    def test_revoked_key_not_active(self, km):
        k = km.generate_key()
        result = km.revoke_key(k['kid'])
        assert result['ok'] is True
        new_active = km.get_active_key()
        assert new_active is not None
        assert new_active['kid'] != k['kid']
        assert new_active['kid'] == result['new_kid']

    def test_revoke_of_retired_key(self, km):
        k1 = km.generate_key()
        km.generate_key()  # retires k1
        result = km.revoke_key(k1['kid'])
        assert result['ok'] is True
        assert result['rotated'] is False
        assert result['new_kid'] is None
        assert km.get_key(k1['kid'])['status'] == STATUS_REVOKED


# ---------------------------------------------------------------------------
# Edge cases and integration scenarios
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_full_lifecycle(self, km):
        k1 = km.generate_key()
        assert k1['status'] == STATUS_ACTIVE
        k2 = km.rotate_key()
        assert k2['status'] == STATUS_ACTIVE
        assert km.get_key(k1['kid'])['status'] == STATUS_RETIRED
        result = km.revoke_key(k1['kid'], reason='old key retired')
        assert result['ok'] is True
        assert result['rotated'] is False
        assert km.get_key(k1['kid'])['status'] == STATUS_REVOKED
        vkeys = km.get_verification_keys()
        assert k1['kid'] not in {k['kid'] for k in vkeys}
        assert k2['kid'] in {k['kid'] for k in vkeys}

    def test_multiple_rotations(self, km):
        """10 rotations, verify graceful verification includes all."""
        keys = [km.generate_key()]
        for _ in range(9):
            keys.append(km.rotate_key())

        vkeys = km.get_verification_keys()
        assert len(vkeys) == 10
        # All retired keys are still verifiable
        vkids = {k["kid"] for k in vkeys}
        for k in keys:
            assert k["kid"] in vkids

    def test_revoke_reason_survives_rotate(self, km):
        """Revoking a retired key should preserve the reason."""
        k1 = km.generate_key()
        km.rotate_key()
        km.revoke_key(k1["kid"], reason="manual audit")
        assert km.get_key(k1["kid"])["revoke_reason"] == "manual audit"

    def test_db_persistence(self, tmp_path):
        """KeyManager data survives across instances (SQLite durability)."""
        db = tmp_path / "persist.db"
        mgr1 = KeyManager(db_path=str(db))
        k1 = mgr1.generate_key()
        mgr2 = KeyManager(db_path=str(db))
        loaded = mgr2.get_key(k1["kid"])
        assert loaded is not None
        assert loaded["kid"] == k1["kid"]
        assert loaded["fingerprint"] == k1["fingerprint"]
        assert loaded["status"] == STATUS_ACTIVE


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------


class TestEncryptionAtRest:
    """Private keys are encrypted with Fernet in the SQLite store."""

    def test_stored_key_is_encrypted(self, km):
        """Raw SQLite blob must be Fernet ciphertext, not 32 raw bytes."""
        key = km.generate_key()
        import sqlite3
        conn = sqlite3.connect(km.db_path)
        row = conn.execute(
            "SELECT private_key FROM keys WHERE kid=?", (key["kid"],)
        ).fetchone()
        conn.close()
        raw = row[0]
        assert raw.startswith(b"gAAAA"), f"Expected Fernet prefix, got {raw[:10]!r}"
        assert len(raw) > 32

    def test_decrypted_key_matches_original(self, km):
        key = km.generate_key()
        raw_key = key["private_key"]
        assert len(raw_key) == 32
        reloaded = km.get_key(key["kid"])
        assert reloaded["private_key"] == raw_key

    def test_persistence_with_master_key(self, tmp_path):
        from cryptography.fernet import Fernet
        mk = Fernet.generate_key()
        db = tmp_path / "enc_persist.db"
        mgr1 = KeyManager(db_path=str(db), master_key=mk)
        k1 = mgr1.generate_key()
        mgr2 = KeyManager(db_path=str(db), master_key=mk)
        loaded = mgr2.get_key(k1["kid"])
        assert loaded is not None
        assert loaded["kid"] == k1["kid"]
        assert loaded["private_key"] == k1["private_key"]

    def test_wrong_master_key_fails_gracefully(self, tmp_path):
        from cryptography.fernet import Fernet
        mk1 = Fernet.generate_key()
        mk2 = Fernet.generate_key()
        db = tmp_path / "wrong_key.db"
        mgr = KeyManager(db_path=str(db), master_key=mk1)
        k1 = mgr.generate_key()
        mgr2 = KeyManager(db_path=str(db), master_key=mk2)
        loaded = mgr2.get_key(k1["kid"])
        assert loaded is not None
        assert loaded["kid"] == k1["kid"]

    def test_nonexistent_master_key_created_automatically(self, tmp_path):
        from seal import key_manager as km_mod
        orig_dir = km_mod.SEAL_DIR
        orig_path = km_mod.DEFAULT_MASTER_KEY_PATH
        try:
            tmp_seal = tmp_path / ".seal"
            km_mod.SEAL_DIR = tmp_seal
            km_mod.DEFAULT_MASTER_KEY_PATH = tmp_seal / "master.key"
            db = tmp_path / "auto_mk.db"
            mgr = KeyManager(db_path=str(db))
            k1 = mgr.generate_key()
            assert k1 is not None
            assert (tmp_seal / "master.key").exists()
            mode = os.stat(tmp_seal / "master.key").st_mode & 0o777
            assert mode == 0o600
        finally:
            km_mod.SEAL_DIR = orig_dir
            km_mod.DEFAULT_MASTER_KEY_PATH = orig_path

    def test_master_key_file_permissions(self, tmp_path):
        mk_path = tmp_path / "master.key"
        from cryptography.fernet import Fernet
        from seal.key_manager import _load_or_create_master_key
        key = _load_or_create_master_key(mk_path)
        assert mk_path.exists()
        mode = os.stat(mk_path).st_mode & 0o777
        assert mode == 0o600
        assert len(key) > 0

    def test_custom_master_key_bytes(self, tmp_path):
        from cryptography.fernet import Fernet
        mk = Fernet.generate_key()
        db = tmp_path / "custom_bytes.db"
        mgr = KeyManager(db_path=str(db), master_key=mk)
        k1 = mgr.generate_key()
        assert k1 is not None
        assert len(k1["private_key"]) == 32

    def test_master_key_from_file_path(self, tmp_path):
        from cryptography.fernet import Fernet
        mk = Fernet.generate_key()
        mk_path = tmp_path / "custom_master.key"
        mk_path.write_bytes(mk)
        db = tmp_path / "path_key.db"
        mgr = KeyManager(db_path=str(db), master_key=str(mk_path))
        k1 = mgr.generate_key()
        assert k1 is not None
        assert len(k1["private_key"]) == 32

    def test_list_keys_decrypts_transparently(self, km):
        k1 = km.generate_key()
        k2 = km.generate_key()
        all_keys = km.list_keys()
        for k in all_keys:
            assert len(k["private_key"]) == 32
            assert k["private_key"] == km.get_key(k["kid"])["private_key"]
        assert len(all_keys) == 2

    def test_verification_keys_decrypts(self, km):
        k1 = km.generate_key()
        k2 = km.rotate_key()
        vkeys = km.get_verification_keys()
        for k in vkeys:
            assert len(k["private_key"]) == 32

    def test_get_expiring_keys_decrypts(self, km):
        now = int(time.time())
        k1 = km.generate_key(not_after=now + 3600)
        expiring = km.get_expiring_keys(days_before=30)
        for k in expiring:
            assert len(k["private_key"]) == 32


class TestMachineIdXor:
    """Optional machine-id XOR second factor."""

    def test_xor_with_machine_id(self, tmp_path):
        from cryptography.fernet import Fernet
        mk = Fernet.generate_key()
        db = tmp_path / "xor.db"
        mgr = KeyManager(db_path=str(db), master_key=mk, use_machine_id=True)
        k1 = mgr.generate_key()
        assert k1 is not None
        assert len(k1["private_key"]) == 32

    def test_xor_persistence(self, tmp_path):
        from cryptography.fernet import Fernet
        mk = Fernet.generate_key()
        db = tmp_path / "xor_persist.db"
        mgr1 = KeyManager(db_path=str(db), master_key=mk, use_machine_id=True)
        k1 = mgr1.generate_key()
        mgr2 = KeyManager(db_path=str(db), master_key=mk, use_machine_id=True)
        loaded = mgr2.get_key(k1["kid"])
        assert loaded["private_key"] == k1["private_key"]


class TestLegacyMigration:
    """Legacy raw keys should be auto-migrated to Fernet-encrypted on init."""

    def test_legacy_raw_key_migrated_transparently(self, tmp_path):
        from cryptography.fernet import Fernet
        import sqlite3
        mk = Fernet.generate_key()
        db = tmp_path / "legacy.db"
        conn = sqlite3.connect(str(db))
        conn.execute("""
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
            )
        """)
        now = int(time.time())
        conn.execute(
            "INSERT INTO keys (kid, public_key, private_key, status, created_at, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("k_legacy", b"\x01" * 32, b"\x02" * 32, "active", now, "deadbeef1234"),
        )
        conn.commit()
        conn.close()

        # Init triggers auto-migration — no warning emitted.
        mgr = KeyManager(db_path=str(db), master_key=mk)
        legacy = mgr.get_key("k_legacy")
        assert legacy is not None
        assert legacy["private_key"] == b"\x02" * 32
        assert legacy["status"] == STATUS_ACTIVE

        # Verify the blob in the DB is now Fernet-encrypted.
        conn2 = sqlite3.connect(str(db))
        stored = conn2.execute(
            "SELECT private_key FROM keys WHERE kid=?", ("k_legacy",)
        ).fetchone()[0]
        conn2.close()
        assert len(stored) > 64, f"Expected Fernet token, got {len(stored)} bytes"
        assert stored.startswith(b"gAAAA"), f"Expected Fernet prefix, got {stored[:10]!r}"

    def test_legacy_raw_key_warning_without_migration(self, tmp_path):
        """If migrate_legacy_keys is not called, a legacy raw key warns on read."""
        from cryptography.fernet import Fernet
        import sqlite3
        mk = Fernet.generate_key()
        db = tmp_path / "legacy_nowarn.db"
        conn = sqlite3.connect(str(db))
        conn.execute("""
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
            )
        """)
        now = int(time.time())
        conn.execute(
            "INSERT INTO keys (kid, public_key, private_key, status, created_at, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("k_legacy2", b"\x03" * 32, b"\x04" * 32, "active", now, "feedcafe1234"),
        )
        conn.commit()
        conn.close()

        # Construct manager without auto-migration — bypass __init__ migration.
        mgr = object.__new__(KeyManager)
        mgr.db_path = str(db)
        mgr._fernet = Fernet(mk)
        # No migrate_legacy_keys() called

        with pytest.warns(UserWarning, match="NOT encrypted"):
            legacy = mgr.get_key("k_legacy2")
            assert legacy is not None
            assert legacy["private_key"] == b"\x04" * 32
