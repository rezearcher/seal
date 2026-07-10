"""Unit tests for P9.2 — time-based key expiry and rotation daemon."""

import os
import tempfile
import time

import pytest

from seal.core import (
    generate_key_pair,
    vpe_sign,
    vpe_sign_hmac,
    vpe_verify,
    vpe_verify_hmac,
)
from seal.key_manager import KeyManager


@pytest.fixture
def km():
    """KeyManager with a temporary SQLite database and an initial active key."""
    tmp = tempfile.mktemp(suffix=".db")
    mgr = KeyManager(db_path=tmp)
    mgr.generate_key()  # seed so get_active_key() returns a key
    yield mgr
    try:
        os.unlink(tmp)
    except OSError:
        pass


class TestKeyGenerationWithTimeWindow:
    def test_default_expiry_set(self, km):
        key = km.get_active_key()
        assert key is not None
        now = int(time.time())
        assert key["not_after"] > now

    def test_custom_not_after(self, km):
        now = int(time.time())
        key = km.generate_key(not_after=now + 3600)
        assert key["not_after"] == now + 3600

    def test_custom_not_before(self, km):
        now = int(time.time())
        key = km.generate_key(not_before=now + 3600)
        assert key["not_before"] == now + 3600

    def test_zero_not_after_means_no_expiry(self, km):
        key = km.generate_key(not_after=0)
        assert key["not_after"] == 0

    def test_not_after_stored_and_retrieved(self, km):
        now = int(time.time())
        k = km.generate_key(not_after=now + 7200)
        assert k["not_after"] == now + 7200


class TestVerifyTimeConstraints:
    def test_expired_key_rejection(self):
        keys = generate_key_pair()
        env = vpe_sign("test", private_key=keys["private_key"])
        now = int(time.time())
        result = vpe_verify(env, public_key=keys["public_key"], not_after=now - 1)
        assert result["valid"] is False
        assert result["reason"] == "key_expired"

    def test_premature_key_rejection(self):
        keys = generate_key_pair()
        env = vpe_sign("test", private_key=keys["private_key"])
        now = int(time.time())
        result = vpe_verify(env, public_key=keys["public_key"], not_before=now + 3600)
        assert result["valid"] is False
        assert result["reason"] == "key_not_yet_valid"

    def test_valid_time_window(self):
        keys = generate_key_pair()
        env = vpe_sign("test", private_key=keys["private_key"])
        now = int(time.time())
        result = vpe_verify(env, public_key=keys["public_key"], not_before=now - 100, not_after=now + 3600)
        assert result["valid"] is True

    def test_no_time_constraints_still_works(self):
        keys = generate_key_pair()
        env = vpe_sign("test", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_expired_key_rejection_hmac(self):
        secret = b"test-secret-32-bytes-for-hmac-testing!"
        env = vpe_sign_hmac("test", shared_secret=secret)
        now = int(time.time())
        result = vpe_verify_hmac(env, shared_secret=secret, not_after=now - 1)
        assert result["valid"] is False
        assert result["reason"] == "key_expired"

    def test_premature_key_rejection_hmac(self):
        secret = b"test-secret-32-bytes-for-hmac-testing!"
        env = vpe_sign_hmac("test", shared_secret=secret)
        now = int(time.time())
        result = vpe_verify_hmac(env, shared_secret=secret, not_before=now + 3600)
        assert result["valid"] is False
        assert result["reason"] == "key_not_yet_valid"

    def test_signature_mismatch_takes_priority(self):
        keys = generate_key_pair()
        other = generate_key_pair()
        env = vpe_sign("test", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=other["public_key"], not_after=1)
        assert result["valid"] is False
        assert "signature_mismatch" in result["reason"]


class TestVerifyWithLifecycle:
    def test_verify_with_active_key(self, km):
        active = km.get_active_key()
        env = vpe_sign("hello", private_key=active["private_key"])
        result = km.verify_with_lifecycle(env)
        assert result["valid"] is True
        assert result["kid"] == active["kid"]

    def test_verify_graceful_transition(self, km):
        active = km.get_active_key()
        env = vpe_sign("old sig", private_key=active["private_key"])
        km.rotate_key()
        result = km.verify_with_lifecycle(env)
        assert result["valid"] is True
        assert result["kid"] == active["kid"]

    def test_verify_no_keys(self):
        tmp = tempfile.mktemp(suffix=".db")
        try:
            km = KeyManager(db_path=tmp)
            keys = generate_key_pair()
            env = vpe_sign("test", private_key=keys["private_key"])
            result = km.verify_with_lifecycle(env)
            assert result["valid"] is False
            assert "no_verification_keys" in result["reason"]
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


class TestKeyExpiryDetection:
    def test_expired_key_detected(self, km):
        now = int(time.time())
        km.generate_key(not_after=now - 1)
        expired = km.check_expired_active_key()
        assert expired is not None
        assert expired["status"] == "active"

    def test_valid_key_not_expired(self, km):
        assert km.check_expired_active_key() is None

    def test_no_active_key_not_expired(self):
        tmp = tempfile.mktemp(suffix=".db")
        try:
            assert KeyManager(db_path=tmp).check_expired_active_key() is None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_premature_key_detected(self, km):
        now = int(time.time())
        km.generate_key(not_before=now + 3600)
        assert km.check_premature_key() is not None


class TestRotationFlow:
    def test_rotate_creates_new_active(self, km):
        old = km.get_active_key()
        new = km.rotate_key()
        assert new["kid"] != old["kid"]
        assert new["status"] == "active"

    def test_old_key_retired_after_rotation(self, km):
        old_kid = km.get_active_key()["kid"]
        km.rotate_key()
        assert km.get_key(old_kid)["status"] == "retired"

    def test_rotate_if_expiring_skips_valid(self, km):
        assert km.rotate_if_expiring(days_before=1) is None

    def test_rotate_if_expiring_triggers(self, km):
        now = int(time.time())
        km.generate_key(not_after=now + 3600)
        assert km.rotate_if_expiring(days_before=365) is not None

    def test_get_verification_keys_includes_retired(self, km):
        k1 = km.get_active_key()
        km.rotate_key()
        assert k1["kid"] in [k["kid"] for k in km.get_verification_keys()]

    def test_get_verification_keys_excludes_revoked(self, km):
        k1 = km.get_active_key()
        km.revoke_key(k1["kid"], reason="test")
        assert k1["kid"] not in [k["kid"] for k in km.get_verification_keys()]


class TestRotationDaemon:
    def test_daemon_once_generates_key_if_none(self):
        tmp = tempfile.mktemp(suffix=".db")
        try:
            KeyManager.run_rotation_daemon(db_path=tmp, once=True)
            assert KeyManager(db_path=tmp).get_active_key() is not None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_daemon_once_rotates_expired_key(self, km):
        now = int(time.time())
        km.generate_key(not_after=now - 1)
        old = km.get_active_key()
        KeyManager.run_rotation_daemon(db_path=km.db_path, once=True)
        new = km.get_active_key()
        assert old["kid"] != new["kid"] or old["status"] != "active"
