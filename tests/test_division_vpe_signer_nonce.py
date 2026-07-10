"""Tests for DivisionVPESigner persistent nonce store (replay protection).

Verifies that a replayed nonce is rejected even when verify_stored_value is
called on a fresh DivisionVPESigner instance that shares the same NonceStore
db_path — simulating a process restart.
"""

from __future__ import annotations

import pytest

from seal.integration.division_vpe_signer import DivisionVPESigner
from seal.store import NonceStore


@pytest.fixture
def nonce_db(tmp_path):
    """Path to a temporary NonceStore database."""
    return str(tmp_path / "test_nonces.db")


@pytest.fixture
def keypair_dir(tmp_path):
    """Temporary directory for VPE keypair."""
    return str(tmp_path / "vpe-keys")


def _make_signer(key_dir: str, nonce_db: str) -> DivisionVPESigner:
    """Create a signer backed by a NonceStore at the given db path."""
    signer = DivisionVPESigner(
        key_dir=key_dir,
        mode="sign",
        nonce_store=NonceStore(db_path=nonce_db),
    )
    signer.ensure_keys()
    return signer


def test_replay_rejected_across_restarts(keypair_dir, nonce_db):
    """A replayed nonce is rejected by a fresh signer instance sharing the same DB.

    Sequence:
      1. Signer A signs and stores a value — nonce recorded in persistent DB.
      2. Signer B (fresh instance, same DB path) verifies the same signed value
         → valid on first call.
      3. Signer C (another fresh instance, same DB path) tries to verify the
         same value again → must be rejected as a replay.
    """
    signer_a = _make_signer(keypair_dir, nonce_db)

    value = {"secret": "discovery", "score": 99}
    signed = signer_a.wrap_for_storage(value, domain="recon", agent="hermes")

    assert isinstance(signed, dict), "wrap_for_storage must return a signed wrapper"
    assert signed.get("__vpe_signed__") is True

    # First verification on a fresh instance — should pass
    signer_b = _make_signer(keypair_dir, nonce_db)
    result_first = signer_b.verify_stored_value(signed)
    assert result_first.valid is True, f"First verification should succeed; got: {result_first.reason}"

    # Second verification on another fresh instance — same nonce, must be rejected
    signer_c = _make_signer(keypair_dir, nonce_db)
    result_replay = signer_c.verify_stored_value(signed)
    assert result_replay.valid is False, "Replayed nonce must be rejected across process-restart simulation"
    assert "replay" in result_replay.reason.lower(), f"Reason should mention replay; got: {result_replay.reason}"


def test_different_values_not_affected(keypair_dir, nonce_db):
    """Two distinct signed values (different nonces) both verify successfully."""
    signer = _make_signer(keypair_dir, nonce_db)

    signed_a = signer.wrap_for_storage({"id": 1}, domain="test", agent="hermes")
    signed_b = signer.wrap_for_storage({"id": 2}, domain="test", agent="hermes")

    verifier = DivisionVPESigner(
        key_dir=keypair_dir,
        mode="verify",
        nonce_store=NonceStore(db_path=nonce_db),
    )
    verifier.ensure_keys()

    result_a = verifier.verify_stored_value(signed_a)
    result_b = verifier.verify_stored_value(signed_b)

    assert result_a.valid is True, f"First value should verify; got: {result_a.reason}"
    assert result_b.valid is True, f"Second value should verify; got: {result_b.reason}"


def test_in_memory_fallback_when_no_nonce_store(keypair_dir):
    """When nonce_store=None is forced, falls back to in-memory set."""
    signer = DivisionVPESigner(
        key_dir=keypair_dir,
        mode="sign",
        nonce_store=None,
    )
    # Patch out the auto-created NonceStore so we get the in-memory path
    signer._nonce_store = None
    signer._seen_nonces = set()
    signer.ensure_keys()

    signed = signer.wrap_for_storage({"x": 1}, domain="test", agent="hermes")

    verifier = DivisionVPESigner(
        key_dir=keypair_dir,
        mode="verify",
        nonce_store=None,
    )
    verifier._nonce_store = None
    verifier._seen_nonces = set()
    verifier.ensure_keys()

    result = verifier.verify_stored_value(signed)
    assert result.valid is True, f"In-memory path should still verify; got: {result.reason}"
