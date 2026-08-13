"""Unit tests for seal/integration/division_vpe_signer.py (t_7bb5b728).

Covers the DivisionVPESigner public API and its failure/fallback branches:
  - mode handling (sign / verify / bypass, invalid mode rejection)
  - ensure_keys success + unavailable/exception fallbacks
  - wrap_for_storage: happy path, serialization failure, no keypair,
    sign-crypto failure, bypass passthrough
  - verify_stored_value: envelope path, nonce replay, unsigned values,
    missing signature, tampered envelope, basic verification fallback,
    no public key
  - verify_batch, is_signed, extract_value
  - P6.4b audit trail integration (set_audit / set_audit_from_func /
    _record_audit including the degraded-hash branch)
  - seal/store/audit module-unavailable branches (via module-flag
    monkeypatching, since the imports succeed in this environment)

The module under test is read-only; all unavailable-branch behavior is
exercised by monkeypatching the module-level availability flags.
"""

from __future__ import annotations

import pytest

import seal.integration.division_vpe_signer as signer_mod
from seal.integration.division_vpe_signer import DivisionVPESigner
from seal.store import NonceStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair_dir(tmp_path):
    """Temporary directory for VPE keypair."""
    return str(tmp_path / "vpe-keys")


@pytest.fixture
def nonce_db(tmp_path):
    """Path to a temporary NonceStore database."""
    return str(tmp_path / "nonces.db")


def _make_signer(key_dir: str, nonce_db: str, mode: str = "sign") -> DivisionVPESigner:
    """Create a signer backed by an explicit NonceStore at *nonce_db*."""
    signer = DivisionVPESigner(
        key_dir=key_dir,
        mode=mode,
        nonce_store=NonceStore(db_path=nonce_db),
    )
    signer.ensure_keys()
    return signer


class _FakeAudit:
    """Records calls to ``record`` without touching Division or disk."""

    def __init__(self):
        self.calls: list[dict] = []

    def record(self, **kwargs) -> str:
        self.calls.append(kwargs)
        return "episode-1"


# ---------------------------------------------------------------------------
# Mode handling
# ---------------------------------------------------------------------------


def test_bypass_mode_passthrough(keypair_dir):
    """In bypass mode wrap_for_storage returns the value unchanged."""
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="bypass")
    value = {"data": "raw"}
    assert signer.wrap_for_storage(value, domain="test", agent="hermes") is value


def test_set_mode_valid_and_invalid(keypair_dir):
    """set_mode accepts sign/verify/bypass and rejects anything else."""
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="bypass")
    with pytest.raises(ValueError, match="Invalid mode"):
        signer.set_mode("nonsense")
    for mode in ("sign", "verify", "bypass"):
        signer.set_mode(mode)
        assert signer._mode == mode


# ---------------------------------------------------------------------------
# ensure_keys
# ---------------------------------------------------------------------------


def test_ensure_keys_creates_keypair(keypair_dir):
    """ensure_keys generates a keypair on first use."""
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")
    assert signer.ensure_keys() is True
    assert signer._private_key is not None
    assert signer._public_key is not None


def test_ensure_keys_seal_unavailable(keypair_dir, monkeypatch):
    """ensure_keys returns False when the seal module is unavailable."""
    monkeypatch.setattr(signer_mod, "_SEAL_AVAILABLE", False)
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")
    assert signer.ensure_keys() is False
    assert signer._private_key is None


def test_ensure_keys_exception_falls_back(keypair_dir, monkeypatch):
    """ensure_keys returns False when keypair loading raises."""

    def _boom(*args, **kwargs):
        raise RuntimeError("disk failure")

    monkeypatch.setattr(signer_mod, "load_or_generate_keypair", _boom)
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")
    assert signer.ensure_keys() is False


# ---------------------------------------------------------------------------
# wrap_for_storage
# ---------------------------------------------------------------------------


def test_wrap_for_storage_returns_signed_wrapper(keypair_dir, nonce_db):
    """A signed wrapper carries the marker, value, signature, and envelope."""
    signer = _make_signer(keypair_dir, nonce_db)
    value = {"discovery": "RCE in /api/v1", "score": 9.5}
    wrapped = signer.wrap_for_storage(value, domain="recon", agent="hermes")

    assert signer_mod._VPE_SIGNED_MARKER in wrapped
    assert wrapped[signer_mod._VPE_SIGNED_MARKER] is True
    assert wrapped["value"] == value
    assert wrapped["signature"]
    assert wrapped["signed_by"] == "agent:hermes"
    assert wrapped["nonce"]
    assert wrapped["public_key"] == signer._public_key.hex()
    assert "_original_envelope" in wrapped


def test_wrap_for_storage_empty_domain_agent_defaults(keypair_dir, nonce_db):
    """Empty domain/agent fall back to the configured agent name."""
    signer = _make_signer(keypair_dir, nonce_db, mode="sign")
    wrapped = signer.wrap_for_storage({"x": 1}, domain="", agent="")
    assert wrapped[signer_mod._VPE_SIGNED_MARKER] is True
    assert wrapped["signed_by"] == f"agent:{signer._agent_name}"


def test_wrap_for_storage_no_keypair_returns_value(keypair_dir, nonce_db, monkeypatch):
    """When no keypair exists and key loading fails, the value is returned unsigned."""

    def _no_keys(*args, **kwargs):
        raise RuntimeError("no keys")

    monkeypatch.setattr(signer_mod, "load_or_generate_keypair", _no_keys)
    signer = DivisionVPESigner(
        key_dir=keypair_dir,
        mode="sign",
        nonce_store=NonceStore(db_path=nonce_db),
    )
    value = {"a": 1}
    assert signer.wrap_for_storage(value, domain="test", agent="hermes") is value


def test_wrap_for_storage_unserializable_value(keypair_dir, nonce_db):
    """Values that cannot be JSON-serialized fall back to unsigned."""
    signer = _make_signer(keypair_dir, nonce_db)

    # A self-referential structure defeats json.dumps even with default=str.
    cyclic: list = []
    cyclic.append(cyclic)
    value = {"obj": cyclic}

    assert signer.wrap_for_storage(value, domain="test", agent="hermes") is value


def test_wrap_for_storage_signing_failure_returns_value(keypair_dir, nonce_db, monkeypatch):
    """A vpe_sign exception falls back to the unsigned value."""

    def _boom(*args, **kwargs):
        raise RuntimeError("crypto backend down")

    monkeypatch.setattr(signer_mod, "vpe_sign", _boom)
    signer = _make_signer(keypair_dir, nonce_db)
    value = {"a": 1}
    assert signer.wrap_for_storage(value, domain="test", agent="hermes") is value


# ---------------------------------------------------------------------------
# verify_stored_value — envelope path
# ---------------------------------------------------------------------------


def test_verify_valid_signed_value(keypair_dir, nonce_db):
    """A freshly signed value verifies as authentic."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": "authentic"}, domain="test", agent="hermes")

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier.verify_stored_value(wrapped)
    assert result.valid is True, result.reason


def test_verify_tampered_envelope_rejected(keypair_dir, nonce_db):
    """Tampering with the embedded envelope invalidates the signature."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": "original"}, domain="test", agent="hermes")
    wrapped["_original_envelope"]["prompt"] = wrapped["_original_envelope"]["prompt"].replace("original", "MUTATED")

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier.verify_stored_value(wrapped)
    assert result.valid is False


def test_verify_replay_detected(keypair_dir, nonce_db):
    """Verifying the same signed value twice triggers replay protection."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": "once"}, domain="test", agent="hermes")

    verifier_a = _make_signer(keypair_dir, nonce_db, mode="verify")
    assert verifier_a.verify_stored_value(wrapped).valid is True

    verifier_b = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier_b.verify_stored_value(wrapped)
    assert result.valid is False
    assert "replay" in result.reason.lower()


def test_verify_unsigned_value_accepted(keypair_dir, nonce_db):
    """Unsigned values pass through as valid with a note."""
    signer = _make_signer(keypair_dir, nonce_db, mode="verify")
    for value in ({"plain": "dict"}, "string", 42, None, [1, 2]):
        result = signer.verify_stored_value(value)
        assert result.valid is True
        assert "unsigned" in result.reason.lower()


def test_verify_missing_signature_rejected(keypair_dir, nonce_db):
    """A signed wrapper without a signature field is rejected."""
    signer = _make_signer(keypair_dir, nonce_db, mode="verify")
    fake = {signer_mod._VPE_SIGNED_MARKER: True, "value": {"x": 1}}
    result = signer.verify_stored_value(fake)
    assert result.valid is False
    assert "signature" in result.reason.lower()


def test_verify_envelope_error_falls_through_to_basic(keypair_dir, nonce_db):
    """A malformed envelope falls through to the basic signature check."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": "x"}, domain="test", agent="hermes")
    wrapped["_original_envelope"] = "not-a-dict"  # .get() raises AttributeError

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier.verify_stored_value(wrapped)
    # Basic check executes; a plain string envelope cannot yield a valid signature.
    assert result is not None
    assert result.valid is False


# ---------------------------------------------------------------------------
# verify_stored_value — basic path + edge cases
# ---------------------------------------------------------------------------


def test_verify_basic_path_with_public_key(keypair_dir, nonce_db):
    """Basic verification runs against a reconstructed envelope when the
    original envelope is absent but a public key is available."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": "x"}, domain="test", agent="hermes")
    # Remove the embedded envelope to force the basic path. The reconstructed
    # envelope differs from the signed prompt, so verification fails — but the
    # path itself must execute without raising.
    del wrapped["_original_envelope"]

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier.verify_stored_value(wrapped)
    assert result.valid is False


def test_verify_basic_path_bad_public_key_hex(keypair_dir, nonce_db):
    """A non-hex public key in a signed wrapper yields a clean failure."""
    fake = {
        signer_mod._VPE_SIGNED_MARKER: True,
        "signature": "deadbeef" * 8,
        "public_key": "not-hex!!!",
        "signed_by": "agent:hermes",
        "signed_at": 0,
        "nonce": "",
    }
    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    result = verifier.verify_stored_value(fake)
    assert result.valid is False
    assert "verification failed" in result.reason.lower()


def test_verify_no_public_key_available(keypair_dir, nonce_db):
    """Without an embedded public key and no loaded keypair, verification is impossible."""
    fake = {
        signer_mod._VPE_SIGNED_MARKER: True,
        "signature": "deadbeef" * 8,
        # no public_key, no _original_envelope
    }
    signer = DivisionVPESigner(
        key_dir=keypair_dir,
        mode="verify",
        nonce_store=NonceStore(db_path=nonce_db),
    )
    # Keys deliberately not loaded.
    result = signer.verify_stored_value(fake)
    assert result.valid is False
    assert "no public key" in result.reason.lower()


def test_verify_seal_unavailable(keypair_dir, monkeypatch):
    """When the seal module is unavailable, verification is a soft pass."""
    monkeypatch.setattr(signer_mod, "_SEAL_AVAILABLE", False)
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="verify")
    result = signer.verify_stored_value({"anything": 1})
    assert result.valid is True
    assert "not available" in result.reason.lower()


def test_verify_with_in_memory_nonce_fallback(keypair_dir, monkeypatch):
    """Without a persistent store, seen nonces are tracked in memory."""
    monkeypatch.setattr(signer_mod, "_NONCE_STORE_AVAILABLE", False)
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign", nonce_store=None)
    signer.ensure_keys()
    assert signer._nonce_store is None
    assert isinstance(signer._seen_nonces, set)

    wrapped = signer.wrap_for_storage({"data": "mem"}, domain="test", agent="hermes")

    verifier = DivisionVPESigner(key_dir=keypair_dir, mode="verify", nonce_store=None)
    verifier.ensure_keys()
    assert verifier.verify_stored_value(wrapped).valid is True
    # Replay still detected within the process via the in-memory set.
    assert verifier.verify_stored_value(wrapped).valid is False


# ---------------------------------------------------------------------------
# Batch / utility methods
# ---------------------------------------------------------------------------


def test_verify_batch_mixed_values(keypair_dir, nonce_db):
    """verify_batch processes signed and unsigned values."""
    signer = _make_signer(keypair_dir, nonce_db)
    signed = signer.wrap_for_storage({"id": 1}, domain="test", agent="hermes")
    values = [signed, {"id": 2, "raw": True}, "plain"]

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    results = verifier.verify_batch(values)
    assert len(results) == 3
    assert results[0][1].valid is True
    assert results[1][1].valid is True
    assert results[2][1].valid is True


def test_verify_batch_empty(keypair_dir):
    """verify_batch([]) returns an empty list."""
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="verify")
    assert signer.verify_batch([]) == []


def test_is_signed(keypair_dir, nonce_db):
    """is_signed distinguishes wrapped values from everything else."""
    signer = _make_signer(keypair_dir, nonce_db)
    signed = signer.wrap_for_storage({"a": 1}, domain="test", agent="hermes")
    assert signer.is_signed(signed) is True
    for not_signed in ({"a": 1}, "str", 3, None, [1], {"__vpe_signed__": "not-bool"}):
        assert signer.is_signed(not_signed) is False


def test_extract_value(keypair_dir, nonce_db):
    """extract_value unwraps signed values and passes others through."""
    signer = _make_signer(keypair_dir, nonce_db)
    original = {"deep": {"nested": [1, 2, 3]}}
    signed = signer.wrap_for_storage(original, domain="test", agent="hermes")
    assert signer.extract_value(signed) == original
    assert signer.extract_value(original) is original


# ---------------------------------------------------------------------------
# Audit trail integration (P6.4b)
# ---------------------------------------------------------------------------


def test_set_audit_records_sign_operations(keypair_dir, nonce_db):
    """With an audit attached, wrap_for_storage records a sign episode."""
    signer = _make_signer(keypair_dir, nonce_db)
    audit = _FakeAudit()
    signer.set_audit(audit)
    assert signer._audit is audit

    wrapped = signer.wrap_for_storage({"data": 1}, domain="test", agent="hermes")
    assert audit.calls, "sign operation should be recorded"
    call = audit.calls[0]
    assert call["result"] == "valid"
    assert call["reason"] == "operation=sign"
    assert call["tool_name"] == "division_vpe_signer:sign"
    assert call["issuer"] == "agent:hermes"
    assert len(call["envelope_hash"]) == 64  # sha256 hex
    assert wrapped[signer_mod._VPE_SIGNED_MARKER] is True


def test_set_audit_records_verify_operations(keypair_dir, nonce_db):
    """With an audit attached, verify_stored_value records a verify episode."""
    signer = _make_signer(keypair_dir, nonce_db)
    wrapped = signer.wrap_for_storage({"data": 1}, domain="test", agent="hermes")

    verifier = _make_signer(keypair_dir, nonce_db, mode="verify")
    audit = _FakeAudit()
    verifier.set_audit(audit)
    result = verifier.verify_stored_value(wrapped)
    assert result.valid is True
    assert audit.calls, "verify operation should be recorded"
    call = audit.calls[0]
    assert call["result"] == "valid"
    assert call["tool_name"] == "division_vpe_signer:verify"


def test_set_audit_none_disables_recording(keypair_dir, nonce_db):
    """set_audit(None) disables audit recording."""
    signer = _make_signer(keypair_dir, nonce_db)
    signer.set_audit(None)
    assert signer._audit is None
    wrapped = signer.wrap_for_storage({"data": 1}, domain="test", agent="hermes")
    assert wrapped[signer_mod._VPE_SIGNED_MARKER] is True  # still signs, just no audit


def test_record_audit_degraded_hash(keypair_dir, monkeypatch):
    """Un-canonicalizable envelopes produce a degraded hash + reason."""
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")
    audit = _FakeAudit()
    signer.set_audit(audit)

    # An envelope whose scope contains a non-serializable value defeats
    # canonical JSON serialization.
    bad_envelope = {
        "issuer": "agent:hermes",
        "nonce": "nonce-1234567890abcdef",
        "scope": {"allowed_tools": {"set", "of", "strings"}},
    }
    signer._record_audit(bad_envelope, False, "verify")

    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["envelope_hash"].startswith("degraded:")
    assert call["envelope_hash"] == "degraded:nonce-1234567890"
    assert call["result"] == "invalid"
    assert call["reason"] == "hash_computation_failed"
    assert call["tool_name"] == "division_vpe_signer:verify"


def test_set_audit_from_func_attaches_audit(keypair_dir, monkeypatch):
    """set_audit_from_func builds a DivisionVPEAudit from a remember function."""

    class _FakeAuditCls:
        def __init__(self, conversation_id, remember_func):
            self.conversation_id = conversation_id
            self.remember_func = remember_func

    monkeypatch.setattr(signer_mod, "DivisionVPEAudit", _FakeAuditCls)
    remember = lambda **kwargs: {"ok": True}  # noqa: E731 — mock Division write

    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")
    signer.set_audit_from_func(remember, conversation_id="audit-conv")

    assert signer._audit is not None
    assert signer._audit.conversation_id == "audit-conv"
    assert signer._audit.remember_func is remember


def test_set_audit_from_func_unavailable(keypair_dir, monkeypatch, caplog):
    """When the audit module is unavailable, set_audit_from_func warns and no-ops."""
    monkeypatch.setattr(signer_mod, "_AUDIT_AVAILABLE", False)
    signer = DivisionVPESigner(key_dir=keypair_dir, mode="sign")

    with caplog.at_level("WARNING"):
        signer.set_audit_from_func(lambda **kwargs: None)

    assert signer._audit is None
    assert any("audit module not available" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Module-level import fallbacks
# ---------------------------------------------------------------------------


def test_import_fallbacks_when_seal_modules_unavailable(monkeypatch):
    """Module-level ImportError branches set the availability flags to False.

    The module tries to import seal.vpe / seal.store / division_vpe_audit at
    import time. When those imports fail (e.g. a partial install), it must
    degrade gracefully: flags flip to False and the fallback symbols become
    None. We simulate the failure by blocking the imports and reloading the
    module, then restore the real module state.
    """
    import importlib
    import sys

    blocked = ("seal.vpe", "seal.store", "seal.integration.division_vpe_audit")

    class _Blocker:
        def find_spec(self, fullname, path=None, target=None):
            if fullname in blocked:
                raise ImportError(f"blocked import: {fullname}")
            return None

    saved = {name: sys.modules.get(name) for name in blocked}
    for name in blocked:
        sys.modules.pop(name, None)

    blocker = _Blocker()
    sys.meta_path.insert(0, blocker)
    try:
        importlib.reload(signer_mod)
        assert signer_mod._SEAL_AVAILABLE is False
        assert signer_mod._NONCE_STORE_AVAILABLE is False
        assert signer_mod._AUDIT_AVAILABLE is False
        assert signer_mod.VPEResult is None
        assert signer_mod.NonceStore is None
    finally:
        sys.meta_path.remove(blocker)
        for name, mod in saved.items():
            if mod is not None:
                sys.modules[name] = mod
        importlib.reload(signer_mod)  # restore the fully-imported module state
        assert signer_mod._SEAL_AVAILABLE is True
