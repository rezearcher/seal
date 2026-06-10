"""Tests for seal.memory — axis-3 memory-trust API."""

from __future__ import annotations

import json

import pytest

from seal.core import generate_key_pair
from seal.memory import sign_memory, verify_memory, verify_on_recall
from seal.store import NonceStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def trusted_keys():
    return generate_key_pair()


@pytest.fixture(scope="module")
def attacker_keys():
    return generate_key_pair()


@pytest.fixture()
def tmp_nonce_store(tmp_path):
    db = tmp_path / "nonces.db"
    store = NonceStore(db_path=str(db))
    yield store
    store.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(
    content, keys, *, writer="agent:writer", namespace="ns:default", nonce=None, ttl=0, scope=None
):
    return sign_memory(
        content,
        writer=writer,
        namespace=namespace,
        scope=scope,
        ttl_seconds=ttl,
        private_key=keys["private_key"],
        nonce=nonce,
    )


def _verify(record, keys, *, trusted_writers=None, expected_namespace=None, nonce_store=None):
    return verify_memory(
        record,
        public_key=keys["public_key"],
        trusted_writers=trusted_writers,
        expected_namespace=expected_namespace,
        nonce_store=nonce_store,
    )


# ---------------------------------------------------------------------------
# 1. Roundtrip — sign then verify, content/writer/namespace preserved
# ---------------------------------------------------------------------------


def test_roundtrip(trusted_keys):
    content = "RCE found at /api/exec"
    writer = "agent:hermes"
    namespace = "ns:recon"

    record = sign_memory(
        content,
        writer=writer,
        namespace=namespace,
        private_key=trusted_keys["private_key"],
    )
    result = verify_memory(record, public_key=trusted_keys["public_key"])

    assert result["valid"] is True
    assert result["reason"] == "ok"
    assert result["content"] == content
    assert result["writer"] == writer
    assert result["namespace"] == namespace


# ---------------------------------------------------------------------------
# 2. Tampered content → signature_mismatch
# ---------------------------------------------------------------------------


def test_tampered_content(trusted_keys):
    record = _sign("original content", trusted_keys)
    envelope = json.loads(record)
    envelope["prompt"] = "injected payload"
    tampered = json.dumps(envelope)

    result = _verify(tampered, trusted_keys)
    assert result["valid"] is False
    assert result["reason"] == "signature_mismatch"
    assert result["content"] is None


# ---------------------------------------------------------------------------
# 3a. Untrusted writer — attacker key (signature_mismatch)
# ---------------------------------------------------------------------------


def test_attacker_key_rejected(trusted_keys, attacker_keys):
    record = _sign("legit content", attacker_keys, writer="agent:attacker")
    result = verify_memory(record, public_key=trusted_keys["public_key"])

    assert result["valid"] is False
    assert result["reason"] == "signature_mismatch"


# ---------------------------------------------------------------------------
# 3b. Untrusted writer — valid signature but writer not on allowlist
# ---------------------------------------------------------------------------


def test_untrusted_writer_allowlist(trusted_keys):
    record = _sign("content", trusted_keys, writer="agent:rogue")
    result = _verify(
        record,
        trusted_keys,
        trusted_writers={"agent:approved"},
    )

    assert result["valid"] is False
    assert result["reason"] == "untrusted_writer"


# ---------------------------------------------------------------------------
# 4. Cross-namespace contamination → cross_namespace
# ---------------------------------------------------------------------------


def test_cross_namespace(trusted_keys):
    record = _sign("content", trusted_keys, namespace="ns:alpha")
    result = _verify(record, trusted_keys, expected_namespace="ns:beta")

    assert result["valid"] is False
    assert result["reason"] == "cross_namespace"


# ---------------------------------------------------------------------------
# 5. Unsigned / missing signature → missing_signature
# ---------------------------------------------------------------------------


def test_unsigned_no_signature(trusted_keys):
    record = _sign("content", trusted_keys)
    envelope = json.loads(record)
    envelope.pop("signature", None)
    unsigned = json.dumps(envelope)

    result = _verify(unsigned, trusted_keys)
    assert result["valid"] is False
    assert result["reason"] == "missing_signature"


def test_unsigned_empty_string(trusted_keys):
    result = _verify("not-json-at-all", trusted_keys)
    assert result["valid"] is False
    assert result["reason"] == "no-memory-envelope"


def test_unsigned_no_vpe_version(trusted_keys):
    result = _verify(json.dumps({"some": "dict"}), trusted_keys)
    assert result["valid"] is False
    assert result["reason"] == "no-memory-envelope"


# ---------------------------------------------------------------------------
# 6. Extra unsigned field → unsigned_field:<key>
# ---------------------------------------------------------------------------


def test_extra_unsigned_field(trusted_keys):
    record = _sign("content", trusted_keys)
    envelope = json.loads(record)
    envelope["injected_scope"] = {"malicious": True}
    poisoned = json.dumps(envelope)

    result = _verify(poisoned, trusted_keys)
    assert result["valid"] is False
    assert result["reason"] == "unsigned_field:injected_scope"


# ---------------------------------------------------------------------------
# 7. Nonce replay → nonce_reused
# ---------------------------------------------------------------------------


def test_nonce_replay(trusted_keys, tmp_nonce_store):
    fixed_nonce = "deadbeefcafe0001"
    # ttl > 0 so nonce store is consulted
    record = _sign("content", trusted_keys, nonce=fixed_nonce, ttl=3600)

    first = verify_memory(
        record,
        public_key=trusted_keys["public_key"],
        nonce_store=tmp_nonce_store,
    )
    assert first["valid"] is True

    second = verify_memory(
        record,
        public_key=trusted_keys["public_key"],
        nonce_store=tmp_nonce_store,
    )
    assert second["valid"] is False
    assert second["reason"] == "nonce_reused"


# ---------------------------------------------------------------------------
# 8. verify_on_recall — mixed batch partitioned correctly
# ---------------------------------------------------------------------------


def test_verify_on_recall_mixed(trusted_keys, attacker_keys):
    good1 = _sign("authentic record 1", trusted_keys, writer="agent:bob", namespace="ns:prod")
    good2 = _sign("authentic record 2", trusted_keys, writer="agent:alice", namespace="ns:prod")

    # Poisoned: signed by attacker key
    poisoned_sig = _sign("injected record", attacker_keys, writer="agent:evil", namespace="ns:prod")

    # Poisoned: valid sig but wrong namespace
    wrong_ns = _sign("wrong ns record", trusted_keys, writer="agent:bob", namespace="ns:staging")

    # Poisoned: tampered content
    env = json.loads(_sign("will be tampered", trusted_keys))
    env["prompt"] = "tampered"
    tampered = json.dumps(env)

    records = [good1, good2, poisoned_sig, wrong_ns, tampered]

    result = verify_on_recall(
        records,
        public_key=trusted_keys["public_key"],
        trusted_writers={"agent:bob", "agent:alice"},
        expected_namespace="ns:prod",
    )

    assert len(result["accepted"]) == 2
    assert len(result["rejected"]) == 3

    accepted_contents = {r["content"] for r in result["accepted"]}
    assert "authentic record 1" in accepted_contents
    assert "authentic record 2" in accepted_contents

    rejected_reasons = {r["reason"] for r in result["rejected"]}
    assert "signature_mismatch" in rejected_reasons
    assert "cross_namespace" in rejected_reasons

    rejected_indices = [r["record_index"] for r in result["rejected"]]
    # wrong_ns is index 3, tampered is index 4, poisoned_sig is index 2
    assert sorted(rejected_indices) == [2, 3, 4]


# ---------------------------------------------------------------------------
# 9. verify_on_recall — all accepted
# ---------------------------------------------------------------------------


def test_verify_on_recall_all_accepted(trusted_keys):
    records = [
        _sign(f"record {i}", trusted_keys, writer="agent:w", namespace="ns:x")
        for i in range(4)
    ]
    result = verify_on_recall(records, public_key=trusted_keys["public_key"])
    assert len(result["accepted"]) == 4
    assert result["rejected"] == []


# ---------------------------------------------------------------------------
# 10. verify_on_recall — all rejected
# ---------------------------------------------------------------------------


def test_verify_on_recall_all_rejected(trusted_keys, attacker_keys):
    records = [_sign("bad", attacker_keys) for _ in range(3)]
    result = verify_on_recall(records, public_key=trusted_keys["public_key"])
    assert result["accepted"] == []
    assert len(result["rejected"]) == 3


# ---------------------------------------------------------------------------
# 11. Verdict determinism — same nonce + same content = same verdict
# ---------------------------------------------------------------------------


def test_verdict_determinism(trusted_keys):
    content = "stable content"
    nonce = "aabbccdd11223344"

    r1 = _sign(content, trusted_keys, nonce=nonce)
    r2 = _sign(content, trusted_keys, nonce=nonce)

    v1 = _verify(r1, trusted_keys)
    v2 = _verify(r2, trusted_keys)

    assert v1["valid"] is True
    assert v2["valid"] is True
    assert v1["content"] == v2["content"] == content


# ---------------------------------------------------------------------------
# 12. Default namespace propagates correctly
# ---------------------------------------------------------------------------


def test_default_namespace(trusted_keys):
    record = sign_memory("data", writer="agent:x", private_key=trusted_keys["private_key"])
    result = verify_memory(record, public_key=trusted_keys["public_key"])
    assert result["valid"] is True
    assert result["namespace"] == "default"


# ---------------------------------------------------------------------------
# 13. trusted_writers + expected_namespace both pass when correct
# ---------------------------------------------------------------------------


def test_both_checks_pass(trusted_keys):
    record = _sign("data", trusted_keys, writer="agent:approved", namespace="ns:right")
    result = _verify(
        record,
        trusted_keys,
        trusted_writers={"agent:approved"},
        expected_namespace="ns:right",
    )
    assert result["valid"] is True
    assert result["writer"] == "agent:approved"
    assert result["namespace"] == "ns:right"
