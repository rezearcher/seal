"""Unit tests for VPE federation — trust anchor registry, DNS/DID discovery,
cross-agent sign/verify, and audit trail.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from seal import (
    TrustAnchorRegistry,
    generate_key_pair,
    vpe_federated_sign,
    vpe_federated_verify,
    resolve_via_did,
    resolve_via_dns,
    resolve_trust_anchor,
    FederationAuditLog,
    FederatedSignResult,
    ResolutionResult,
)
from seal.audit import AuditLog


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def alice_keys():
    return generate_key_pair()


@pytest.fixture
def bob_keys():
    return generate_key_pair()


@pytest.fixture
def tmp_registry():
    """Provide a TrustAnchorRegistry backed by a temp file."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        f.write("{}\n")
        tmp_path = f.name
    registry = TrustAnchorRegistry(path=tmp_path)
    yield registry
    try:
        os.unlink(tmp_path)
    except OSError:
        pass


@pytest.fixture
def populated_registry(tmp_registry, alice_keys, bob_keys):
    """Registry with Alice and Bob pre-registered."""
    tmp_registry.register("agent:alice", alice_keys["public_key"])
    tmp_registry.register("agent:bob", bob_keys["public_key"])
    tmp_registry.save()
    return tmp_registry


# ---------------------------------------------------------------------------
# Trust anchor registry
# ---------------------------------------------------------------------------

class TestTrustAnchorRegistry:
    def test_empty_registry(self, tmp_registry):
        assert len(tmp_registry) == 0
        assert tmp_registry.lookup("agent:nobody") is None

    def test_register_and_lookup(self, tmp_registry):
        pk = bytes(range(32))
        tmp_registry.register("agent:test", pk)
        assert tmp_registry.lookup("agent:test") == pk
        assert "agent:test" in tmp_registry

    def test_register_updates_existing(self, tmp_registry):
        pk1 = bytes([0] * 32)
        pk2 = bytes([1] * 32)
        tmp_registry.register("agent:x", pk1)
        tmp_registry.register("agent:x", pk2)
        assert tmp_registry.lookup("agent:x") == pk2

    def test_remove(self, tmp_registry):
        pk = bytes(range(32))
        tmp_registry.register("agent:remove_me", pk)
        assert tmp_registry.remove("agent:remove_me") is True
        assert tmp_registry.lookup("agent:remove_me") is None
        assert tmp_registry.remove("agent:nonexistent") is False

    def test_persistence(self, tmp_registry, alice_keys):
        tmp_registry.register("agent:alice", alice_keys["public_key"])
        tmp_registry.save()
        # Load fresh registry from same file
        fresh = TrustAnchorRegistry(path=tmp_registry.path)
        assert fresh.lookup("agent:alice") == alice_keys["public_key"]

    def test_list_anchors(self, populated_registry, alice_keys, bob_keys):
        anchors = populated_registry.list_anchors()
        assert len(anchors) == 2
        assert anchors["agent:alice"] == alice_keys["public_key"].hex()
        assert anchors["agent:bob"] == bob_keys["public_key"].hex()

    def test_lookup_invalid_hex(self, tmp_registry):
        """Registry file with invalid hex should return None."""
        Path(tmp_registry.path).expanduser().write_text('{"agent:bad": "nothex"}')
        assert tmp_registry.lookup("agent:bad") is None

    def test_malformed_json(self, tmp_registry):
        """Malformed JSON loads as empty registry."""
        Path(tmp_registry.path).expanduser().write_text("not json")
        assert len(tmp_registry) == 0


# ---------------------------------------------------------------------------
# DID key resolution
# ---------------------------------------------------------------------------

class TestDIDResolution:
    def test_invalid_prefix(self):
        assert resolve_via_did("not-a-did") is None
        assert resolve_via_did("did:something") is None

    def test_empty_encoded(self):
        assert resolve_via_did("did:key:") is None

    def test_non_base58_prefix(self):
        assert resolve_via_did("did:key:x12345") is None  # 'x' is not base58 prefix

    def test_generated_key_roundtrip(self):
        """Generate an Ed25519 key and verify we can create a valid did:key for it.

        This validates the full round-trip: key -> multicodec -> base58 -> did:key -> parse.
        """
        keys = generate_key_pair()
        pk = keys["public_key"]

        # Build did:key manually: multicodec(0xed) + raw public key -> base58btc
        payload = bytes([0xed]) + pk

        # Encode to base58btc
        encoded = _base58btc_encode(payload)
        did_str = f"did:key:z{encoded}"

        resolved = resolve_via_did(did_str)
        assert resolved == pk, f"Round-trip failed: {resolved.hex()} != {pk.hex()}"

    def test_short_decoded_bytes(self):
        """Decoded data shorter than 33 bytes should return None."""
        s = _base58btc_encode(b"\xed")
        did = f"did:key:z{s}"
        assert resolve_via_did(did) is None

    def test_wrong_multicodec(self):
        """Non-Ed25519 multicodec prefix should return None."""
        # 0x01 is not Ed25519
        payload = bytes([0x01]) + bytes(range(32))
        s = _base58btc_encode(payload)
        did = f"did:key:z{s}"
        assert resolve_via_did(did) is None


# ---------------------------------------------------------------------------
# Helper: base58btc encode (for test round-trip)
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Base58 encode (Bitcoin-style) for test helper."""
    if not data:
        return ""

    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break

    num = int.from_bytes(data, byteorder="big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_BASE58_ALPHABET[rem])
    result.reverse()
    return "1" * leading_zeros + "".join(result)


# ---------------------------------------------------------------------------
# Trust anchor resolution chain
# ---------------------------------------------------------------------------

class TestResolutionChain:
    def test_registry_first(self, populated_registry, alice_keys):
        result = resolve_trust_anchor("agent:alice", registry=populated_registry)
        assert result.public_key == alice_keys["public_key"]
        assert result.source == "registry"

    def test_no_resolver_returns_none(self):
        result = resolve_trust_anchor("agent:unknown")
        assert result.public_key is None
        assert result.source == "none"

    def test_registry_unknown(self, populated_registry):
        result = resolve_trust_anchor("agent:unknown", registry=populated_registry)
        assert result.public_key is None
        assert result.source == "none"

    def test_did_fallback(self, alice_keys):
        """DID resolution works when registry fails."""
        payload = bytes([0xed]) + alice_keys["public_key"]
        did = f"did:key:z{_base58btc_encode(payload)}"

        result = resolve_trust_anchor("agent:alice", did_str=did)
        assert result.public_key == alice_keys["public_key"]
        assert result.source == "did"


# ---------------------------------------------------------------------------
# Federated signing
# ---------------------------------------------------------------------------

class TestFederatedSign:
    def test_sign_returns_envelope(self, alice_keys):
        result = vpe_federated_sign(
            prompt="list files",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        assert isinstance(result, FederatedSignResult)
        assert result.envelope != ""
        assert result.error == ""
        assert result.nonce != ""

        parsed = json.loads(result.envelope)
        assert parsed["issuer"] == "agent:alice"
        assert parsed["audience"] == "agent:bob"
        assert parsed["prompt"] == "list files"

    def test_sign_with_audit(self, alice_keys, tmp_registry):
        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_sign_audit.jsonl")))
        result = vpe_federated_sign(
            prompt="secret mission",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
            audit_log=audit,
        )
        assert result.error == ""
        assert result.nonce != ""

        # Verify audit entry was written
        entries = audit.audit.query()
        assert len(entries) >= 1
        assert any("vpe:federation:issuance" in e.get("label", "") for e in entries)


# ---------------------------------------------------------------------------
# Federated verification
# ---------------------------------------------------------------------------

class TestFederatedVerify:
    def test_verify_from_registry(self, populated_registry, alice_keys, bob_keys):
        # Alice signs for Bob
        signed = vpe_federated_sign(
            prompt="process data",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        # Bob verifies using registry
        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
        )
        assert result["valid"] is True
        assert result["source"] == "registry"

    def test_verify_fails_wrong_key(self, populated_registry, alice_keys, bob_keys):
        signed = vpe_federated_sign(
            prompt="process data",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        # Register Alice with Bob's key (wrong key)
        populated_registry.register("agent:alice", bob_keys["public_key"])
        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
        )
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_verify_unknown_issuer(self, populated_registry, alice_keys):
        signed = vpe_federated_sign(
            prompt="test",
            issuer="agent:eve",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
        )
        assert result["valid"] is False
        assert "unknown_issuer" in result["reason"]

    def test_verify_with_did(self, alice_keys, bob_keys):
        # Alice signs for Bob
        signed = vpe_federated_sign(
            prompt="cross-chain op",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        # Resolve via DID
        payload = bytes([0xed]) + alice_keys["public_key"]
        did = f"did:key:z{_base58btc_encode(payload)}"

        result = vpe_federated_verify(
            signed.envelope,
            did_str=did,
        )
        assert result["valid"] is True
        assert result["source"] == "did"

    def test_verify_with_audit_log(self, populated_registry, alice_keys, tmp_registry):
        signed = vpe_federated_sign(
            prompt="audited operation",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_verify_audit.jsonl")))
        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
            audit_log=audit,
        )
        assert result["valid"] is True

        # Check audit entries
        entries = audit.audit.query()
        assert len(entries) >= 1
        assert any("vpe:federation:verification" in e.get("label", "") for e in entries)

    def test_verify_invalid_json(self):
        result = vpe_federated_verify("not json")
        assert result["valid"] is False
        assert "invalid_json" in result["reason"]

    def test_verify_tampered_envelope(self, populated_registry, alice_keys):
        signed = vpe_federated_sign(
            prompt="original",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )

        # Tamper with the prompt
        parsed = json.loads(signed.envelope)
        parsed["prompt"] = "TAMPERED"
        tampered = json.dumps(parsed, separators=(",", ":"))

        result = vpe_federated_verify(
            tampered,
            registry=populated_registry,
        )
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Cross-agent audit trail
# ---------------------------------------------------------------------------

class TestFederationAuditLog:
    def test_log_issuance(self, tmp_registry):
        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_audit.jsonl")))
        audit.log_issuance(
            issuer="agent:alice",
            audience="agent:bob",
            prompt_summary="do the thing",
            envelope_nonce="abc123",
        )
        entries = audit.audit.query()
        assert len(entries) >= 1

        # Find the cross-audit entry
        cross = [e for e in entries if e.get("event") == "vpe_cross_audit"]
        assert len(cross) >= 1
        assert cross[0]["issuer"] == "agent:alice"
        assert cross[0]["audience"] == "agent:bob"
        assert cross[0]["envelope_nonce"] == "abc123"

    def test_log_verification_granted(self, tmp_registry):
        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_audit2.jsonl")))
        audit.log_verification(
            issuer="agent:alice",
            verifier="agent:bob",
            envelope_nonce="abc123",
            result="granted",
        )
        cross = [e for e in audit.audit.query() if e.get("event") == "vpe_cross_audit"]
        assert len(cross) >= 1
        assert cross[0]["result"] == "granted"

    def test_log_verification_denied(self, tmp_registry):
        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_audit3.jsonl")))
        audit.log_verification(
            issuer="agent:eve",
            verifier="agent:bob",
            envelope_nonce="def456",
            result="denied",
            reason="unknown_issuer",
        )
        cross = [e for e in audit.audit.query() if e.get("event") == "vpe_cross_audit"]
        assert len(cross) >= 1
        assert cross[0]["result"] == "denied"
        assert "unknown_issuer" in cross[0].get("reason", "")

    def test_full_roundtrip_with_audit(self, populated_registry, alice_keys, bob_keys, tmp_registry):
        """Full cross-agent flow: Alice signs, Bob verifies, both audited."""
        audit = FederationAuditLog(audit=AuditLog(path=tmp_registry.path.replace(".json", "_audit_full.jsonl")))

        # Alice signs
        signed = vpe_federated_sign(
            prompt="transfer: 100 tokens to vault",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
            audit_log=audit,
        )
        assert signed.error == ""

        # Bob verifies
        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
            audit_log=audit,
        )
        assert result["valid"] is True

        # Check both issuance and verification appear in audit
        entries = audit.audit.query()
        issuance_events = [
            e for e in entries
            if e.get("event") == "vpe_cross_audit"
            and e.get("event_type") == "issuance"
        ]
        verification_events = [
            e for e in entries
            if e.get("event") == "vpe_cross_audit"
            and e.get("event_type") == "verification"
        ]
        assert len(issuance_events) >= 1
        assert len(verification_events) >= 1
        assert issuance_events[0]["issuer"] == "agent:alice"
        assert verification_events[0]["issuer"] == "agent:alice"


# ---------------------------------------------------------------------------
# DNS resolution (unit-testable parts)
# ---------------------------------------------------------------------------

class TestDNSResolutionParsing:
    def test_resolve_via_dns_invalid_domain(self):
        """Should return None for non-existent domains (no crash)."""
        result = resolve_via_dns("nonexistent-domain-xyz123.test")
        assert result is None or isinstance(result, bytes)
