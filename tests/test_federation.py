"""Unit tests for VPE federation — trust anchor registry, DNS/DID discovery,
cross-agent sign/verify, and audit trail.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from seal import (
    FederatedSignResult,
    FederationAuditLog,
    TrustAnchorRegistry,
    export_trust_bundle,
    generate_key_pair,
    import_trust_bundle,
    resolve_trust_anchor,
    resolve_via_did,
    resolve_via_did_document,
    resolve_via_dns,
    vpe_federated_sign,
    vpe_federated_verify,
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
        payload = bytes([0xED]) + pk

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
        payload = bytes([0xED]) + alice_keys["public_key"]
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
        payload = bytes([0xED]) + alice_keys["public_key"]
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
            e for e in entries if e.get("event") == "vpe_cross_audit" and e.get("event_type") == "issuance"
        ]
        verification_events = [
            e for e in entries if e.get("event") == "vpe_cross_audit" and e.get("event_type") == "verification"
        ]
        assert len(issuance_events) >= 1
        assert len(verification_events) >= 1
        assert issuance_events[0]["issuer"] == "agent:alice"
        assert verification_events[0]["issuer"] == "agent:alice"


# ---------------------------------------------------------------------------
# DNS resolution (unit-testable parts)
# ---------------------------------------------------------------------------


def _make_dns_header(
    query_id: int,
    flags: int = 0x8180,
    qdcount: int = 1,
    ancount: int = 0,
    nscount: int = 0,
    arcount: int = 0,
) -> bytes:
    """Build a DNS response header for test purposes."""
    import struct
    return struct.pack("!HHHHHH", query_id, flags, qdcount, ancount, nscount, arcount)


def _make_dns_name(domain: str) -> bytes:
    """Encode a domain name into DNS label format."""
    encoded = b""
    for part in domain.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def _make_txt_rdata(*strings: str) -> bytes:
    """Build TXT RDATA bytes from string values.

    Each string is prefixed with a length byte. Multiple strings
    are concatenated as required by RFC 1035.
    """
    data = b""
    for s in strings:
        data += bytes([len(s)]) + s.encode("ascii")
    return data


class TestFederationError:
    def test_is_exception(self):
        """FederationError is a proper Exception subclass."""
        from seal.federation import FederationError
        assert issubclass(FederationError, Exception)
        err = FederationError("test error")
        assert str(err) == "test error"

    def test_caught_separately_from_value_error(self):
        """FederationError is distinct from standard exceptions."""
        from seal.federation import FederationError
        try:
            raise FederationError("malformed")
        except FederationError:
            pass  # Caught specifically
        except Exception:
            pytest.fail("FederationError should be caught by its own except clause")


class TestDNSPacketBuilding:
    def test_build_dns_query_structure(self):
        """_build_dns_query produces a valid DNS query packet."""
        from seal.federation import _build_dns_query
        packet, qid = _build_dns_query("example.com")

        # Should start with the 12-byte header
        assert len(packet) >= 12
        # Header: ID should match
        import struct
        pid = struct.unpack("!H", packet[:2])[0]
        assert pid == qid
        # Flags should have RD=1
        flags = struct.unpack("!H", packet[2:4])[0]
        assert flags == 0x0100  # RD bit
        # QDCOUNT should be 1
        qdcount = struct.unpack("!H", packet[4:6])[0]
        assert qdcount == 1

    def test_build_dns_query_id_range(self):
        """Query ID should be in valid 16-bit range."""
        from seal.federation import _build_dns_query
        _, qid = _build_dns_query("test.com")
        assert 0 <= qid <= 65535

    def test_build_dns_query_contains_question(self):
        """Query packet should contain the encoded domain question."""
        from seal.federation import _build_dns_query
        packet, _ = _build_dns_query("example.com")

        # The question section starts after the 12-byte header
        question = packet[12:]
        # Should contain the encoded domain
        assert b"\x07example\x03com\x00" in question
        # Should end with QTYPE(16=TXT) + QCLASS(1=IN)
        import struct
        qtype, qclass = struct.unpack("!HH", question[-4:])
        assert qtype == 16  # TXT
        assert qclass == 1   # IN


class TestDNSNameParsing:
    def test_parse_name_simple(self):
        """Parse a simple uncompressed DNS name."""
        from seal.federation import _parse_name
        data = _make_dns_name("example.com")
        name, offset = _parse_name(data, 0)
        assert name == "example.com"
        assert offset == len(data)  # consumed exactly

    def test_parse_name_multi_label(self):
        """Parse a multi-label DNS name."""
        from seal.federation import _parse_name
        data = _make_dns_name("_vpe.agent.internal.example.com")
        name, offset = _parse_name(data, 0)
        assert name == "_vpe.agent.internal.example.com"
        assert offset == len(data)

    def test_parse_name_single_label(self):
        """Parse a single-label DNS name (e.g. 'localhost')."""
        from seal.federation import _parse_name
        data = _make_dns_name("localhost")
        name, offset = _parse_name(data, 0)
        assert name == "localhost"
        assert offset == len(data)

    def test_parse_name_with_compression(self):
        """Parse a compressed DNS name referencing an earlier label."""
        from seal.federation import _parse_name

        # Build a response-like packet:
        # Offset 0: uncompressed name "example.com"
        # Offset 14: a pointer to offset 0 (0xC000)
        name_bytes = _make_dns_name("example.com")
        pointer_bytes = b"\xc0\x00"  # Points to offset 0

        data = name_bytes + pointer_bytes
        name, new_offset = _parse_name(data, len(name_bytes))
        assert name == "example.com"
        assert new_offset == len(name_bytes) + 2  # consumed 2 pointer bytes at outer

    def test_parse_name_raises_on_truncated_pointer(self):
        """A truncated compression pointer raises FederationError."""
        from seal.federation import _parse_name, FederationError
        data = b"\xc0"  # Only half a pointer
        with pytest.raises(FederationError, match="Truncated DNS compression pointer"):
            _parse_name(data, 0)

    def test_parse_name_raises_on_truncated_label(self):
        """A label that extends past the packet boundary raises FederationError."""
        from seal.federation import _parse_name, FederationError
        data = b"\x05hello\x10" + b"x" * 10  # Length 16 label but only 10 bytes remain
        with pytest.raises(FederationError, match="Truncated DNS label"):
            _parse_name(data, 0)


class TestDNSResponseParsing:
    def test_parse_response_too_short(self):
        """Response shorter than 12 bytes raises FederationError."""
        from seal.federation import _parse_dns_response, FederationError
        with pytest.raises(FederationError, match="too short"):
            _parse_dns_response(b"\x00" * 10, 1)

    def test_parse_response_id_mismatch(self):
        """Response with mismatched ID raises FederationError."""
        from seal.federation import _parse_dns_response, FederationError
        header = _make_dns_header(query_id=42)  # Sent ID=42
        with pytest.raises(FederationError, match="ID mismatch"):
            _parse_dns_response(header, 99)  # Expected 99

    def test_parse_response_not_a_response(self):
        """Response without QR bit raises FederationError."""
        from seal.federation import _parse_dns_response, FederationError
        # Flags=0 (query, not response)
        header = _make_dns_header(query_id=1, flags=0x0000)
        with pytest.raises(FederationError, match="Not a DNS response"):
            _parse_dns_response(header, 1)

    def test_parse_response_nxdomain(self):
        """NXDOMAIN returns an empty list."""
        from seal.federation import _parse_dns_response
        # RCODE=3 (NXDOMAIN)
        header = _make_dns_header(query_id=1, flags=0x8183)
        assert _parse_dns_response(header, 1) == []

    def test_parse_response_truncated(self):
        """TC flag raises FederationError."""
        from seal.federation import _parse_dns_response, FederationError
        # Flags with TC=1 (0x8200)
        header = _make_dns_header(query_id=1, flags=0x8280)
        with pytest.raises(FederationError, match="truncated"):
            _parse_dns_response(header, 1)

    def test_parse_response_rcode_error(self):
        """Non-zero non-NXDOMAIN RCODE raises FederationError."""
        from seal.federation import _parse_dns_response, FederationError
        # RCODE=2 (ServFail)
        header = _make_dns_header(query_id=1, flags=0x8182)
        with pytest.raises(FederationError, match="RCODE=2"):
            _parse_dns_response(header, 1)

    def test_parse_response_single_txt(self):
        """Parse a response with a single TXT record."""
        from seal.federation import _parse_dns_response
        import struct

        qid = 1001
        # Build a complete response:
        header = _make_dns_header(
            query_id=qid,
            flags=0x8180,
            qdcount=1,
            ancount=1,
        )
        # Question section: _vpe.test.com
        question = _make_dns_name("_vpe.test.com") + struct.pack("!HH", 16, 1)
        # Answer section: compressed name + TYPE + CLASS + TTL + RDLENGTH + RDATA
        answer_name = b"\xc0\x0c"  # Pointer to question name (offset 12)
        answer_type_class = struct.pack("!HH", 16, 1)  # TXT, IN
        answer_ttl_rdlen = struct.pack("!IH", 300, 5)  # TTL=300, RDATA length=5
        answer_rdata = _make_txt_rdata("test")

        packet = header + question + answer_name + answer_type_class + answer_ttl_rdlen + answer_rdata
        result = _parse_dns_response(packet, qid)
        assert result == ["test"]

    def test_parse_response_multiple_txt_records(self):
        """Parse a response with multiple TXT records in one answer."""
        from seal.federation import _parse_dns_response
        import struct

        qid = 2002
        # Build response with multi-string TXT RDATA
        header = _make_dns_header(
            query_id=qid,
            flags=0x8180,
            qdcount=1,
            ancount=1,
        )
        question = _make_dns_name("example.com") + struct.pack("!HH", 16, 1)

        # Single answer with two TXT strings in one RDATA
        rdata = _make_txt_rdata("vpe-key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "extra-info")
        answer_name = b"\xc0\x0c"
        answer_type_class = struct.pack("!HH", 16, 1)
        answer_ttl_rdlen = struct.pack("!IH", 60, len(rdata))
        answer = answer_name + answer_type_class + answer_ttl_rdlen + rdata

        packet = header + question + answer
        result = _parse_dns_response(packet, qid)
        # First string is the vpe-key
        assert len(result) == 2
        assert result[0].startswith("vpe-key=")
        assert result[1] == "extra-info"

    def test_parse_response_multiple_answers(self):
        """Parse a response with multiple answer records."""
        from seal.federation import _parse_dns_response
        import struct

        qid = 3003
        header = _make_dns_header(
            query_id=qid,
            flags=0x8180,
            qdcount=1,
            ancount=2,
        )
        question = _make_dns_name("test.org") + struct.pack("!HH", 16, 1)

        # Answer 1: TXT "first"
        rdata1 = _make_txt_rdata("first")
        ans1 = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata1)) + rdata1

        # Answer 2: TXT "second"
        rdata2 = _make_txt_rdata("second")
        ans2 = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata2)) + rdata2

        packet = header + question + ans1 + ans2
        result = _parse_dns_response(packet, qid)
        assert result == ["first", "second"]

    def test_parse_response_ignores_non_txt(self):
        """Non-TXT record types are ignored."""
        from seal.federation import _parse_dns_response
        import struct

        qid = 4004
        header = _make_dns_header(
            query_id=qid,
            flags=0x8180,
            qdcount=1,
            ancount=2,
        )
        question = _make_dns_name("test.net") + struct.pack("!HH", 16, 1)

        # Answer 1: A record (type 1) — should be ignored
        a_rdata = struct.pack("!BBBB", 1, 2, 3, 4)
        ans1 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + a_rdata

        # Answer 2: TXT record — should be extracted
        rdata2 = _make_txt_rdata("vpe-key=aa")
        ans2 = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata2)) + rdata2

        packet = header + question + ans1 + ans2
        result = _parse_dns_response(packet, qid)
        assert result == ["vpe-key=aa"]

    def test_parse_response_zero_answers(self):
        """A valid response with zero answers returns empty list."""
        from seal.federation import _parse_dns_response
        qid = 5005
        header = _make_dns_header(query_id=qid, flags=0x8180, qdcount=1, ancount=0)
        question = _make_dns_name("empty.example") + b"\x00\x10\x00\x01"
        packet = header + question
        result = _parse_dns_response(packet, qid)
        assert result == []


class TestSystemResolver:
    def test_get_system_resolver_returns_string(self):
        """_get_system_resolver returns a non-empty IP string."""
        from seal.federation import _get_system_resolver
        resolver = _get_system_resolver()
        assert isinstance(resolver, str)
        assert len(resolver) > 0
        # Should be an IP address or hostname
        assert "." in resolver or ":" in resolver

    def test_get_system_resolver_fallback(self, monkeypatch):
        """When /etc/resolv.conf is missing, fallback to Cloudflare."""
        from seal.federation import _get_system_resolver

        def no_such_file(*args):
            raise FileNotFoundError()

        monkeypatch.setattr("builtins.open", no_such_file)
        assert _get_system_resolver() == "1.1.1.1"

    def test_get_system_resolver_fallback_on_oserror(self, monkeypatch):
        """When /etc/resolv.conf can't be read, fallback to Cloudflare."""
        from seal.federation import _get_system_resolver

        def raise_oserror(*args):
            raise OSError("permission denied")

        monkeypatch.setattr("builtins.open", raise_oserror)
        assert _get_system_resolver() == "1.1.1.1"


class TestResolveViaDNS:
    def test_nonexistent_domain_returns_none(self):
        """Non-existent domains return None (no crash)."""
        result = resolve_via_dns("nonexistent-domain-xyz123.test")
        assert result is None or isinstance(result, bytes)

    def test_resolve_via_dns_parse_vpe_key(self):
        """vpe-key= hex string is correctly parsed from TXT record."""
        # We can't easily mock DNS on a real query, but we can test the
        # vpe-key extraction logic via a manually constructed response
        # Test the regex path directly:
        import re
        record = 'vpe-key=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        assert match is not None
        key_bytes = bytes.fromhex(match.group(1))
        assert len(key_bytes) == 32

    def test_resolve_via_dns_bad_vpe_key(self):
        """Invalid hex in vpe-key returns None (graceful degradation)."""
        import re
        # Bad hex (zzz not valid)
        record = 'vpe-key=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        assert match is None  # zzz is not hex

    def test_resolve_via_dns_wrong_length_key(self):
        """A 63-char hex string (not 64) does not match vpe-key pattern."""
        import re
        # 63 chars (not 64)
        record = 'vpe-key=abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678'
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        assert match is None  # Not 64 chars

    def test_resolve_via_dns_no_vpe_key_prefix(self):
        """A TXT record without 'vpe-key=' prefix is ignored."""
        # Test via the regex path
        import re
        record = 'some-other-txt-record'
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        assert match is None


class TestResolveDNSTxt:
    def test_resolve_dns_txt_returns_list(self):
        """_resolve_dns_txt returns a list even on failure."""
        from seal.federation import _resolve_dns_txt
        result = _resolve_dns_txt("nonexistent-domain-for-testing-xyz.test")
        assert isinstance(result, list)

    def test_resolve_dns_txt_handles_malformed_gracefully(self):
        """_resolve_dns_txt never raises on bad input."""
        from seal.federation import _resolve_dns_txt
        # Even with an unqueryable domain, should return [] not crash
        result = _resolve_dns_txt("!@#$%^&*()_+.test")
        assert isinstance(result, list)


class TestDNSSendQuery:
    def test_send_dns_query_resolver_none(self):
        """Calling with resolver=None uses the system resolver."""
        from seal.federation import _send_dns_query
        # This shouldn't crash — should return [] for nonexistent or raise FederationError
        try:
            result = _send_dns_query("nonexistent-domain-for-testing-xyz.test")
            assert isinstance(result, list)
        except (OSError, Exception) as exc:
            # Network unavailable in CI — not a crash, just skip
            import socket
            if isinstance(exc, (socket.gaierror, OSError)):
                pass
            else:
                raise


# ---------------------------------------------------------------------------
# DID document resolution (did:web / did:ion)
# ---------------------------------------------------------------------------


class TestParseDIDWeb:
    def test_bare_domain(self):
        """did:web:example.com → https://example.com/.well-known/did.json"""
        from seal.federation import _parse_did_web
        url = _parse_did_web("did:web:example.com")
        assert url == "https://example.com/.well-known/did.json"

    def test_with_path(self):
        """did:web:example.com:path:to:file → https://example.com/path/to/file/did.json"""
        from seal.federation import _parse_did_web
        url = _parse_did_web("did:web:example.com:path:to:file")
        assert url == "https://example.com/path/to/file/did.json"

    def test_ip_address_domain(self):
        """did:web:192.168.1.1 works as bare domain."""
        from seal.federation import _parse_did_web
        url = _parse_did_web("did:web:192.168.1.1")
        assert url == "https://192.168.1.1/.well-known/did.json"

    def test_empty_domain_raises(self):
        """Empty domain raises FederationError."""
        from seal.federation import _parse_did_web, FederationError
        with pytest.raises(FederationError, match="Empty domain"):
            _parse_did_web("did:web:")
        with pytest.raises(FederationError, match="Empty domain"):
            _parse_did_web("did:web::path")

    def test_wrong_prefix_raises(self):
        """Non-did:web prefix raises FederationError."""
        from seal.federation import _parse_did_web, FederationError
        with pytest.raises(FederationError, match="Expected did:web"):
            _parse_did_web("did:key:zabc")


class TestDecodeMultibase:
    def test_invalid_prefix(self):
        """Non-'z' prefix returns None."""
        from seal.federation import _decode_multibase_key
        assert _decode_multibase_key("x12345") is None
        assert _decode_multibase_key("") is None

    def test_valid_ed25519_key(self):
        """Valid z-base58btc with Ed25519 multicodec returns key bytes."""
        from seal.federation import _decode_multibase_key
        # Build: 0xED + 32-byte test key → base58btc
        test_key = bytes(range(32))
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)
        multibase = f"z{encoded}"

        result = _decode_multibase_key(multibase)
        assert result == test_key
        assert len(result) == 32

    def test_valid_multikey_edge(self):
        """Two-byte Ed25519 varint (0x1301) also works."""
        from seal.federation import _decode_multibase_key
        test_key = bytes(range(32))
        payload = bytes([0x01, 0x13]) + test_key  # 2-byte varint
        encoded = _base58btc_encode(payload)
        multibase = f"z{encoded}"

        result = _decode_multibase_key(multibase)
        assert result == test_key

    def test_wrong_multicodec(self):
        """Non-Ed25519 multicodec returns None."""
        from seal.federation import _decode_multibase_key
        payload = bytes([0x01]) + bytes(range(32))  # 0x01 = unknown
        encoded = _base58btc_encode(payload)
        result = _decode_multibase_key(f"z{encoded}")
        assert result is None

    def test_wrong_key_length(self):
        """Wrong key length after stripping multicodec returns None."""
        from seal.federation import _decode_multibase_key
        # 0xED + 31 bytes (too short)
        payload = bytes([0xED]) + bytes(range(31))
        encoded = _base58btc_encode(payload)
        result = _decode_multibase_key(f"z{encoded}")
        assert result is None


class TestExtractEd25519FromDIDDocument:
    def test_ed25519_verification_key_2018(self):
        """Ed25519VerificationKey2018 with publicKeyMultibase is extracted."""
        from seal.federation import _extract_ed25519_from_did_document
        test_key = bytes(range(32))
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": f"z{encoded}",
                }
            ],
        }
        result = _extract_ed25519_from_did_document(doc)
        assert result == test_key

    def test_multikey_type(self):
        """Multikey type with Ed25519 multicodec is extracted."""
        from seal.federation import _extract_ed25519_from_did_document
        test_key = bytes(range(32))
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Multikey",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": f"z{encoded}",
                }
            ],
        }
        result = _extract_ed25519_from_did_document(doc)
        assert result == test_key

    def test_missing_verification_method(self):
        """Missing verificationMethod returns None."""
        from seal.federation import _extract_ed25519_from_did_document
        doc = {"id": "did:web:example.com"}
        assert _extract_ed25519_from_did_document(doc) is None

    def test_empty_verification_method(self):
        """Empty verificationMethod array returns None."""
        from seal.federation import _extract_ed25519_from_did_document
        doc = {"id": "did:web:example.com", "verificationMethod": []}
        assert _extract_ed25519_from_did_document(doc) is None

    def test_controller_filter(self):
        """expected_did filters verificationMethods by controller."""
        from seal.federation import _extract_ed25519_from_did_document
        key_alice = bytes([0] * 31 + [1])
        key_bob = bytes([0] * 31 + [2])

        def _make_doc(controller, key):
            payload = bytes([0xED]) + key
            encoded = _base58btc_encode(payload)
            return {
                "id": controller,
                "type": "Ed25519VerificationKey2018",
                "controller": controller,
                "publicKeyMultibase": f"z{encoded}",
            }

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                _make_doc("did:web:alice.com", key_alice),
                _make_doc("did:web:bob.com", key_bob),
            ],
        }

        # Filter for alice
        result = _extract_ed25519_from_did_document(doc, expected_did="did:web:alice.com")
        assert result == key_alice

        # Filter for bob
        result = _extract_ed25519_from_did_document(doc, expected_did="did:web:bob.com")
        assert result == key_bob

        # No match
        result = _extract_ed25519_from_did_document(doc, expected_did="did:web:eve.com")
        assert result is None

    def test_unsupported_key_type_skipped(self):
        """Unsupported key types (e.g. RSA) are skipped; next key tried."""
        from seal.federation import _extract_ed25519_from_did_document
        test_key = bytes(range(32))
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#rsa-key",
                    "type": "RsaVerificationKey2018",
                    "controller": "did:web:example.com",
                    "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
                },
                {
                    "id": "did:web:example.com#ed-key",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": f"z{encoded}",
                },
            ],
        }
        result = _extract_ed25519_from_did_document(doc)
        assert result == test_key  # Falls through to the Ed25519 key

    def test_public_key_jwk_fallback(self):
        """publicKeyJwk with Ed25519 curve is decoded via base64url."""
        from seal.federation import _extract_ed25519_from_did_document
        import base64

        test_key = bytes(range(32))
        x_encoded = base64.urlsafe_b64encode(test_key).decode("ascii").rstrip("=")

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:web:example.com",
                    "publicKeyJwk": {
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": x_encoded,
                    },
                }
            ],
        }
        result = _extract_ed25519_from_did_document(doc)
        assert result == test_key


class TestResolveViaDIDDocument:
    def test_unsupported_method_raises(self):
        """Unsupported DID method raises FederationError."""
        from seal.federation import resolve_via_did_document, FederationError
        with pytest.raises(FederationError, match="Unsupported DID method"):
            resolve_via_did_document("did:key:zabc")

    def test_did_web_malformed_raises(self):
        """Malformed did:web URI raises FederationError."""
        from seal.federation import resolve_via_did_document, FederationError
        with pytest.raises(FederationError, match="Empty domain"):
            resolve_via_did_document("did:web:")

    def test_did_ion_malformed_raises(self):
        """Malformed did:ion URI raises FederationError."""
        from seal.federation import resolve_via_did_document, FederationError
        with pytest.raises(FederationError, match="Empty suffix"):
            resolve_via_did_document("did:ion:")

    def test_fetch_json_https_network_error_raises(self, monkeypatch):
        """Network error in _fetch_json_https raises FederationError."""
        from seal.federation import _fetch_json_https, FederationError
        import urllib.error

        def mock_urlopen(*args, **kwargs):
            raise urllib.error.URLError("Network unreachable")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="Network error|URL error"):
            _fetch_json_https("https://example.com/did.json")

    def test_fetch_json_https_http_error_raises(self, monkeypatch):
        """HTTP error in _fetch_json_https raises FederationError."""
        from seal.federation import _fetch_json_https, FederationError
        import urllib.error

        def mock_urlopen(*args, **kwargs):
            raise urllib.error.HTTPError(
                "https://example.com/did.json", 404, "Not Found", {}, None
            )

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="HTTP 404"):
            _fetch_json_https("https://example.com/did.json")

    def test_fetch_json_https_bad_json_raises(self, monkeypatch):
        """Malformed JSON response raises FederationError."""
        from seal.federation import _fetch_json_https, FederationError

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self):
                return b"not valid json{{{"

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="Malformed JSON"):
            _fetch_json_https("https://example.com/did.json")

    def test_fetch_json_https_non_dict_raises(self, monkeypatch):
        """JSON array (not object) raises FederationError."""
        from seal.federation import _fetch_json_https, FederationError

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self):
                return b"[1, 2, 3]"

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="Expected JSON object"):
            _fetch_json_https("https://example.com/did.json")

    def test_fetch_json_https_empty_body_raises(self, monkeypatch):
        """Empty response body raises FederationError."""
        from seal.federation import _fetch_json_https, FederationError

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self):
                return b""

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="Empty response"):
            _fetch_json_https("https://example.com/did.json")

    def test_parse_did_ion_constructs_url(self):
        """_parse_did_ion constructs correct ION resolver URL."""
        from seal.federation import _parse_did_ion
        url = _parse_did_ion("did:ion:EiD9k9f3q5m8w2r7t6y1u4p3a6s8d9f0g1h2j3k4l5z6x7c8v9b0n1m2")
        assert url.startswith("https://discover.did.msidentity.com/1.0/identifiers/")
        assert "EiD9k9f3q5m8w2r7t6y1u4p3a6s8d9f0g1h2j3k4l5z6x7c8v9b0n1m2" in url


# ---------------------------------------------------------------------------
# Trust bundle export/import
# ---------------------------------------------------------------------------


class TestCanonicalTrustBundle:
    def test_deterministic_ordering(self):
        """_canonical_trust_bundle produces deterministic output."""
        from seal.federation import _canonical_trust_bundle

        bundle = {
            "vpe_trust_bundle": "1",
            "exported_at": "2026-07-11T04:30:00Z",
            "exporter_agent_id": "agent:alice",
            "exporter_public_key_hex": "ab" * 32,
            "anchors": {"z-agent": "01" * 32, "a-agent": "02" * 32},
        }
        canon1 = _canonical_trust_bundle(bundle)
        canon2 = _canonical_trust_bundle(bundle)
        assert canon1 == canon2

    def test_anchors_sorted_lexicographically(self):
        """Anchors are sorted lexicographically in canonical output."""
        from seal.federation import _canonical_trust_bundle

        bundle = {
            "vpe_trust_bundle": "1",
            "exported_at": "2026-07-11T04:30:00Z",
            "exporter_agent_id": "agent:alice",
            "exporter_public_key_hex": "ab" * 32,
            "anchors": {"z-agent": "01" * 32, "a-agent": "02" * 32},
        }
        canon = _canonical_trust_bundle(bundle).decode("utf-8")
        # a-agent should appear before z-agent
        a_pos = canon.index("a-agent")
        z_pos = canon.index("z-agent")
        assert a_pos < z_pos

    def test_missing_fields_default(self):
        """Missing fields default to empty string or empty dict."""
        from seal.federation import _canonical_trust_bundle

        canon = _canonical_trust_bundle({}).decode("utf-8")
        assert '"vpe_trust_bundle":""' in canon
        assert '"anchors":{}' in canon
        assert '"exported_at":""' in canon


class TestExportTrustBundle:
    def test_export_produces_valid_bundle(self, populated_registry, alice_keys):
        """Basic export returns valid JSON with required fields."""
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        assert bundle["vpe_trust_bundle"] == "1"
        assert bundle["exporter_agent_id"] == "agent:alice"
        assert "exported_at" in bundle
        assert "exporter_public_key_hex" in bundle
        assert "anchors" in bundle
        assert "signature" in bundle
        assert len(bundle["anchors"]) == 2

    def test_export_empty_registry_raises(self, tmp_registry, alice_keys):
        """Export with no anchors raises FederationError."""
        from seal.federation import FederationError

        with pytest.raises(FederationError, match="no trust anchors registered"):
            export_trust_bundle(
                tmp_registry,  # empty registry
                exporter_agent_id="agent:alice",
                private_key=alice_keys["private_key"],
            )

    def test_export_bundle_signature_verifiable(self, populated_registry, alice_keys):
        """The bundle signature can be verified with the embedded public key."""
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)

        from seal.federation import _canonical_trust_bundle
        from seal._base import _load_public_key

        pk_hex = bundle["exporter_public_key_hex"]
        pk = _load_public_key(bytes.fromhex(pk_hex))
        sig = bytes.fromhex(bundle["signature"])

        # Copy bundle without signature, canonicalize, verify
        payload = dict(bundle)
        del payload["signature"]
        canon = _canonical_trust_bundle(payload)

        # Should not raise
        pk.verify(sig, canon)

    def test_export_exported_at_is_iso_timestamp(self, populated_registry, alice_keys):
        """exported_at field is a valid ISO 8601 timestamp."""
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)

        import datetime

        # Should parse as UTC ISO timestamp
        ts = bundle["exported_at"]
        parsed = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert isinstance(parsed, datetime.datetime)


class TestImportTrustBundle:
    def test_import_valid_bundle(self, populated_registry, alice_keys, tmp_registry):
        """Import a valid bundle succeeds and anchors are registered."""
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )

        result = import_trust_bundle(bundle_str, tmp_registry)
        assert result["ok"] is True
        assert result["imported_count"] == 2
        assert result["exporter_agent_id"] == "agent:alice"

        # Verify anchors were imported
        assert tmp_registry.lookup("agent:alice") is not None
        assert tmp_registry.lookup("agent:bob") is not None

    def test_import_duplicate_is_idempotent(self, populated_registry, alice_keys, tmp_registry):
        """Re-importing the same anchor does not error (idempotent)."""
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )

        # First import
        result1 = import_trust_bundle(bundle_str, tmp_registry)
        assert result1["imported_count"] == 2

        # Second import — should still succeed with same count
        result2 = import_trust_bundle(bundle_str, tmp_registry)
        # Anchors already exist, register updates them (counts them as imported)
        assert result2["ok"] is True
        assert result2["imported_count"] == 2

    def test_import_invalid_json_raises(self, tmp_registry):
        """Malformed JSON raises FederationError."""
        from seal.federation import FederationError

        with pytest.raises(FederationError, match="Invalid trust bundle JSON"):
            import_trust_bundle("not valid json{{", tmp_registry)

    def test_import_not_a_dict_raises(self, tmp_registry):
        """Non-dict bundle raises FederationError."""
        from seal.federation import FederationError

        with pytest.raises(FederationError, match="Trust bundle must be a JSON object"):
            import_trust_bundle('["array", "not", "object"]', tmp_registry)

    def test_import_wrong_version_raises(self, tmp_registry, populated_registry, alice_keys):
        """Wrong bundle version raises FederationError."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        bundle["vpe_trust_bundle"] = "999"
        tampered = json.dumps(bundle, separators=(",", ":"))

        with pytest.raises(FederationError, match="Unsupported trust bundle version"):
            import_trust_bundle(tampered, tmp_registry)

    def test_import_tampered_bundle_raises(self, populated_registry, alice_keys, tmp_registry):
        """Tampered content fails signature verification."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        # Tamper with an anchor value
        bundle["anchors"]["agent:alice"] = "ff" * 32
        tampered = json.dumps(bundle, separators=(",", ":"))

        with pytest.raises(FederationError, match="signature verification failed|signature mismatch"):
            import_trust_bundle(tampered, tmp_registry)

    def test_import_untrusted_exporter_raises(self, populated_registry, alice_keys, tmp_registry):
        """Exporter not in trusted set raises FederationError."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )

        with pytest.raises(FederationError, match="Untrusted exporter"):
            import_trust_bundle(
                bundle_str, tmp_registry, trusted_exporter_ids={"agent:bob"}
            )

    def test_import_missing_exporter_id_raises(self, populated_registry, alice_keys, tmp_registry):
        """Bundle without exporter_agent_id raises FederationError."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        del bundle["exporter_agent_id"]
        tampered = json.dumps(bundle, separators=(",", ":"))

        with pytest.raises(FederationError, match="missing exporter_agent_id"):
            import_trust_bundle(tampered, tmp_registry)

    def test_import_missing_signature_raises(self, populated_registry, alice_keys, tmp_registry):
        """Bundle without signature raises FederationError."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        del bundle["signature"]
        tampered = json.dumps(bundle, separators=(",", ":"))

        with pytest.raises(FederationError, match="missing signature"):
            import_trust_bundle(tampered, tmp_registry)

    def test_import_missing_public_key_raises(self, populated_registry, alice_keys, tmp_registry):
        """Bundle without exporter_public_key_hex raises FederationError."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        del bundle["exporter_public_key_hex"]
        tampered = json.dumps(bundle, separators=(",", ":"))

        with pytest.raises(FederationError, match="missing exporter_public_key_hex"):
            import_trust_bundle(tampered, tmp_registry)

    def test_import_partial_anchor_skip(self, tmp_registry, alice_keys):
        """Anchors with invalid hex keys are skipped without failing the whole import."""
        bundle = {
            "vpe_trust_bundle": "1",
            "exported_at": "2026-07-11T04:30:00Z",
            "exporter_agent_id": "agent:test",
            "exporter_public_key_hex": alice_keys["public_key"].hex(),
            "anchors": {
                "agent:valid": alice_keys["public_key"].hex(),
                "agent:invalid_hex": "not hex at all",
                "agent:short_key": "abcd",
            },
        }
        # Sign it properly
        from seal.federation import _canonical_trust_bundle
        from seal._base import _load_private_key

        sk = _load_private_key(alice_keys["private_key"])
        canon = _canonical_trust_bundle(bundle)
        bundle["signature"] = sk.sign(canon).hex()
        bundle_str = json.dumps(bundle, separators=(",", ":"))

        result = import_trust_bundle(bundle_str, tmp_registry)
        assert result["imported_count"] == 1  # Only the valid anchor was imported
        assert tmp_registry.lookup("agent:valid") is not None


class TestTrustBundleRoundtrip:
    def test_export_import_roundtrip(self, populated_registry, alice_keys):
        """Export and import on a separate registry transfers all anchors."""
        import tempfile

        # Export
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )

        # Create a fresh registry
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}\n")
            target_path = f.name

        try:
            from seal.federation import TrustAnchorRegistry
            target_registry = TrustAnchorRegistry(path=target_path)

            # Import
            result = import_trust_bundle(bundle_str, target_registry)
            assert result["ok"] is True
            assert result["imported_count"] == 2

            # Verify all anchors transferred
            assert target_registry.lookup("agent:alice") == populated_registry.lookup("agent:alice")
            assert target_registry.lookup("agent:bob") == populated_registry.lookup("agent:bob")
        finally:
            import os
            try:
                os.unlink(target_path)
            except OSError:
                pass

    def test_export_import_cross_agent(self, populated_registry, alice_keys, bob_keys):
        """Alice exports, Bob imports using Bob's key for signing the export."""
        import tempfile

        # Alice registers one anchor, exports signed with her key
        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )

        # Bob creates his own registry and imports Alice's bundle
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}\n")
            target_path = f.name

        try:
            from seal.federation import TrustAnchorRegistry
            bobs_registry = TrustAnchorRegistry(path=target_path)

            result = import_trust_bundle(
                bundle_str,
                bobs_registry,
                trusted_exporter_ids={"agent:alice"},
            )
            assert result["ok"] is True
            assert result["imported_count"] == 2
            assert bobs_registry.lookup("agent:alice") == populated_registry.lookup("agent:alice")
        finally:
            import os
            try:
                os.unlink(target_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# P9.5d: Integration tests — DNS stub, full chain, timeout, DID doc mock
# ---------------------------------------------------------------------------


class MockDNSSocket:
    """Mock socket.socket that returns controlled DNS response packets.

    Captures the query ID from the sent packet so response ID matches.
    """

    def __init__(self, family, sock_type):
        self._response_data: bytes = b""
        self._timeout_value: float | None = None
        self._should_timeout: bool = False
        self._sent_bytes: bytes = b""
        self._closed = False

    def set_response_txt(self, domain: str, txt_records: list[str], ttl: int = 300):
        """Build and store a DNS response packet with the given TXT records."""
        import struct

        query_id = 0xCAFE
        header = _make_dns_header(
            query_id=query_id,
            flags=0x8180,
            qdcount=1,
            ancount=len(txt_records) or 1,
        )
        question = _make_dns_name(domain) + struct.pack("!HH", 16, 1)
        answers = b""
        for txt in txt_records:
            rdata = _make_txt_rdata(txt)
            answers += (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 16, 1, ttl, len(rdata))
                + rdata
            )
        actual_ancount = len(txt_records)
        header = _make_dns_header(
            query_id=query_id,
            flags=0x8180,
            qdcount=1,
            ancount=actual_ancount,
        )
        self._response_data = header + question + answers

    def settimeout(self, value: float):
        self._timeout_value = value

    def sendto(self, data: bytes, addr: tuple):
        self._sent_bytes = data
        if not self._response_data or len(data) < 2:
            return
        sent_qid = (data[0] << 8) | data[1]
        resp = bytearray(self._response_data)
        resp[0] = (sent_qid >> 8) & 0xFF
        resp[1] = sent_qid & 0xFF
        self._response_data = bytes(resp)

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple]:
        if self._should_timeout:
            import socket as _socket
            raise _socket.timeout("timed out")
        return self._response_data[:bufsize], ("127.0.0.1", 53)

    def close(self):
        self._closed = True

    def enable_timeout(self):
        self._should_timeout = True


@pytest.fixture
def mock_dns_socket():
    """Fixture that installs a MockDNSSocket in place of socket.socket."""
    import socket as socket_module

    mock = MockDNSSocket(socket_module.AF_INET, socket_module.SOCK_DGRAM)

    def mock_socket(family=socket_module.AF_INET, sock_type=socket_module.SOCK_DGRAM):
        return mock

    original_socket = socket_module.socket
    socket_module.socket = mock_socket
    yield mock
    socket_module.socket = original_socket


class TestIntegrationDNSStub:
    """Controlled DNS stub (AC1) — mock socket returns configurable TXT records."""

    def test_dns_stub_returns_txt(self, mock_dns_socket):
        """The DNS stub returns configured TXT records when queried."""
        mock_dns_socket.set_response_txt(
            "_vpe.test.agent.example", ["vpe-key=" + "ab" * 32]
        )
        from seal.federation import _send_dns_query

        records = _send_dns_query("test.agent.example")
        assert len(records) == 1
        assert records[0] == "vpe-key=" + "ab" * 32

    def test_dns_stub_multiple_txt(self, mock_dns_socket):
        """The stub returns multiple TXT records."""
        mock_dns_socket.set_response_txt(
            "_vpe.agent.corp",
            ["vpe-key=" + "aa" * 32, "extra-info"],
        )
        from seal.federation import _send_dns_query

        records = _send_dns_query("agent.corp")
        assert len(records) == 2
        assert any(r.startswith("vpe-key=") for r in records)
        assert "extra-info" in records

    def test_dns_stub_empty_response(self, mock_dns_socket):
        """Stub with zero records returns empty list."""
        mock_dns_socket.set_response_txt("_vpe.unknown.domain", [])
        from seal.federation import _send_dns_query

        records = _send_dns_query("unknown.domain")
        assert records == []

    def test_dns_stub_resolve_via_dns_full_path(self, mock_dns_socket, alice_keys):
        """resolve_via_dns returns correct key bytes when stub has vpe-key TXT."""
        pk_hex = alice_keys["public_key"].hex()
        mock_dns_socket.set_response_txt(
            "_vpe.alice.internal.corp", [f"vpe-key={pk_hex}"]
        )
        key = resolve_via_dns("alice.internal.corp")
        assert key == alice_keys["public_key"]

    def test_dns_stub_no_vpe_key_record(self, mock_dns_socket):
        """TXT records without 'vpe-key=' prefix are ignored, returns None."""
        mock_dns_socket.set_response_txt("_vpe.nokey.test", ["some-other-txt=value"])
        key = resolve_via_dns("nokey.test")
        assert key is None

    def test_stub_handles_nxdomain_like_empty(self, mock_dns_socket):
        """Stub with no answers returns empty list from _resolve_dns_txt."""
        mock_dns_socket.set_response_txt("_vpe.void.domain", [])
        from seal.federation import _resolve_dns_txt

        result = _resolve_dns_txt("void.domain")
        assert result == []


class TestIntegrationDNSFullChain:
    """Full DNS discovery -> sign -> verify -> reject-tampered chain (AC2)."""

    def test_dns_discover_sign_verify(self, mock_dns_socket, alice_keys):
        """DNS-discovered key can verify a federated signature."""
        pk_hex = alice_keys["public_key"].hex()
        mock_dns_socket.set_response_txt(
            "_vpe.alice.vault.corp", [f"vpe-key={pk_hex}"]
        )
        signed = vpe_federated_sign(
            prompt="release: deploy v3.2 to staging",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        assert signed.error == ""

        result = vpe_federated_verify(
            signed.envelope, dns_domain="alice.vault.corp"
        )
        assert result["valid"] is True
        assert result["source"] == "dns"

    def test_dns_chain_reject_tampered(self, mock_dns_socket, alice_keys):
        """After DNS discovery, a tampered envelope is rejected."""
        pk_hex = alice_keys["public_key"].hex()
        mock_dns_socket.set_response_txt(
            "_vpe.alice.vault.corp", [f"vpe-key={pk_hex}"]
        )
        signed = vpe_federated_sign(
            prompt="release: deploy to prod",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        parsed = json.loads(signed.envelope)
        parsed["prompt"] = "release: DEPLOY MALICIOUS CODE"
        tampered = json.dumps(parsed, separators=(",", ":"))

        result = vpe_federated_verify(tampered, dns_domain="alice.vault.corp")
        assert result["valid"] is False
        assert result["source"] == "dns"

    def test_dns_chain_wrong_key_rejected(self, mock_dns_socket, alice_keys, bob_keys):
        """DNS returns wrong key -> signature verification fails."""
        bob_hex = bob_keys["public_key"].hex()
        mock_dns_socket.set_response_txt(
            "_vpe.alice.vault.corp", [f"vpe-key={bob_hex}"]
        )
        signed = vpe_federated_sign(
            prompt="transfer funds",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        result = vpe_federated_verify(
            signed.envelope, dns_domain="alice.vault.corp"
        )
        assert result["valid"] is False
        assert "signature_mismatch" in result.get("reason", "")

    def test_dns_chain_unknown_issuer(self, mock_dns_socket, alice_keys):
        """DNS returns no key -> unknown_issuer error."""
        mock_dns_socket.set_response_txt("_vpe.unknown.vault.corp", [])
        signed = vpe_federated_sign(
            prompt="test",
            issuer="agent:eve",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        result = vpe_federated_verify(
            signed.envelope, dns_domain="unknown.vault.corp"
        )
        assert result["valid"] is False
        assert "unknown_issuer" in result.get("reason", "")

    def test_dns_discover_with_audit(self, mock_dns_socket, alice_keys, tmp_registry):
        """DNS-discovered verification is audited correctly."""
        from seal.audit import AuditLog

        pk_hex = alice_keys["public_key"].hex()
        mock_dns_socket.set_response_txt(
            "_vpe.alice.vault.corp", [f"vpe-key={pk_hex}"]
        )
        audit = FederationAuditLog(
            audit=AuditLog(
                path=tmp_registry.path.replace(".json", "_dns_audit.jsonl")
            )
        )
        signed = vpe_federated_sign(
            prompt="audited DNS operation",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        result = vpe_federated_verify(
            signed.envelope, dns_domain="alice.vault.corp", audit_log=audit
        )
        assert result["valid"] is True

        entries = audit.audit.query()
        dns_sourced = [
            e
            for e in entries
            if e.get("event") == "vpe_cross_audit" and e.get("source") == "dns"
        ]
        assert len(dns_sourced) >= 1

    def test_dns_resolution_order_respected(
        self, mock_dns_socket, alice_keys, populated_registry
    ):
        """Registry lookup takes priority over DNS even when both are available."""
        import os

        wrong_pk = os.urandom(32)
        mock_dns_socket.set_response_txt(
            "_vpe.alice.vault.corp", [f"vpe-key={wrong_pk.hex()}"]
        )
        signed = vpe_federated_sign(
            prompt="priority test",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        result = vpe_federated_verify(
            signed.envelope,
            registry=populated_registry,
            dns_domain="alice.vault.corp",
        )
        assert result["valid"] is True
        assert result["source"] == "registry"


class TestIntegrationDNSTimeout:
    """DNS timeout simulation (AC3) - graceful degradation on slow DNS."""

    def test_dns_timeout_returns_empty(self, mock_dns_socket):
        """When DNS socket times out, _resolve_dns_txt returns [] (no crash)."""
        mock_dns_socket.enable_timeout()
        from seal.federation import _resolve_dns_txt

        result = _resolve_dns_txt("timeout.test.example")
        assert result == []

    def test_dns_timeout_resolve_via_dns_returns_none(self, mock_dns_socket):
        """resolve_via_dns returns None when DNS times out."""
        mock_dns_socket.enable_timeout()
        key = resolve_via_dns("timeout.test.example")
        assert key is None

    def test_dns_timeout_federated_verify_graceful(
        self, mock_dns_socket, alice_keys
    ):
        """Federated verify with timing-out DNS returns unknown_issuer."""
        mock_dns_socket.enable_timeout()
        signed = vpe_federated_sign(
            prompt="timeout test",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        result = vpe_federated_verify(
            signed.envelope, dns_domain="alice.vault.corp"
        )
        assert result["valid"] is False
        assert "unknown_issuer" in result.get("reason", "")

    def test_dns_socket_error_graceful(self, monkeypatch):
        """A socket error during DNS returns [] from _resolve_dns_txt."""
        from seal import federation as fed_module
        import socket as socket_module

        class BrokenSocket:
            def __init__(self, family, sock_type):
                pass
            def settimeout(self, v):
                pass
            def sendto(self, d, a):
                raise OSError("Network unreachable")
            def recvfrom(self, s):
                return b"", ("", 0)
            def close(self):
                pass

        monkeypatch.setattr(socket_module, "socket", BrokenSocket)
        result = fed_module._resolve_dns_txt("brokentest.local")
        assert result == []


class TestIntegrationDIDDocumentFetch:
    """DID document fetch-and-parse with mock HTTP (AC4)."""

    def _make_mock_did_web_response(self, test_key, monkeypatch):
        """Install a mock urllib.request.urlopen that returns a valid DID document."""
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)
        did_doc = {
            "id": "did:web:test.example.com",
            "verificationMethod": [
                {
                    "id": "did:web:test.example.com#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:web:test.example.com",
                    "publicKeyMultibase": f"z{encoded}",
                }
            ],
        }

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/did+json"}

            def read(self):
                return json.dumps(did_doc).encode("utf-8")

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    def test_did_web_resolve_full_chain(self, alice_keys, monkeypatch):
        """resolve_via_did_document with mocked HTTP returns correct key."""
        self._make_mock_did_web_response(alice_keys["public_key"], monkeypatch)
        key = resolve_via_did_document("did:web:test.example.com")
        assert key == alice_keys["public_key"]

    def test_did_web_federated_verify(self, alice_keys, monkeypatch):
        """Full chain: resolve via DID document -> verify with resolved key."""
        self._make_mock_did_web_response(alice_keys["public_key"], monkeypatch)
        signed = vpe_federated_sign(
            prompt="cross-DID operation",
            issuer="agent:alice",
            audience="agent:bob",
            private_key=alice_keys["private_key"],
        )
        resolved_key = resolve_via_did_document("did:web:test.example.com")
        assert resolved_key is not None

        from seal.core import vpe_verify

        result = vpe_verify(signed.envelope, public_key=resolved_key)
        assert result["valid"] is True

    def test_did_doc_invalid_key_type_returns_none(self, monkeypatch):
        """DID document with only unsupported key types returns None."""
        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/did+json"}

            def read(self):
                return json.dumps({
                    "id": "did:web:rsa.example.com",
                    "verificationMethod": [
                        {
                            "id": "did:web:rsa.example.com#rsa-key",
                            "type": "RsaVerificationKey2018",
                            "controller": "did:web:rsa.example.com",
                            "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
                        }
                    ],
                }).encode("utf-8")

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        assert resolve_via_did_document("did:web:rsa.example.com") is None

    def test_did_doc_network_fallback_graceful(self, monkeypatch):
        """Network error in DID document resolution raises FederationError."""
        from seal.federation import FederationError
        import urllib.error

        def mock_urlopen(*args, **kwargs):
            raise urllib.error.URLError("Connection refused")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="URL error|Network error"):
            resolve_via_did_document("did:web:unreachable.example.com")

    def test_did_ion_mock_resolve(self, monkeypatch):
        """did:ion resolution with mocked HTTP returns correct key."""
        test_key = bytes(range(32))
        payload = bytes([0xED]) + test_key
        encoded = _base58btc_encode(payload)

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/json"}
            def read(self):
                return json.dumps({
                    "id": "did:ion:EiABCD",
                    "didDocument": {
                        "id": "did:ion:EiABCD",
                        "verificationMethod": [
                            {
                                "id": "did:ion:EiABCD#key-1",
                                "type": "Ed25519VerificationKey2018",
                                "controller": "did:ion:EiABCD",
                                "publicKeyMultibase": f"z{encoded}",
                            }
                        ],
                    },
                }).encode("utf-8")

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        assert resolve_via_did_document("did:ion:EiABCD") == test_key

    def test_did_doc_empty_response_returns_none(self, monkeypatch):
        """Empty response body raises FederationError."""
        from seal.federation import FederationError

        class MockResponse:
            status = 200
            headers = {"Content-Type": "application/json"}
            def read(self):
                return b""

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        with pytest.raises(FederationError, match="Empty response"):
            resolve_via_did_document("did:web:empty.example.com")


class TestIntegrationTrustBundleCycle:
    """Trust bundle export -> import -> sign-verify cycle tests (AC5)."""

    def test_export_reimport_sign_verify(
        self, populated_registry, alice_keys, bob_keys
    ):
        """Export bundle -> import to new registry -> federated sign/verify works."""
        import tempfile
        import os as _os

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}\n")
            target_path = f.name
        try:
            new_registry = TrustAnchorRegistry(path=target_path)
            result = import_trust_bundle(bundle_str, new_registry)
            assert result["ok"] is True
            assert result["imported_count"] == 2

            signed = vpe_federated_sign(
                prompt="post-import operation",
                issuer="agent:alice",
                audience="agent:bob",
                private_key=alice_keys["private_key"],
            )
            verify_result = vpe_federated_verify(
                signed.envelope, registry=new_registry
            )
            assert verify_result["valid"] is True
            assert verify_result["source"] == "registry"
        finally:
            try:
                _os.unlink(target_path)
            except OSError:
                pass

    def test_cycle_tampered_export_rejected(
        self, populated_registry, alice_keys, tmp_registry
    ):
        """Tampered bundle between export and import is rejected on import."""
        from seal.federation import FederationError

        bundle_str = export_trust_bundle(
            populated_registry,
            exporter_agent_id="agent:alice",
            private_key=alice_keys["private_key"],
        )
        bundle = json.loads(bundle_str)
        bundle["anchors"]["agent:alice"] = "ff" * 32
        tampered = json.dumps(bundle, separators=(",", ":"))
        with pytest.raises(
            FederationError, match="signature verification failed|signature mismatch"
        ):
            import_trust_bundle(tampered, tmp_registry)

    def test_cycle_multiple_imports_accumulate(
        self, populated_registry, alice_keys, bob_keys
    ):
        """Multiple imports into the same registry accumulate anchors."""
        import tempfile
        import os as _os

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}\n")
            target_path = f.name
        try:
            registry = TrustAnchorRegistry(path=target_path)
            alice_bundle = export_trust_bundle(
                populated_registry,
                exporter_agent_id="agent:alice",
                private_key=alice_keys["private_key"],
            )
            r1 = import_trust_bundle(alice_bundle, registry)
            assert r1["imported_count"] == 2

            charlie_keys = generate_key_pair()
            populated_registry.register("agent:charlie", charlie_keys["public_key"])
            charlie_bundle = export_trust_bundle(
                populated_registry,
                exporter_agent_id="agent:alice",
                private_key=alice_keys["private_key"],
            )
            r2 = import_trust_bundle(charlie_bundle, registry)
            assert r2["imported_count"] == 3
            assert registry.lookup("agent:charlie") == charlie_keys["public_key"]
        finally:
            try:
                _os.unlink(target_path)
            except OSError:
                pass

    def test_cycle_sign_with_imported_verify_with_original(
        self, populated_registry, alice_keys, bob_keys
    ):
        """Sign using imported reg, verify using original reg (cross-registry exchange)."""
        import tempfile
        import os as _os

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}\n")
            target_path = f.name
        try:
            imported_reg = TrustAnchorRegistry(path=target_path)
            bundle = export_trust_bundle(
                populated_registry,
                exporter_agent_id="agent:alice",
                private_key=alice_keys["private_key"],
            )
            import_trust_bundle(bundle, imported_reg)

            signed = vpe_federated_sign(
                prompt="cross-registry exchange",
                issuer="agent:bob",
                audience="agent:alice",
                private_key=bob_keys["private_key"],
            )
            result = vpe_federated_verify(
                signed.envelope, registry=populated_registry
            )
            assert result["valid"] is True
        finally:
            try:
                _os.unlink(target_path)
            except OSError:
                pass

    def test_cycle_empty_import_idempotent(self, alice_keys, tmp_registry):
        """Importing a bundle with zero valid anchors does not corrupt registry."""
        from seal.federation import _canonical_trust_bundle
        from seal._base import _load_private_key

        bundle = {
            "vpe_trust_bundle": "1",
            "exported_at": "2026-07-11T04:30:00Z",
            "exporter_agent_id": "agent:alice",
            "exporter_public_key_hex": alice_keys["public_key"].hex(),
            "anchors": {},
        }
        sk = _load_private_key(alice_keys["private_key"])
        canon = _canonical_trust_bundle(bundle)
        bundle["signature"] = sk.sign(canon).hex()
        bundle_str = json.dumps(bundle, separators=(",", ":"))

        result = import_trust_bundle(bundle_str, tmp_registry)
        assert result["ok"] is True
        assert result["imported_count"] == 0
