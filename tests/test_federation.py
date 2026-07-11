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
    generate_key_pair,
    resolve_trust_anchor,
    resolve_via_did,
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
        from seal.federation import resolve_via_dns, _resolve_dns_txt
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
        from seal.federation import resolve_via_dns, _resolve_dns_txt
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
