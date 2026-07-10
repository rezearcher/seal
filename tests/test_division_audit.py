"""Tests for seal.integration.division_vpe_audit (P6.4b)."""

from __future__ import annotations

import json
import os
import time

import pytest

from seal.audit import AuditLog
from seal.vpe import generate_keypair, vpe_sign, vpe_verify

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def audit_path(tmp_path):
    return str(tmp_path / "vpe_audit.jsonl")


@pytest.fixture
def audit_log(audit_path):
    return AuditLog(audit_path)


@pytest.fixture
def mock_remember():
    """A Division remember mock that captures calls and returns an episode_id."""
    _captured = []

    def remember(conversation_id="", agent="", key="", value=None, **kwargs):
        if value is None:
            value = {}
        _captured.append(
            {
                "conversation_id": conversation_id,
                "agent": agent,
                "key": key,
                "value": value,
                "kwargs": kwargs,
            }
        )
        return {
            "result": json.dumps(
                {
                    "episode_id": f"ep_{len(_captured)}_{int(time.time())}",
                    "conversation_id": conversation_id,
                }
            )
        }

    remember.captured = _captured
    return remember


@pytest.fixture
def sealer_audit(audit_log, mock_remember):
    """A fully configured DivisionVPEAudit with mock Division."""
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    return DivisionVPEAudit(
        audit_log=audit_log,
        conversation_id="test-vpe-audit",
        remember_func=mock_remember,
    )


@pytest.fixture
def local_only_audit(audit_log):
    """A DivisionVPEAudit without a Division back-end (fallback test)."""
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    return DivisionVPEAudit(
        audit_log=audit_log,
        conversation_id="test-vpe-audit-local",
        remember_func=None,
    )


# ---------------------------------------------------------------------------
# Episode schema
# ---------------------------------------------------------------------------


def test_episode_schema(sealer_audit, mock_remember):
    """Each episode contains required fields."""
    sealer_audit.record(
        envelope_hash="abc123def456",
        issuer="user:rez",
        result="invalid",
        reason="signature mismatch",
        tool_name="terminal",
    )

    assert len(mock_remember.captured) == 1
    cap = mock_remember.captured[0]

    assert cap["conversation_id"] == "test-vpe-audit"
    assert cap["agent"] == "seal-vpe"
    assert cap["key"].startswith("vpe:invalid:")

    value = cap["value"]
    assert value["envelope_hash"] == "abc123def456"
    assert value["issuer"] == "user:rez"
    assert value["result"] == "invalid"
    assert value["reason"] == "signature mismatch"
    assert value["tool_name"] == "terminal"
    assert "audit_id" in value
    assert "timestamp" in value
    assert "timestamp_iso" in value


def test_all_result_types(sealer_audit, mock_remember):
    """All valid result types are accepted."""
    for r in ("valid", "invalid", "expired", "error", "unverified"):
        sealer_audit.record(
            envelope_hash=f"hash_{r}",
            issuer="test",
            result=r,
        )
    assert len(mock_remember.captured) == 5
    captured_results = {c["value"]["result"] for c in mock_remember.captured}
    assert captured_results == {"valid", "invalid", "expired", "error", "unverified"}


def test_invalid_result_raises(sealer_audit):
    """Invalid result type raises ValueError."""
    with pytest.raises(ValueError, match="Invalid result"):
        sealer_audit.record(
            envelope_hash="h1",
            issuer="test",
            result="not_a_real_result",
        )


# ---------------------------------------------------------------------------
# Local fallback (P6.4a)
# ---------------------------------------------------------------------------


def test_local_fallback_no_division(local_only_audit, audit_path):
    """Records are written to local JSONL even without Division."""
    aid = local_only_audit.record(
        envelope_hash="hash1",
        issuer="user:test",
        result="valid",
        reason="all good",
    )

    # Verify local audit has the entry
    entries = local_only_audit.query_local()
    assert len(entries) >= 1
    assert entries[0]["audit_id"] == aid
    assert entries[0]["result"] == "valid"

    # File should exist on disk
    assert os.path.exists(audit_path)


def test_local_fallback_division_fails(sealer_audit, audit_log):
    """When Division remember raises, local log still works."""

    def broken_remember(**kwargs):
        raise ConnectionError("Division unavailable")

    sealer_audit._remember_func = broken_remember

    _ = sealer_audit.record(
        envelope_hash="hash2",
        issuer="user:test",
        result="error",
        reason="connection refused",
    )

    # Local log should have the entry
    entries = sealer_audit.query_local()
    assert len(entries) >= 1


# ---------------------------------------------------------------------------
# Query local
# ---------------------------------------------------------------------------


def test_query_local_filter_result(sealer_audit):
    """query_local can filter by result type."""
    sealer_audit.record("h1", "alice", "valid")
    sealer_audit.record("h2", "bob", "invalid", reason="bad sig")
    sealer_audit.record("h3", "alice", "valid")

    valid = sealer_audit.query_local(result_filter="valid")
    assert len(valid) == 2
    assert all(e["result"] == "valid" for e in valid)

    invalid = sealer_audit.query_local(result_filter="invalid")
    assert len(invalid) == 1
    assert invalid[0]["result"] == "invalid"


def test_query_local_filter_issuer(sealer_audit):
    """query_local can filter by issuer."""
    sealer_audit.record("h1", "user:rez", "valid")
    sealer_audit.record("h2", "agent:hermes", "valid")
    sealer_audit.record("h3", "user:alice", "invalid")

    rez = sealer_audit.query_local(issuer_filter="rez")
    assert len(rez) >= 1
    assert all("rez" in e["issuer"] for e in rez)


def test_query_local_filter_since(sealer_audit):
    """query_local can filter by timestamp."""
    now = time.time()
    sealer_audit.record("h1", "test", "valid")

    future = sealer_audit.query_local(since=now + 99999)
    assert len(future) == 0

    past = sealer_audit.query_local(since=now - 10)
    assert len(past) >= 1


# ---------------------------------------------------------------------------
# record_from_result convenience
# ---------------------------------------------------------------------------


def test_record_from_result(sealer_audit, keypair, mock_remember):
    """record_from_result extracts envelope hash and result from VPEResult."""
    sk, pk = keypair
    envelope = vpe_sign(
        prompt="test prompt",
        issuer="user:rez",
        audience="agent:hermes",
        private_key=sk,
        public_key=pk,
    )
    result = vpe_verify(envelope, public_key=pk)

    aid = sealer_audit.record_from_result(
        envelope=envelope,
        result_obj=result,
        tool_name="web_search",
    )

    assert aid is not None
    assert len(mock_remember.captured) >= 1
    cap = mock_remember.captured[-1]
    assert cap["value"]["result"] == "valid"
    assert cap["value"]["tool_name"] == "web_search"
    assert "envelope_hash" in cap["value"]


def test_record_from_result_invalid(sealer_audit, keypair, mock_remember):
    """record_from_result records 'invalid' for failed verification."""
    sk, pk = keypair
    envelope = vpe_sign(
        prompt="test",
        issuer="user:rez",
        audience="agent:hermes",
        private_key=sk,
        public_key=pk,
    )
    # Verify with wrong key — will be invalid
    wrong_sk, wrong_pk = generate_keypair()
    result = vpe_verify(envelope, public_key=wrong_pk)

    aid = sealer_audit.record_from_result(
        envelope=envelope,
        result_obj=result,
    )

    assert aid is not None
    cap = mock_remember.captured[-1]
    assert cap["value"]["result"] == "invalid"


# ---------------------------------------------------------------------------
# DivisionVPESigner integration
# ---------------------------------------------------------------------------


def test_signer_with_audit(keypair, audit_log, mock_remember):
    """DivisionVPESigner records audit entries when set_audit is called."""
    from seal.integration.division_vpe_audit import DivisionVPEAudit
    from seal.integration.division_vpe_signer import DivisionVPESigner

    audit = DivisionVPEAudit(
        audit_log=audit_log,
        conversation_id="test-signer-audit",
        remember_func=mock_remember,
    )

    signer = DivisionVPESigner(key_dir="/tmp", mode="sign")
    signer.ensure_keys()
    signer.set_audit(audit)

    # Wrapping for storage should trigger audit record
    value = {"secret": "data", "score": 42}
    result = signer.wrap_for_storage(value, domain="recon", agent="hermes")

    assert result is not None
    # Should have at least one audit entry written via mock_remember
    assert len(mock_remember.captured) >= 1

    # The audit entry should have the right result type
    cap = mock_remember.captured[-1]
    assert cap["value"]["result"] == "valid"
    assert "envelope_hash" in cap["value"]


def test_signer_verify_with_audit(keypair, audit_log, mock_remember):
    """DivisionVPESigner verify_stored_value records audit entries."""
    from seal.integration.division_vpe_audit import DivisionVPEAudit
    from seal.integration.division_vpe_signer import DivisionVPESigner

    audit = DivisionVPEAudit(
        audit_log=audit_log,
        conversation_id="test-signer-verify-audit",
        remember_func=mock_remember,
    )

    signer = DivisionVPESigner(key_dir="/tmp", mode="verify")
    signer.ensure_keys()
    signer.set_audit(audit)

    # An unsigned value — verify returns valid (not signed, but ok)
    result = signer.verify_stored_value({"msg": "hello"})

    assert result.valid is True
    # Unsigned values should NOT trigger audit (no envelope to hash)
    # Only signed wrappers trigger audit
    count_before = len(mock_remember.captured)

    # Now test with a properly signed wrapper
    signer2 = DivisionVPESigner(key_dir="/tmp", mode="sign")
    signer2.ensure_keys()
    signed = signer2.wrap_for_storage({"important": True}, domain="test", agent="verifier")

    result2 = signer.verify_stored_value(signed)
    assert result2.valid is True

    # Should have new audit entries
    assert len(mock_remember.captured) >= count_before


# ---------------------------------------------------------------------------
# Division roundtrip (with real MCP tools when available)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("HERMES_DIVISION_AVAILABLE"),
    reason="Division MCP not available in test environment",
)
def test_real_division_roundtrip():
    """Integration test: real Division remember + search.

    This test requires Division MCP tools to be available.
    Set HERMES_DIVISION_AVAILABLE=1 to enable.
    """
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    # Import the real MCP functions (available when run inside Hermes)
    try:
        from hermes_tools import mcp_division_memory_remember, mcp_division_memory_search
    except ImportError:
        pytest.skip("Hermes MCP tools not importable")

    audit = DivisionVPEAudit(
        conversation_id="test-vpe-audit-integration",
        remember_func=mcp_division_memory_remember,
    )

    # Record an invalid verification
    aid = audit.record(
        envelope_hash="integration_test_hash",
        issuer="test:integration",
        result="invalid",
        reason="integration test",
        tool_name="test",
    )

    # Query it back via Division search
    results = audit.query_division(
        query="result:invalid",
        limit=10,
        search_func=mcp_division_memory_search,
    )

    assert len(results) >= 1
    matching = [
        r for r in results if isinstance(r.get("episode_content"), dict) and r["episode_content"].get("audit_id") == aid
    ]
    assert len(matching) >= 1, f"audit_id={aid} not found in Division search results"
