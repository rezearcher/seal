"""Tests for seal.audit."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta

import pytest

from seal.audit import AuditLog


@pytest.fixture
def audit_path(tmp_path):
    return str(tmp_path / "audit.jsonl")


def test_log_and_query(audit_path):
    log = AuditLog(audit_path)
    log.log_access("api_key", "agent:hermes", action="get")
    log.log_denial("missing", "agent:hermes")

    entries = log.query()
    assert len(entries) == 2
    assert entries[0]["label"] == "api_key"
    assert entries[0]["result"] == "granted"
    assert entries[0]["action"] == "get"
    assert "timestamp" in entries[0]
    assert entries[1]["result"] == "denied"
    assert entries[1]["reason"] == "label_not_found"


def test_query_missing_file_returns_empty(tmp_path):
    log = AuditLog(str(tmp_path / "nope.jsonl"))
    assert log.query() == []


def test_filter_by_label(audit_path):
    log = AuditLog(audit_path)
    log.log_access("alpha", "c1")
    log.log_access("beta", "c1")
    log.log_access("alpha", "c2")

    alpha = log.query(label="alpha")
    assert len(alpha) == 2
    assert all(e["label"] == "alpha" for e in alpha)


def test_query_limit(audit_path):
    log = AuditLog(audit_path)
    for i in range(10):
        log.log_access(f"k{i}", "c")
    recent = log.query(limit=3)
    assert len(recent) == 3
    # Newest last: the final three written.
    assert [e["label"] for e in recent] == ["k7", "k8", "k9"]


def test_rotation(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path, max_entries=10000)
    for i in range(10001):
        log.log_access(f"k{i}", "c")

    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    assert len(lines) == 10000

    # Oldest (k0) pruned; newest (k10000) retained.
    first = json.loads(lines[0])
    last = json.loads(lines[-1])
    assert first["label"] == "k1"
    assert last["label"] == "k10000"


def test_file_permissions_0600(audit_path):
    log = AuditLog(audit_path)
    log.log_access("a", "c")
    mode = stat.S_IMODE(os.stat(audit_path).st_mode)
    assert mode == 0o600


def test_entry_schema(audit_path):
    log = AuditLog(audit_path)
    log.log_access("lbl", "caller-x", action="set")
    entry = log.query()[0]
    assert set(entry) >= {"timestamp", "label", "caller", "action", "result"}
    assert entry["caller"] == "caller-x"
    assert entry["action"] == "set"
    assert entry["result"] == "granted"


# --------------------------------------------------------------------- VPE


def test_vpe_verification_entry(audit_path):
    """VPE audit entry has correct schema."""
    log = AuditLog(audit_path)
    log.log_vpe_verification(
        "sha256:abc123def456",
        "user:rez",
        "agent:hermes-default",
        "valid",
    )
    entry = log.query()[0]
    assert set(entry) >= {
        "timestamp",
        "type",
        "envelope_hash",
        "issuer",
        "audience",
        "result",
        "reason",
    }
    assert entry["type"] == "vpe_verification"
    assert entry["envelope_hash"] == "sha256:abc123def456"
    assert entry["issuer"] == "user:rez"
    assert entry["audience"] == "agent:hermes-default"
    assert entry["result"] == "valid"
    assert entry["reason"] == ""


def test_vpe_query_by_status(audit_path):
    """Query filtered by valid/invalid/expired."""
    log = AuditLog(audit_path)
    log.log_vpe_verification("sha256:a", "user:rez", "agent:h", "valid")
    log.log_vpe_verification("sha256:b", "user:rez", "agent:h", "invalid", "bad sig")
    log.log_vpe_verification("sha256:c", "user:rez", "agent:h", "expired", "ttl")
    log.log_vpe_verification("sha256:d", "user:rez", "agent:h", "valid")

    valid = log.query(status="valid")
    assert len(valid) == 2
    assert all(e["result"] == "valid" for e in valid)

    invalid = log.query(status="invalid")
    assert len(invalid) == 1
    assert invalid[0]["envelope_hash"] == "sha256:b"

    expired = log.query(status="expired")
    assert len(expired) == 1
    assert expired[0]["reason"] == "ttl"


def test_vpe_query_by_since(audit_path):
    """Query filtered by time range."""
    log = AuditLog(audit_path)
    old_ts = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    # Pre-seed an older entry directly, then add a current one via the API.
    with open(audit_path, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "timestamp": old_ts,
                    "type": "vpe_verification",
                    "envelope_hash": "sha256:old",
                    "issuer": "user:rez",
                    "audience": "agent:h",
                    "result": "valid",
                    "reason": "",
                }
            )
            + "\n"
        )
    log.log_vpe_verification("sha256:new", "user:rez", "agent:h", "valid")

    cutoff = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    recent = log.query(since=cutoff)
    assert len(recent) == 1
    assert recent[0]["envelope_hash"] == "sha256:new"

    # No cutoff returns both entries.
    assert len(log.query()) == 2


def test_vpe_query_by_status_and_since(audit_path):
    """Combined status + since filter."""
    log = AuditLog(audit_path)
    old_valid = (datetime.now(UTC) - timedelta(hours=3)).isoformat()
    old_invalid = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    with open(audit_path, "w", encoding="utf-8") as fh:
        for ts, hsh, result in [
            (old_valid, "sha256:oldvalid", "valid"),
            (old_invalid, "sha256:oldinvalid", "invalid"),
        ]:
            fh.write(
                json.dumps(
                    {
                        "timestamp": ts,
                        "type": "vpe_verification",
                        "envelope_hash": hsh,
                        "issuer": "user:rez",
                        "audience": "agent:h",
                        "result": result,
                        "reason": "",
                    }
                )
                + "\n"
            )
    # Two current entries: one valid, one invalid.
    log.log_vpe_verification("sha256:newvalid", "user:rez", "agent:h", "valid")
    log.log_vpe_verification("sha256:newinvalid", "user:rez", "agent:h", "invalid")

    cutoff = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    result = log.query(status="valid", since=cutoff)
    assert len(result) == 1
    assert result[0]["envelope_hash"] == "sha256:newvalid"


def test_time_based_rotation(tmp_path):
    """Entries older than max_age_days are pruned on rotation."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path), max_age_days=30)
    old_ts = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    recent_ts = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"timestamp": old_ts, "type": "vpe_verification", "result": "valid"}) + "\n")
        fh.write(json.dumps({"timestamp": recent_ts, "type": "vpe_verification", "result": "valid"}) + "\n")
    # Appending triggers _rotate_locked, which prunes the 40-day-old entry.
    log.log_vpe_verification("sha256:fresh", "user:rez", "agent:h", "valid")

    entries = log.query()
    timestamps = [e["timestamp"] for e in entries]
    assert old_ts not in timestamps
    assert recent_ts in timestamps
    assert len(entries) == 2

    # max_age_days=0 prunes everything older than "now" — i.e. all of it.
    log0 = AuditLog(str(tmp_path / "audit0.jsonl"), max_age_days=0)
    log0.log_vpe_verification("sha256:x", "user:rez", "agent:h", "valid")
    assert log0.query() == []
