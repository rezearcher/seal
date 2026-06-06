"""Tests for seal.audit."""

from __future__ import annotations

import json
import os
import stat

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

    with open(path, "r", encoding="utf-8") as fh:
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
