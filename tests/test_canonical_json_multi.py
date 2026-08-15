"""Tests for seal.core._canonical_json_multi — multi-sig canonical serialization.

Asserts that multi-sig canonicalization delegates the 11 shared envelope
fields to the shared ``_canonical_json`` (same defaults, same cert_chain
omission when None) and appends ``threshold`` immediately after.
"""

import json

from seal.core import (
    _canonical_json,
    _canonical_json_multi,
    generate_key_pair,
    vpe_sign_multi,
    vpe_verify_multi,
)


def _make_envelope(**overrides):
    base = {
        "vpe_version": "1.0",
        "prompt": "multi-sig test",
        "scope": {"z": 1, "a": 2},
        "issuer": "user:alice",
        "audience": "agent:bob",
        "doc_sha256": "abc123",
        "iat": 1700000000,
        "ttl_seconds": 300,
        "nonce": "deadbeef",
        "counter": 1,
        "cert_chain": None,
        "threshold": 2,
        "signatures": [],
    }
    base.update(overrides)
    return base


class TestCanonicalJsonMulti:
    def test_delegates_shared_fields_and_appends_threshold(self):
        env = _make_envelope()
        multi = _canonical_json_multi(env)
        shared = _canonical_json(env)
        # cert_chain is None -> omitted from both single- and multi-sig output
        assert b"cert_chain" not in multi
        assert b"cert_chain" not in shared
        # multi-sig output == shared canonical bytes + threshold appended after
        assert multi == shared[:-1] + b',"threshold":2}'
        assert multi.decode().endswith(',"threshold":2}')

    def test_cert_chain_none_omitted(self):
        env = _make_envelope(cert_chain=None)
        raw = _canonical_json_multi(env).decode("utf-8")
        assert "cert_chain" not in raw

    def test_cert_chain_present_serialized(self):
        chain = [{"subject_public_key": "abcd"}]
        env = _make_envelope(cert_chain=chain)
        raw = _canonical_json_multi(env).decode("utf-8")
        assert '"cert_chain":[{"subject_public_key":"abcd"}]' in raw

    def test_threshold_none_omitted(self):
        env = _make_envelope(threshold=None)
        raw = _canonical_json_multi(env).decode("utf-8")
        assert "threshold" not in raw

    def test_scope_keys_sorted(self):
        raw = _canonical_json_multi(_make_envelope()).decode("utf-8")
        assert '"scope":{"a":2,"z":1}' in raw

    def test_shared_field_values_match_single_sig(self):
        env = _make_envelope()
        multi = json.loads(_canonical_json_multi(env))
        shared = json.loads(_canonical_json(env))
        for key, value in shared.items():
            assert multi[key] == value, f"shared field {key!r} diverged"
        assert multi["threshold"] == env["threshold"]
        assert list(multi)[-1] == "threshold"


class TestMultiSigRoundTrip:
    def test_sign_multi_verify_multi_round_trip(self):
        keys = [generate_key_pair() for _ in range(3)]
        env = vpe_sign_multi(
            "multi-sig test",
            scope={"a": 1},
            issuer="user:alice",
            audience="agent:bob",
            threshold=2,
            private_key=keys[0]["private_key"],
            key_id="alice",
        )
        env = vpe_sign_multi(
            "multi-sig test",
            scope={"a": 1},
            issuer="user:alice",
            audience="agent:bob",
            threshold=2,
            private_key=keys[1]["private_key"],
            key_id="bob",
            existing_envelope=env,
        )
        result = vpe_verify_multi(
            env,
            public_keys={"alice": keys[0]["public_key"], "bob": keys[1]["public_key"]},
        )
        assert result["valid"] is True
        assert result["details"]["valid_signatures"] == ["alice", "bob"]
