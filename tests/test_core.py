"""Tests for seal.core: signing, verification, tamper detection."""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import json
import time

import pytest

from seal.core import (
    VPE_VERSION,
    create_certificate,
    generate_key_pair,
    verify_cert_chain,
    verify_certificate,
    vpe_sign,
    vpe_sign_hmac,
    vpe_sign_multi,
    vpe_verify,
    vpe_verify_hmac,
    vpe_verify_multi,
)
from seal.store import NonceStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keys():
    return generate_key_pair()


@pytest.fixture
def hmac_secret():
    return b"donkeykong_test_secret_2026"


# ---------------------------------------------------------------------------
# Canonical JSON serialization (P5.3a)
# ---------------------------------------------------------------------------


class TestCanonicalJSON:
    """Direct tests for ``_canonical_json()`` — compact separators, determinism, field ordering."""

    def _make_envelope(self, **overrides):
        base = {
            "vpe_version": "1.0",
            "prompt": "hello",
            "scope": {},
            "issuer": "",
            "audience": "",
            "doc_sha256": "",
            "ttl_seconds": 300,
            "nonce": "abc",
            "counter": None,
            "cert_chain": None,
        }
        base.update(overrides)
        return base

    def test_compact_no_whitespace(self):
        """Canonical JSON must use separators=(',',':') — no extra spaces or newlines."""
        from seal.core import _canonical_json

        env = self._make_envelope()
        raw = _canonical_json(env).decode("utf-8")
        assert " " not in raw, f"unexpected whitespace in {raw!r}"
        assert "\n" not in raw
        # Verify separators directly
        assert ": " not in raw, "space after colon detected"
        assert ", " not in raw, "space after comma detected"

    def test_deterministic(self):
        """Same input must produce identical bytes every call."""
        from seal.core import _canonical_json

        env = self._make_envelope()
        assert _canonical_json(env) == _canonical_json(env)

    def test_field_ordering(self):
        """Output fields must follow _ENVELOPE_FIELDS order (minus signature, minus omitted None)."""
        from seal.core import _ENVELOPE_FIELDS, _canonical_json

        env = self._make_envelope()
        raw = _canonical_json(env).decode("utf-8")
        # Parse JSON and extract top-level keys in order
        import json

        top_keys = list(json.loads(raw).keys())
        # cert_chain=None is omitted, so it won't appear
        expected = [f for f in _ENVELOPE_FIELDS if f not in ("signature", "cert_chain")]
        assert top_keys == expected, (
            f"expected field order {expected}, got {top_keys}"
        )

    def test_field_ordering_with_cert_chain(self):
        """When cert_chain is present, it appears as the last field in canonical form."""
        from seal.core import _ENVELOPE_FIELDS, _canonical_json

        env = self._make_envelope(cert_chain=[{"subject_id": "leaf"}])
        raw = _canonical_json(env).decode("utf-8")
        import json

        top_keys = list(json.loads(raw).keys())
        expected = [f for f in _ENVELOPE_FIELDS if f != "signature"]
        assert top_keys == expected, (
            f"expected field order {expected}, got {top_keys}"
        )

    def test_scope_keys_sorted(self):
        """Scope dict keys must be sorted alphabetically in canonical form."""
        from seal.core import _canonical_json

        env = self._make_envelope(scope={"z": 1, "a": 2, "m": 3})
        raw = _canonical_json(env).decode("utf-8")
        # scope section should have a,m,z
        import re

        scope_match = re.search(r'"scope":(\{[^}]+\})', raw)
        assert scope_match, "scope not found in output"
        scope_raw = scope_match.group(1)
        assert scope_raw == '{"a":2,"m":3,"z":1}', (
            f"scope not sorted, got {scope_raw}"
        )

    def test_cert_chain_included_when_present(self):
        """cert_chain must appear in canonical output when it has a value."""
        from seal.core import _canonical_json

        env = self._make_envelope(cert_chain=[{"subject_id": "leaf"}])
        raw = _canonical_json(env).decode("utf-8")
        assert "cert_chain" in raw

    def test_cert_chain_omitted_when_none(self):
        """cert_chain must be omitted from canonical output when None."""
        from seal.core import _canonical_json

        env = self._make_envelope(cert_chain=None)
        raw = _canonical_json(env).decode("utf-8")
        assert "cert_chain" not in raw

    def test_missing_keys_resolve_to_defaults(self):
        """Missing envelope fields must use canonical defaults without error."""
        from seal.core import _canonical_json

        env = {"prompt": "hello"}  # only minimal fields
        # Should not raise
        raw = _canonical_json(env).decode("utf-8")
        assert "prompt" in raw
        assert "scope" in raw  # default is {}
        assert "nonce" in raw  # default is ""

    def test_counter_none_produces_null(self):
        """counter=None must produce JSON null, not omitted."""
        from seal.core import _canonical_json

        env = self._make_envelope(counter=None)
        raw = _canonical_json(env).decode("utf-8")
        assert '"counter":null' in raw

    def test_compact_lightweight_overhead(self):
        """Canonical overhead must stay under 200B for short prompts."""
        from seal.core import _canonical_json

        for plen, expected_max in [(1, 200), (50, 250)]:
            env = self._make_envelope(prompt="X" * plen)
            overhead = len(_canonical_json(env))
            assert overhead < expected_max, (
                f"plen={plen}: overhead={overhead}B ≥ {expected_max}B"
            )


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    def test_generates_32_byte_keys(self, keys):
        assert len(keys["private_key"]) == 32
        assert len(keys["public_key"]) == 32

    def test_keys_are_different(self, keys):
        assert keys["private_key"] != keys["public_key"]

    def test_consecutive_calls_differ(self):
        a = generate_key_pair()
        b = generate_key_pair()
        assert a["private_key"] != b["private_key"]
        assert a["public_key"] != b["public_key"]


# ---------------------------------------------------------------------------
# Basic signing (Ed25519)
# ---------------------------------------------------------------------------


class TestSigning:
    def test_sign_returns_json_string(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        assert isinstance(env, str)

    def test_envelope_contains_all_fields(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        data = json.loads(env)
        expected = {"vpe_version", "prompt", "scope", "issuer", "audience",
                    "doc_sha256", "iat", "ttl_seconds", "nonce", "counter",
                    "cert_chain", "signature"}
        assert set(data.keys()) == expected

    def test_version_is_current(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        assert env["vpe_version"] == VPE_VERSION

    def test_signature_is_hex_string(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        sig = env["signature"]
        assert isinstance(sig, str)
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signature_is_64_bytes_ed25519(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        sig = env["signature"]
        assert len(sig) == 128, f"expected 128 hex chars, got {len(sig)}"

    def test_prompt_is_preserved(self, keys):
        env = json.loads(vpe_sign("my specific prompt", private_key=keys["private_key"]))
        assert env["prompt"] == "my specific prompt"

    def test_scope_is_preserved(self, keys):
        scope = {"allowed_tools": ["search", "read_file"]}
        env = json.loads(vpe_sign("test", scope=scope, private_key=keys["private_key"]))
        assert env["scope"] == scope

    def test_different_prompts_different_signatures(self, keys):
        e1 = vpe_sign("hello", private_key=keys["private_key"])
        e2 = vpe_sign("world", private_key=keys["private_key"])
        assert json.loads(e1)["signature"] != json.loads(e2)["signature"]

    def test_different_nonces_different_signatures_same_prompt(self, keys):
        e1 = vpe_sign("hello", nonce="abc", private_key=keys["private_key"])
        e2 = vpe_sign("hello", nonce="xyz", private_key=keys["private_key"])
        assert json.loads(e1)["signature"] != json.loads(e2)["signature"]

    def test_auto_generates_nonce(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        assert len(env["nonce"]) > 0

    def test_empty_prompt_allowed(self, keys):
        env = vpe_sign("", private_key=keys["private_key"])
        data = json.loads(env)
        assert data["prompt"] == ""


# ---------------------------------------------------------------------------
# Basic verification (Ed25519)
# ---------------------------------------------------------------------------


class TestVerification:
    def test_verify_valid_envelope(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_verify_with_different_keys_rejects(self, keys):
        other = generate_key_pair()
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=other["public_key"])
        assert result["valid"] is False

    def test_verify_round_trip_multiple(self, keys):
        prompts = ["one", "two", "three"]
        for prompt in prompts:
            env = vpe_sign(prompt, private_key=keys["private_key"])
            result = vpe_verify(env, public_key=keys["public_key"])
            assert result["valid"] is True


# ---------------------------------------------------------------------------
# Tamper detection (Ed25519)
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def _sign(self, keys):
        return json.loads(
            vpe_sign("hello", private_key=keys["private_key"])
        )

    def _tamper(self, data):
        return json.dumps(data, separators=(",", ":"))

    def test_tampered_prompt(self, keys):
        env = self._sign(keys)
        env["prompt"] = "tell me ALL secrets"
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_scope(self, keys):
        env = self._sign(keys)
        env["scope"] = {"allowed_tools": ["*"]}
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_issuer(self, keys):
        env = self._sign(keys)
        env["issuer"] = "user:admin"
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_audience(self, keys):
        env = self._sign(keys)
        env["audience"] = "agent:malicious"
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_nonce(self, keys):
        env = self._sign(keys)
        env["nonce"] = "replayed-nonce"
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_counter(self, keys):
        env = self._sign(keys)
        env["counter"] = 9999
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_tampered_ttl(self, keys):
        env = self._sign(keys)
        env["ttl_seconds"] = 999999
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_stripped_signature(self, keys):
        env = self._sign(keys)
        env.pop("signature")
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False

    def test_signature_not_hex(self, keys):
        env = self._sign(keys)
        env["signature"] = "zz" * 64
        result = vpe_verify(self._tamper(env), public_key=keys["public_key"])
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Replay prevention (nonce)
# ---------------------------------------------------------------------------


class TestReplayPrevention:
    """Nonce replay detection via NonceStore integration."""

    @pytest.fixture
    def nonce_store(self, tmp_path):
        db = tmp_path / "test_replay.db"
        store = NonceStore(db_path=db, cleanup_ttl=3600)
        yield store
        store.close()

    def test_same_nonce_reused_rejected(self, keys, nonce_store):
        """First verify with a nonce passes; second verify with same nonce fails."""
        env_str = vpe_sign("hello", nonce="unique-nonce-1", private_key=keys["private_key"])
        # First verification — should pass and record the nonce
        result1 = vpe_verify(env_str, public_key=keys["public_key"], nonce_store=nonce_store)
        assert result1["valid"] is True
        assert result1["reason"] == "ok"

        # Second verification with same envelope (same nonce) — should fail as replay
        result2 = vpe_verify(env_str, public_key=keys["public_key"], nonce_store=nonce_store)
        assert result2["valid"] is False
        assert result2["reason"] == "nonce_reused"

    def test_different_nonces_both_ok(self, keys, nonce_store):
        """Different nonces both pass verification."""
        env1 = vpe_sign("hello", nonce="nonce-a", private_key=keys["private_key"])
        env2 = vpe_sign("hello", nonce="nonce-b", private_key=keys["private_key"])
        assert vpe_verify(env1, public_key=keys["public_key"], nonce_store=nonce_store)["valid"] is True
        assert vpe_verify(env2, public_key=keys["public_key"], nonce_store=nonce_store)["valid"] is True

    def test_no_nonce_store_skips_replay_check(self, keys):
        """Without a nonce_store, same nonce can be verified multiple times (backward compat)."""
        env = vpe_sign("hello", nonce="compat-nonce", private_key=keys["private_key"])
        result1 = vpe_verify(env, public_key=keys["public_key"])
        assert result1["valid"] is True
        result2 = vpe_verify(env, public_key=keys["public_key"])
        assert result2["valid"] is True

    def test_ttl_zero_skips_replay_check(self, keys, nonce_store):
        """When ttl=0, replay check is skipped (no time window for replay)."""
        env = vpe_sign("hello", nonce="ttlzero-nonce", ttl_seconds=0, private_key=keys["private_key"])
        result1 = vpe_verify(env, public_key=keys["public_key"], nonce_store=nonce_store)
        assert result1["valid"] is True
        result2 = vpe_verify(env, public_key=keys["public_key"], nonce_store=nonce_store)
        assert result2["valid"] is True

    def test_missing_nonce_rejected(self, keys):
        env = json.loads(
            vpe_sign("hello", private_key=keys["private_key"])
        )
        env.pop("nonce")
        result = vpe_verify(
            json.dumps(env, separators=(",", ":")), public_key=keys["public_key"]
        )
        assert result["valid"] is False

    def test_empty_nonce_rejected(self, keys):
        env = vpe_sign("hello", nonce="", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is False

    def test_nonce_is_string(self, keys):
        env = json.loads(vpe_sign("hello", nonce="abc", private_key=keys["private_key"]))
        assert isinstance(env["nonce"], str)


# ---------------------------------------------------------------------------
# Counter
# ---------------------------------------------------------------------------


class TestCounterSkip:
    def test_counter_accepted_when_present(self, keys):
        env = vpe_sign("hello", counter=42, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_counter_optional(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_counter_tampered(self, keys):
        env = json.loads(vpe_sign("hello", counter=42, private_key=keys["private_key"]))
        env["counter"] = 99
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify(tampered, public_key=keys["public_key"])
        assert result["valid"] is False

    def test_counter_non_integer_rejected(self, keys):
        env = json.loads(vpe_sign("hello", counter=42, private_key=keys["private_key"]))
        env["counter"] = "not-an-int"
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify(tampered, public_key=keys["public_key"])
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class TestScopeViolation:
    def test_scope_must_be_dict(self, keys):
        env = json.loads(
            vpe_sign("hello", scope={"a": 1}, private_key=keys["private_key"])
        )
        env["scope"] = "not-a-dict"
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify(tampered, public_key=keys["public_key"])
        assert result["valid"] is False

    def test_scope_verifies_when_valid(self, keys):
        scope = {"allowed_tools": ["read_file"]}
        env = vpe_sign("hello", scope=scope, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_empty_scope_allowed(self, keys):
        env = vpe_sign("hello", scope={}, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Scope & field escalation attacks
# ---------------------------------------------------------------------------


class TestScopeEscalation:
    """Every test mutates one field after signing and expects verification to fail."""

    def _sign(self, keys):
        return json.loads(
            vpe_sign(
                "search for customer X",
                scope={"allowed_tools": ["search"], "max_tokens": 2000},
                issuer="user:alice",
                audience="agent:hermes-default",
                ttl_seconds=300,
                private_key=keys["private_key"],
            )
        )

    def _tamper(self, data):
        return json.dumps(data, separators=(",", ":"))

    def _verify(self, tampered_str, keys):
        return vpe_verify(tampered_str, public_key=keys["public_key"])

    def test_scope_entirely_replaced_after_signing(self, keys):
        env = self._sign(keys)
        env["scope"] = {"allowed_tools": ["*"]}
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_restrictions_removed_emptied(self, keys):
        env = self._sign(keys)
        env["scope"] = {}
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_allowed_tools_popped(self, keys):
        env = self._sign(keys)
        env["scope"] = {"allowed_tools": []}
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_max_tokens_inflated(self, keys):
        env = self._sign(keys)
        env["scope"] = {"allowed_tools": ["search"], "max_tokens": 999999}
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_extra_domains_injected(self, keys):
        env = self._sign(keys)
        env["scope"]["allowed_domains"] = ["*.evil.com"]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_as_null(self, keys):
        env = self._sign(keys)
        env["scope"] = None
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_as_list(self, keys):
        env = self._sign(keys)
        env["scope"] = [1, 2, 3]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_extra_tools_appended(self, keys):
        env = self._sign(keys)
        env["scope"]["allowed_tools"] = ["search", "delete_all"]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_extra_tools_prepended(self, keys):
        env = self._sign(keys)
        env["scope"]["allowed_tools"] = ["delete_all", "search"]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_all_wildcard_tools(self, keys):
        env = self._sign(keys)
        env["scope"]["allowed_tools"] = ["*"]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_ttl_extended_long(self, keys):
        env = self._sign(keys)
        env["ttl_seconds"] = 86400 * 365
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_ttl_extended_to_infinite(self, keys):
        env = self._sign(keys)
        env["ttl_seconds"] = 0
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_ttl_extended_negative(self, keys):
        env = self._sign(keys)
        env["ttl_seconds"] = -1
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_audience_redirected(self, keys):
        env = self._sign(keys)
        env["audience"] = "agent:malicious-actor"
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_issuer_spoofed(self, keys):
        env = self._sign(keys)
        env["issuer"] = "user:admin"
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_audience_and_issuer_swapped(self, keys):
        env = self._sign(keys)
        env["audience"], env["issuer"] = env["issuer"], env["audience"]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_multi_field_escalation(self, keys):
        env = self._sign(keys)
        env["scope"] = {"allowed_tools": ["*"]}
        env["ttl_seconds"] = 999999
        env["audience"] = "agent:eve"
        env["issuer"] = "user:eve"
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_scope_cert_chain_injected(self, keys):
        """Injecting a cert_chain to try hierarchical key escalation."""
        env = self._sign(keys)
        env["cert_chain"] = [
            {
                "subject_id": "ca:attacker-root",
                "subject_public_key": "00" * 32,
                "issuer_id": "ca:attacker-root",
                "issuer_public_key": "00" * 32,
            }
        ]
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_doc_sha256_rewritten(self, keys):
        env = self._sign(keys)
        env["doc_sha256"] = "deadbeef" * 8
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False

    def test_vpe_version_downgrade(self, keys):
        env = self._sign(keys)
        env["vpe_version"] = "0.1"
        result = self._verify(self._tamper(env), keys)
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------


class TestTTL:
    def test_ttl_zero_means_no_expiry(self, keys):
        env = vpe_sign("hello", ttl_seconds=0, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_ttl_preserved_in_envelope(self, keys):
        env = json.loads(
            vpe_sign("hello", ttl_seconds=120, private_key=keys["private_key"])
        )
        assert env["ttl_seconds"] == 120

    def test_ttl_non_integer_rejected(self, keys):
        env = json.loads(
            vpe_sign("hello", ttl_seconds=120, private_key=keys["private_key"])
        )
        env["ttl_seconds"] = "not-an-int"
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify(tampered, public_key=keys["public_key"])
        assert result["valid"] is False

    def test_default_ttl_is_300(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        assert env["ttl_seconds"] == 300


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_invalid_json(self, keys):
        result = vpe_verify("not json", public_key=keys["public_key"])
        assert result["valid"] is False

    def test_json_not_dict(self, keys):
        result = vpe_verify("[]", public_key=keys["public_key"])
        assert result["valid"] is False

    def test_wrong_version(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        env["vpe_version"] = "0.9"
        result = vpe_verify(
            json.dumps(env, separators=(",", ":")), public_key=keys["public_key"]
        )
        assert result["valid"] is False

    def test_missing_signature_field(self, keys):
        env = json.loads(vpe_sign("hello", private_key=keys["private_key"]))
        env.pop("signature")
        result = vpe_verify(
            json.dumps(env, separators=(",", ":")), public_key=keys["public_key"]
        )
        assert result["valid"] is False

    def test_long_prompt_round_trip(self, keys):
        prompt = "A" * 100_000
        env = vpe_sign(prompt, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_unicode_prompt(self, keys):
        prompt = "\u65e5\u672c\u8a9e \U0001f680"
        env = vpe_sign(prompt, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Key time constraints (not_before / not_after)
# ---------------------------------------------------------------------------


class TestKeyTimeConstraints:
    def test_not_before_rejects_early(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(
            env, public_key=keys["public_key"], not_before=int(time.time()) + 99999
        )
        assert result["valid"] is False
        assert "key_not_yet_valid" in result["reason"]

    def test_not_before_passes_when_valid(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(
            env, public_key=keys["public_key"], not_before=int(time.time()) - 99999
        )
        assert result["valid"] is True

    def test_not_after_rejects_expired(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(
            env, public_key=keys["public_key"], not_after=int(time.time()) - 1
        )
        assert result["valid"] is False
        assert "key_expired" in result["reason"]

    def test_not_after_passes_when_not_expired(self, keys):
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(
            env, public_key=keys["public_key"], not_after=int(time.time()) + 99999
        )
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------


class TestHMACSigning:
    def test_sign_returns_json_string(self, hmac_secret):
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        assert isinstance(env, str)

    def test_envelope_contains_all_fields(self, hmac_secret):
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        data = json.loads(env)
        expected = {"vpe_version", "prompt", "scope", "issuer", "audience",
                    "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "signature"}
        assert set(data.keys()) == expected

    def test_signature_is_32_bytes(self, hmac_secret):
        env = json.loads(vpe_sign_hmac("hello", shared_secret=hmac_secret))
        sig = env["signature"]
        # HMAC-SHA256 = 32 bytes = 64 hex chars
        assert len(sig) == 64

    def test_prompt_is_preserved(self, hmac_secret):
        env = json.loads(vpe_sign_hmac("hello wally", shared_secret=hmac_secret))
        assert env["prompt"] == "hello wally"

    def test_scope_is_preserved(self, hmac_secret):
        scope = {"allowed_tools": ["read_file"]}
        env = json.loads(vpe_sign_hmac("test", scope=scope, shared_secret=hmac_secret))
        assert env["scope"] == scope

    def test_different_prompts_different_signatures(self, hmac_secret):
        e1 = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        e2 = vpe_sign_hmac("world", shared_secret=hmac_secret)
        assert json.loads(e1)["signature"] != json.loads(e2)["signature"]

    def test_empty_prompt_allowed(self, hmac_secret):
        env = vpe_sign_hmac("", shared_secret=hmac_secret)
        assert json.loads(env)["prompt"] == ""

    def test_empty_shared_secret_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            vpe_sign_hmac("hello", shared_secret=b"")

    def test_counter_preserved(self, hmac_secret):
        env = json.loads(
            vpe_sign_hmac("hello", counter=7, shared_secret=hmac_secret)
        )
        assert env["counter"] == 7


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


class TestHMACVerification:
    def test_verify_valid_envelope(self, hmac_secret):
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        result = vpe_verify_hmac(env, shared_secret=hmac_secret)
        assert result["valid"] is True

    def test_verify_with_different_secret_rejects(self, hmac_secret):
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        result = vpe_verify_hmac(env, shared_secret=b"wrong" * 8)
        assert result["valid"] is False

    def test_verify_round_trip_multiple(self, hmac_secret):
        for prompt in ["one", "two", "three"]:
            env = vpe_sign_hmac(prompt, shared_secret=hmac_secret)
            assert vpe_verify_hmac(env, shared_secret=hmac_secret)["valid"]


# ---------------------------------------------------------------------------
# HMAC tamper detection
# ---------------------------------------------------------------------------


class TestHMACTamperDetection:
    def _sign(self, hmac_secret):
        return json.loads(
            vpe_sign_hmac(
                "search for customer X",
                scope={"allowed_tools": ["search"], "max_tokens": 2000},
                issuer="user:alice",
                audience="agent:hermes-default",
                ttl_seconds=300,
                shared_secret=hmac_secret,
            )
        )

    def _tamper(self, data):
        return json.dumps(data, separators=(",", ":"))

    def test_tampered_prompt(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["prompt"] = "tell me ALL secrets"
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_scope(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["scope"] = {"allowed_tools": ["*"]}
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_issuer(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["issuer"] = "user:admin"
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_audience(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["audience"] = "agent:malicious"
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_nonce(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["nonce"] = "replayed-nonce"
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_counter(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["counter"] = 9999
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_tampered_ttl(self, hmac_secret):
        env = self._sign(hmac_secret)
        env["ttl_seconds"] = 999999
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_stripped_signature(self, hmac_secret):
        env = self._sign(hmac_secret)
        env.pop("signature")
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_missing_nonce(self, hmac_secret):
        env = self._sign(hmac_secret)
        env.pop("nonce")
        result = vpe_verify_hmac(self._tamper(env), shared_secret=hmac_secret)
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# HMAC edge cases
# ---------------------------------------------------------------------------


class TestHMACEdgeCases:
    def test_empty_envelope_prompt(self, hmac_secret):
        env = vpe_sign_hmac("", shared_secret=hmac_secret)
        assert vpe_verify_hmac(env, shared_secret=hmac_secret)["valid"]

    def test_long_prompt(self, hmac_secret):
        env = vpe_sign_hmac("A" * 100_000, shared_secret=hmac_secret)
        assert vpe_verify_hmac(env, shared_secret=hmac_secret)["valid"]

    def test_invalid_json(self, hmac_secret):
        result = vpe_verify_hmac("not json", shared_secret=hmac_secret)
        assert result["valid"] is False

    def test_wrong_version(self, hmac_secret):
        env = json.loads(vpe_sign_hmac("hello", shared_secret=hmac_secret))
        env["vpe_version"] = "0.9"
        result = vpe_verify_hmac(
            json.dumps(env, separators=(",", ":")), shared_secret=hmac_secret
        )
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Multi-signature (N-of-M)
# ---------------------------------------------------------------------------


class TestMultiSign:
    @pytest.fixture
    def three_keys(self):
        return [generate_key_pair() for _ in range(3)]

    def test_first_signer_creates_envelope(self, three_keys):
        env = vpe_sign_multi(
            "multi-sig test",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=three_keys[0]["private_key"],
            key_id="alice",
        )
        data = json.loads(env)
        assert data["threshold"] == 2
        assert len(data["signatures"]) == 1

    def test_second_signer_appends(self, three_keys):
        env = vpe_sign_multi(
            "multi-sig test",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=three_keys[0]["private_key"],
            key_id="alice",
        )
        env2 = vpe_sign_multi(
            "multi-sig test",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=three_keys[1]["private_key"],
            key_id="bob",
            existing_envelope=env,
        )
        data = json.loads(env2)
        assert len(data["signatures"]) == 2

    def test_duplicate_key_id_rejected(self, three_keys):
        env = vpe_sign_multi(
            "multi-sig",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=three_keys[0]["private_key"],
            key_id="alice",
        )
        with pytest.raises(ValueError, match="already signed"):
            vpe_sign_multi(
                "multi-sig",
                scope={},
                issuer="user:test",
                audience="agent:test",
                threshold=2,
                private_key=three_keys[0]["private_key"],
                key_id="alice",
                existing_envelope=env,
            )


class TestMultiVerify:
    @pytest.fixture
    def three_keys(self):
        return [generate_key_pair() for _ in range(3)]

    def test_threshold_2_of_3(self, three_keys):
        k = three_keys
        env = vpe_sign_multi(
            "multi-sig test",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=k[0]["private_key"],
            key_id="alice",
        )
        env = vpe_sign_multi(
            "multi-sig test",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=2,
            private_key=k[1]["private_key"],
            key_id="bob",
            existing_envelope=env,
        )
        result = vpe_verify_multi(
            env,
            public_keys={"alice": k[0]["public_key"], "bob": k[1]["public_key"]},
        )
        assert result["valid"] is True

    def test_threshold_not_met(self, three_keys):
        k = three_keys
        env = vpe_sign_multi(
            "multi-sig",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=3,
            private_key=k[0]["private_key"],
            key_id="alice",
        )
        env = vpe_sign_multi(
            "multi-sig",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=3,
            private_key=k[1]["private_key"],
            key_id="bob",
            existing_envelope=env,
        )
        result = vpe_verify_multi(
            env,
            public_keys={"alice": k[0]["public_key"], "bob": k[1]["public_key"]},
        )
        assert result["valid"] is False
        assert "insufficient" in result["reason"]

    def test_wrong_public_key_rejected(self, three_keys):
        k = three_keys
        env = vpe_sign_multi(
            "multi-sig",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=1,
            private_key=k[0]["private_key"],
            key_id="alice",
        )
        result = vpe_verify_multi(
            env,
            public_keys={"alice": k[1]["public_key"]},
        )
        assert result["valid"] is False

    def test_unknown_key_id(self, three_keys):
        k = three_keys
        env = vpe_sign_multi(
            "multi-sig",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=1,
            private_key=k[0]["private_key"],
            key_id="alice",
        )
        result = vpe_verify_multi(
            env,
            public_keys={"unknown": k[0]["public_key"]},
        )
        assert result["valid"] is False
        assert "unknown" in result["reason"]

    def test_threshold_too_low_rejected(self, three_keys):
        k = three_keys
        with pytest.raises(ValueError, match="threshold"):
            vpe_sign_multi(
                "multi-sig",
                scope={},
                issuer="user:test",
                audience="agent:test",
                threshold=0,
                private_key=k[0]["private_key"],
                key_id="alice",
            )

    def test_missing_threshold_rejected(self, three_keys):
        k1 = three_keys[0]
        env = json.loads(vpe_sign_multi(
            prompt="missing threshold",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=1,
            private_key=k1["private_key"],
            key_id="alice",
        ))
        env.pop("threshold", None)
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify_multi(
            tampered,
            public_keys={"alice": k1["public_key"]},
        )
        assert result["valid"] is False

    def test_missing_signatures_array_rejected(self, three_keys):
        k1 = three_keys[0]
        env = json.loads(vpe_sign_multi(
            prompt="missing sigs",
            scope={},
            issuer="user:test",
            audience="agent:test",
            threshold=1,
            private_key=k1["private_key"],
            key_id="alice",
        ))
        env.pop("signatures")
        tampered = json.dumps(env, separators=(",", ":"))
        result = vpe_verify_multi(
            tampered,
            public_keys={"alice": k1["public_key"]},
        )
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Certificate chain — hierarchical key support (P9.1)
# ---------------------------------------------------------------------------


class TestCertificateChain:
    """Tests for root CA -> intermediate -> leaf cert chain operations."""

    def test_root_ca_self_signed_cert(self):
        """Root CA can generate a self-signed certificate."""
        ca_keys = generate_key_pair()
        cert = create_certificate(
            subject_public_key=ca_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=ca_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=ca_keys["public_key"],
            metadata={"ca": True},
        )
        assert cert["cert_version"] == "1.0"
        assert cert["subject_id"] == "ca:root"
        assert cert["issuer_id"] == "ca:root"
        assert cert["subject_public_key"] == ca_keys["public_key"].hex()
        assert cert["issuer_public_key"] == ca_keys["public_key"].hex()
        assert "signature" in cert
        assert len(cert["signature"]) == 128  # 64 bytes hex

    def test_verify_root_cert(self):
        """Self-signed root cert verifies against its own public key."""
        ca_keys = generate_key_pair()
        cert = create_certificate(
            subject_public_key=ca_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=ca_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=ca_keys["public_key"],
        )
        result = verify_certificate(cert, parent_public_key=ca_keys["public_key"])
        assert result["valid"] is True

    def test_reject_tampered_cert(self):
        """Tampered certificate fails verification."""
        ca_keys = generate_key_pair()
        cert = create_certificate(
            subject_public_key=ca_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=ca_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=ca_keys["public_key"],
        )
        cert["subject_id"] = "ca:evil-root"
        result = verify_certificate(cert, parent_public_key=ca_keys["public_key"])
        assert result["valid"] is False

    def test_full_chain_root_to_leaf(self):
        """Root -> intermediate -> leaf chain verifies successfully."""
        # Root CA
        root_keys = generate_key_pair()
        root_cert = create_certificate(
            subject_public_key=root_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
            metadata={"ca": True, "type": "root"},
        )

        # Intermediate signed by root
        interm_keys = generate_key_pair()
        interm_cert = create_certificate(
            subject_public_key=interm_keys["public_key"],
            subject_id="ca:intermediate",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
            metadata={"ca": True, "type": "intermediate"},
        )

        # Leaf signed by intermediate
        leaf_keys = generate_key_pair()
        leaf_cert = create_certificate(
            subject_public_key=leaf_keys["public_key"],
            subject_id="user:agent-leaf",
            issuer_private_key=interm_keys["private_key"],
            issuer_id="ca:intermediate",
            issuer_public_key=interm_keys["public_key"],
            metadata={"ca": False, "type": "leaf"},
        )

        chain = [root_cert, interm_cert, leaf_cert]
        result = verify_cert_chain(chain, trust_anchor=root_keys["public_key"])
        assert result["valid"] is True, f"chain failed: {result['reason']}"
        assert result["leaf_public_key"] == leaf_keys["public_key"]

    def test_broken_chain_rejected(self):
        """Chain with a broken link is rejected (intermediate signed by wrong key)."""
        root_keys = generate_key_pair()
        other_keys = generate_key_pair()
        root_cert = create_certificate(
            subject_public_key=root_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
        )

        leaf_keys = generate_key_pair()

        # Create an intermediate cert signed by other_keys (not root_keys)
        interm_cert = create_certificate(
            subject_public_key=other_keys["public_key"],
            subject_id="ca:intermediate",
            issuer_private_key=other_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=other_keys["public_key"],
        )

        # Leaf signed by interm's key
        leaf_cert = create_certificate(
            subject_public_key=leaf_keys["public_key"],
            subject_id="user:leaf",
            issuer_private_key=other_keys["private_key"],
            issuer_id="ca:intermediate",
            issuer_public_key=other_keys["public_key"],
        )

        chain = [root_cert, interm_cert, leaf_cert]
        result = verify_cert_chain(chain, trust_anchor=root_keys["public_key"])
        # interm_cert was signed by other_keys, not root_keys — chain link 1 fails
        assert result["valid"] is False
        assert "chain_link_1_failed" in result["reason"]

    def test_empty_chain_rejected(self):
        """Empty chain is rejected."""
        result = verify_cert_chain([], trust_anchor=b"\x00" * 32)
        assert result["valid"] is False

    def test_chain_wrong_trust_anchor_rejected(self):
        """Chain with wrong trust anchor is rejected."""
        root_keys = generate_key_pair()
        root_cert = create_certificate(
            subject_public_key=root_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
        )
        wrong_anchor = generate_key_pair()["public_key"]
        result = verify_cert_chain([root_cert], trust_anchor=wrong_anchor)
        assert result["valid"] is False
        assert "trust_anchor" in result["reason"]

    def test_cert_time_validity(self):
        """not_before / not_after are respected in cert creation."""
        ca_keys = generate_key_pair()
        now = int(time.time())
        cert = create_certificate(
            subject_public_key=ca_keys["public_key"],
            subject_id="ca:test",
            issuer_private_key=ca_keys["private_key"],
            issuer_id="ca:test",
            issuer_public_key=ca_keys["public_key"],
            not_before=now - 3600,
            not_after=now + 3600,
        )
        assert cert["not_before"] == now - 3600
        assert cert["not_after"] == now + 3600


# ---------------------------------------------------------------------------
# Envelope with cert chain
# ---------------------------------------------------------------------------


class TestEnvelopeCertChain:
    """Tests for VPE envelopes signed with hierarchical key cert chains."""

    @pytest.fixture
    def cert_chain(self):
        """Build root -> intermediate -> leaf chain for signing."""
        root_keys = generate_key_pair()
        root_cert = create_certificate(
            subject_public_key=root_keys["public_key"],
            subject_id="ca:root",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
            metadata={"ca": True, "type": "root"},
        )

        interm_keys = generate_key_pair()
        interm_cert = create_certificate(
            subject_public_key=interm_keys["public_key"],
            subject_id="ca:intermediate",
            issuer_private_key=root_keys["private_key"],
            issuer_id="ca:root",
            issuer_public_key=root_keys["public_key"],
            metadata={"ca": True, "type": "intermediate"},
        )

        leaf_keys = generate_key_pair()
        leaf_cert = create_certificate(
            subject_public_key=leaf_keys["public_key"],
            subject_id="user:agent-leaf",
            issuer_private_key=interm_keys["private_key"],
            issuer_id="ca:intermediate",
            issuer_public_key=interm_keys["public_key"],
            metadata={"ca": False, "type": "leaf"},
        )

        chain = [root_cert, interm_cert, leaf_cert]
        return {
            "chain": chain,
            "root_public_key": root_keys["public_key"],
            "leaf_private_key": leaf_keys["private_key"],
            "leaf_public_key": leaf_keys["public_key"],
        }

    def test_sign_with_cert_chain(self, cert_chain):
        """Sign an envelope with a cert chain included."""
        env = vpe_sign(
            "prompt from certified agent",
            issuer="user:agent-leaf",
            audience="agent:hermes",
            private_key=cert_chain["leaf_private_key"],
            cert_chain=cert_chain["chain"],
        )
        data = json.loads(env)
        assert data["cert_chain"] is not None
        assert len(data["cert_chain"]) == 3

    def test_verify_with_trust_anchor(self, cert_chain):
        """Verify an envelope signed with a cert chain using trust anchor."""
        env = vpe_sign(
            "prompt from certified agent",
            issuer="user:agent-leaf",
            audience="agent:hermes",
            private_key=cert_chain["leaf_private_key"],
            cert_chain=cert_chain["chain"],
        )
        result = vpe_verify(env, trust_anchor=cert_chain["root_public_key"])
        assert result["valid"] is True, f"verify failed: {result['reason']}"

    def test_verify_without_key_returns_error(self, cert_chain):
        """Without trust_anchor or public_key, verify returns error."""
        env = vpe_sign(
            "prompt",
            private_key=cert_chain["leaf_private_key"],
            cert_chain=cert_chain["chain"],
        )
        result = vpe_verify(env)
        assert result["valid"] is False
        assert "no_verification_key" in result["reason"]

    def test_broken_cert_chain_in_envelope_rejected(self, cert_chain):
        """Envelope with a tampered cert chain is rejected."""
        env = vpe_sign(
            "prompt",
            private_key=cert_chain["leaf_private_key"],
            cert_chain=cert_chain["chain"],
        )
        data = json.loads(env)
        data["cert_chain"][1]["subject_id"] = "ca:eve-intermediate"
        tampered = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered, trust_anchor=cert_chain["root_public_key"])
        assert result["valid"] is False
        assert "cert_chain_failed" in result["reason"]

    def test_cert_chain_not_needed_for_direct_verify(self, keys):
        """Direct public_key verify works without cert_chain."""
        env = vpe_sign("hello", private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_cert_chain_tamper_breaks_envelope_sig(self, cert_chain):
        """Tampering cert_chain breaks the envelope signature."""
        env = vpe_sign(
            "prompt",
            private_key=cert_chain["leaf_private_key"],
            cert_chain=cert_chain["chain"],
        )
        data = json.loads(env)
        other_keys = generate_key_pair()
        fake_root = create_certificate(
            subject_public_key=other_keys["public_key"],
            subject_id="ca:fake",
            issuer_private_key=other_keys["private_key"],
            issuer_id="ca:fake",
            issuer_public_key=other_keys["public_key"],
        )
        data["cert_chain"] = [fake_root]
        tampered = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered, trust_anchor=cert_chain["root_public_key"])
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# TTL expiry — iat-based enforcement (P5.2 fix: L-001)
# ---------------------------------------------------------------------------


class TestTTLExpiry:
    """TTL expiry enforced via iat (issued-at) timestamp signed into envelope."""

    def test_ttl_expiry_rejects_expired(self, keys):
        """Envelope with 1s TTL verified after 2s delay must be rejected."""
        env = vpe_sign("hello", ttl_seconds=1, private_key=keys["private_key"])
        time.sleep(2)
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is False
        assert result["reason"] == "envelope_expired"

    def test_ttl_zero_always_valid(self, keys):
        """Envelope with ttl_seconds=0 must be valid regardless of age."""
        from seal.core import _canonical_json, _load_private_key

        env = vpe_sign("hello", ttl_seconds=0, private_key=keys["private_key"])
        data = json.loads(env)
        # Simulate it was issued 1 hour ago
        data["iat"] = int(time.time()) - 3600
        data["signature"] = ""
        canon = _canonical_json(data)
        sk = _load_private_key(keys["private_key"])
        data["signature"] = sk.sign(canon).hex()
        tampered_env = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered_env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_missing_iat_backward_compat(self, keys):
        """Envelope without iat field must verify as valid (backward compat)."""
        from seal.core import _canonical_json, _load_private_key

        env = vpe_sign("hello", ttl_seconds=10, private_key=keys["private_key"])
        data = json.loads(env)
        del data["iat"]
        data["signature"] = ""
        canon = _canonical_json(data)
        sk = _load_private_key(keys["private_key"])
        data["signature"] = sk.sign(canon).hex()
        tampered_env = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered_env, public_key=keys["public_key"])
        assert result["valid"] is True

    def test_iat_integer_rejects_nonint(self, keys):
        """iat field that is not an integer must be rejected."""
        from seal.core import _canonical_json, _load_private_key

        env = vpe_sign("hello", ttl_seconds=10, private_key=keys["private_key"])
        data = json.loads(env)
        data["iat"] = "not-an-integer"
        data["signature"] = ""
        canon = _canonical_json(data)
        sk = _load_private_key(keys["private_key"])
        data["signature"] = sk.sign(canon).hex()
        tampered_env = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered_env, public_key=keys["public_key"])
        assert result["valid"] is False
        assert result["reason"] == "iat_not_integer"

    def test_tampered_iat_rejected_by_signature(self, keys):
        """Tampering iat after signing must fail signature check."""
        env = vpe_sign("hello", ttl_seconds=10, private_key=keys["private_key"])
        data = json.loads(env)
        data["iat"] = data["iat"] - 99999
        tampered_env = json.dumps(data, separators=(",", ":"))
        result = vpe_verify(tampered_env, public_key=keys["public_key"])
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_iat_present_in_signed_envelope(self, keys):
        """vpe_sign() must include iat in the output envelope."""
        env = vpe_sign("hello", private_key=keys["private_key"])
        data = json.loads(env)
        assert "iat" in data
        assert isinstance(data["iat"], int)

    def test_iat_strippable_default_in_compact(self, keys):
        """iat is not in strippable defaults — it must survive compact mode."""
        env = vpe_sign("hello", compact=True, private_key=keys["private_key"])
        data = json.loads(env)
        assert "iat" in data
        assert isinstance(data["iat"], int)

    def test_hmac_ttl_expiry_rejects_expired(self, hmac_secret):
        """HMAC envelope with 1s TTL verified after 2s must be rejected."""
        env = vpe_sign_hmac("hello", ttl_seconds=1, shared_secret=hmac_secret)
        time.sleep(2)
        result = vpe_verify_hmac(env, shared_secret=hmac_secret)
        assert result["valid"] is False
        assert result["reason"] == "envelope_expired"

    def test_hmac_iat_present(self, hmac_secret):
        """vpe_sign_hmac() must include iat in the output envelope."""
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        data = json.loads(env)
        assert "iat" in data
        assert isinstance(data["iat"], int)

    def test_hmac_tampered_iat_rejected(self, hmac_secret):
        """Tampering iat in HMAC envelope must break signature."""
        env = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        data = json.loads(env)
        data["iat"] = data["iat"] - 99999
        tampered = json.dumps(data, separators=(",", ":"))
        result = vpe_verify_hmac(tampered, shared_secret=hmac_secret)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"


# ---------------------------------------------------------------------------
# Compact mode (P5.3: envelope size optimisation)
# ---------------------------------------------------------------------------


class TestCompactMode:
    """Compact envelope mode strips empty/default fields for wire efficiency."""

    def test_compact_smaller_than_standard(self, keys):
        std = vpe_sign("hello", private_key=keys["private_key"])
        cpt = vpe_sign("hello", compact=True, private_key=keys["private_key"])
        assert len(cpt) < len(std)

    def test_compact_verifies_correctly(self, keys):
        env = vpe_sign("hello", compact=True, private_key=keys["private_key"])
        result = vpe_verify(env, public_key=keys["public_key"])
        assert result["valid"] is True, result["reason"]

    def test_compact_overhead_under_300(self, keys):
        env = vpe_sign("x", compact=True, private_key=keys["private_key"])
        overhead = len(env) - 1
        assert overhead < 300, f"overhead={overhead}B, target <300B"

    def test_compact_preserves_nondefault_fields(self, keys):
        env = vpe_sign("x", scope={"tools": ["read"]}, issuer="me",
                       audience="agent:h", doc_sha256="abc123",
                       ttl_seconds=60, counter=5, compact=True,
                       private_key=keys["private_key"])
        data = json.loads(env)
        assert data["scope"] == {"tools": ["read"]}
        assert data["issuer"] == "me"
        assert data["audience"] == "agent:h"
        assert data["doc_sha256"] == "abc123"
        assert data["ttl_seconds"] == 60
        assert data["counter"] == 5

    def test_compact_strips_empty_scope(self, keys):
        data = json.loads(vpe_sign("x", compact=True,
                                    private_key=keys["private_key"]))
        assert "scope" not in data

    def test_compact_strips_empty_issuer(self, keys):
        data = json.loads(vpe_sign("x", compact=True,
                                    private_key=keys["private_key"]))
        assert "issuer" not in data

    def test_compact_strips_default_ttl(self, keys):
        data = json.loads(vpe_sign("x", ttl_seconds=300, compact=True,
                                    private_key=keys["private_key"]))
        assert "ttl_seconds" not in data

    def test_compact_strips_zero_ttl(self, keys):
        data = json.loads(vpe_sign("x", ttl_seconds=0, compact=True,
                                    private_key=keys["private_key"]))
        assert "ttl_seconds" not in data

    def test_compact_always_has_prompt_nonce_signature(self, keys):
        data = json.loads(vpe_sign("hello", compact=True,
                                    private_key=keys["private_key"]))
        assert data["prompt"] == "hello"
        assert data["nonce"]
        assert data["signature"]

    def test_compact_round_trip_multiple(self, keys):
        prompts = ["", "a", "hello world", "A" * 1000, '{"json": "test"}']
        for p in prompts:
            env = vpe_sign(p, compact=True, private_key=keys["private_key"])
            result = vpe_verify(env, public_key=keys["public_key"])
            assert result["valid"] is True, f"failed prompt len={len(p)}"

    def test_compact_hmac_smaller(self, hmac_secret):
        std = vpe_sign_hmac("hello", shared_secret=hmac_secret)
        cpt = vpe_sign_hmac("hello", compact=True, shared_secret=hmac_secret)
        assert len(cpt) < len(std)

    def test_compact_hmac_verifies(self, hmac_secret):
        env = vpe_sign_hmac("hello", compact=True, shared_secret=hmac_secret)
        result = vpe_verify_hmac(env, shared_secret=hmac_secret)
        assert result["valid"] is True, result["reason"]

    def test_compact_same_canonical_as_standard(self, keys):
        std = json.loads(vpe_sign("x", nonce="fixed-nonce-001",
                                   private_key=keys["private_key"]))
        cpt = json.loads(vpe_sign("x", nonce="fixed-nonce-001", compact=True,
                                   private_key=keys["private_key"]))
        from seal.core import _canonical_json
        std_verify = dict(std)
        std_verify["signature"] = ""
        cpt_verify = dict(cpt)
        cpt_verify["signature"] = ""
        assert _canonical_json(std_verify) == _canonical_json(cpt_verify)

    def test_compact_preserves_audience(self, keys):
        data = json.loads(vpe_sign("x", audience="agent:test", compact=True,
                                    private_key=keys["private_key"]))
        assert data["audience"] == "agent:test"

    def test_compact_ed25519_under_300_overhead(self, keys):
        for prompt_len in [1, 50, 200]:
            prompt = "X" * prompt_len
            env = vpe_sign(prompt, compact=True,
                           private_key=keys["private_key"])
            overhead = len(env) - prompt_len
            assert overhead < 300, f"prompt_len={prompt_len}: overhead={overhead}B"

    def test_compact_hmac_under_200_overhead(self, hmac_secret):
        for prompt_len in [1, 50, 200]:
            prompt = "X" * prompt_len
            env = vpe_sign_hmac(prompt, compact=True, shared_secret=hmac_secret)
            overhead = len(env) - prompt_len
            assert overhead < 200, f"prompt_len={prompt_len}: overhead={overhead}B"


# ---------------------------------------------------------------------------
# Cross-module VPE interop (t_03ea2d3a)
# ---------------------------------------------------------------------------


class TestVPEInterop:
    """Cross-module interop between core.vpe_sign/verify and vpe.vpe_sign/verify.

    Ensures envelopes signed by one module can be verified by the other,
    now that both share the same SIGNED_FIELDS set (iat + cert_chain added).
    """

    def test_core_sign_vpe_verify(self, keys):
        """Sign with core.vpe_sign(), verify that vpe.vpe_verify accepts it.

        core returns JSON string, vpe expects dict — we convert and verify
        the field set is complete and valid.
        """
        from seal import vpe as vpe_mod
        import json

        sk, pk = keys["private_key"], keys["public_key"]
        env_str = vpe_sign("interop test prompt", issuer="user:test",
                           audience="agent:test", private_key=sk)
        env_dict = json.loads(env_str)

        # Verify that the converted envelope has all SIGNED_FIELDS
        signed = set(vpe_mod.SIGNED_FIELDS)
        envelope_keys = set(env_dict.keys()) - {"signature"}
        assert signed.issubset(envelope_keys), (
            f"vpe SIGNED_FIELDS missing from core envelope: {signed - envelope_keys}"
        )

        # Verify works (signature date is fresh)
        # core's canonicalisation uses ordered fields + defaults;
        # vpe uses sorted keys + explicit values.
        # The envelope must contain all required fields for vpe verification.
        result = vpe_mod.vpe_verify(env_dict, public_key=pk)
        assert result.valid, f"vpe_verify failed: {result.reason}"

    def test_vpe_sign_core_verify(self, keys):
        """Sign with vpe.vpe_sign(), verify that core.vpe_verify accepts it.

        vpe returns dict, core expects JSON string — convert and verify
        the field set is complete.
        """
        from seal import vpe as vpe_mod
        import json

        sk, pk = keys["private_key"], keys["public_key"]
        env_dict = vpe_mod.vpe_sign("interop test prompt", issuer="user:test",
                                    audience="agent:test", private_key=sk)

        # core.vpe_verify uses _ENVELOPE_FIELDS; check all required fields present
        from seal.core import _ENVELOPE_FIELDS
        envelope_keys = set(env_dict.keys()) - {"signature", "public_key"}
        core_fields = set(_ENVELOPE_FIELDS)
        assert core_fields.issubset(envelope_keys), (
            f"Core _ENVELOPE_FIELDS missing from vpe envelope: {core_fields - envelope_keys}"
        )

        # Convert dict → JSON string for core verify
        env_str = json.dumps(env_dict)
        result = vpe_verify(env_str, public_key=pk)
        assert result["valid"], f"core.vpe_verify failed: {result['reason']}"

    def test_core_sign_vpe_verify_with_cert_chain(self, keys):
        """Interop with cert_chain included."""
        from seal import vpe as vpe_mod
        import json

        sk, pk = keys["private_key"], keys["public_key"]
        env_str = vpe_sign("interop cert test", issuer="user:rez",
                           audience="agent:hermes", private_key=sk,
                           cert_chain=[{"subject_id": "leaf"}])
        env_dict = json.loads(env_str)

        result = vpe_mod.vpe_verify(env_dict, public_key=pk)
        assert result.valid, f"vpe_verify (with cert_chain) failed: {result.reason}"

    def test_vpe_sign_core_verify_with_cert_chain(self, keys):
        """Interop with cert_chain included, reverse direction."""
        from seal import vpe as vpe_mod
        import json

        sk, pk = keys["private_key"], keys["public_key"]
        env_dict = vpe_mod.vpe_sign("interop cert reverse", issuer="user:rez",
                                    audience="agent:hermes", private_key=sk,
                                    public_key=pk)
        env_str = json.dumps(env_dict)

        result = vpe_verify(env_str, public_key=pk)
        assert result["valid"], f"core.vpe_verify failed: {result['reason']}"

    def test_tampered_rejected_across_modules(self, keys):
        """Tampering an envelope signed by core is rejected by vpe verify."""
        from seal import vpe as vpe_mod

        sk, pk = keys["private_key"], keys["public_key"]
        env_str = vpe_sign("tamper test", issuer="user:rez",
                           audience="agent:hermes", private_key=sk)
        # Tamper by modifying the prompt in the JSON string
        env_str_tampered = env_str.replace('"tamper test"', '"tampered prompt"')

        import json
        env_dict = json.loads(env_str_tampered)
        result = vpe_mod.vpe_verify(env_dict, public_key=pk)
        assert not result.valid
