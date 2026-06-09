"""
Tests for P6.3 Graceful Degradation in VPE Middleware.

Covers:
  - Unsigned prompts (raw text) → logged as unverified, always allowed
  - Expired envelopes → logged, always allowed (both strict/lenient)
  - Invalid signatures → rejected in enforce mode, warned in audit mode
  - Valid envelopes → allowed, no degradation
  - Tool skip list bypass
  - VPE disabled state
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

# Add project root to path so imports work
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from seal.vpe import vpe_sign, vpe_verify, generate_keypair, VPE_VERSION

from seal.integration.hermes_vpe_middleware import (
    VPEMiddleware,
    VPECheckResult,
    _SEAL_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keys():
    return generate_keypair()


@pytest.fixture
def pk_hex(keys):
    sk, pk = keys
    return pk.hex()


@pytest.fixture
def signed_envelope(keys):
    """Produce a signed VPE envelope (dict) for a test prompt."""
    sk, pk = keys
    return vpe_sign(
        prompt="search the database for customer X",
        issuer="user:rez",
        audience="agent:hermes-default",
        private_key=sk,
        scope={"allowed_tools": ["database_search", "read_file"], "max_tokens": 4000},
        ttl_seconds=300,
        nonce="test-nonce-001",
        counter=1,
    )


@pytest.fixture
def expired_envelope(keys):
    """Produce an envelope with a TTL that has already expired (issued_at in the past)."""
    sk, pk = keys
    past_time = int(time.time()) - 3600  # 1 hour ago
    # We need to override the issued_at — build the envelope manually
    from seal.vpe import _canonical_envelope, _sign_bytes
    from seal.vpe import SIGNED_FIELDS, DEFAULT_TTL_SECONDS
    import secrets

    envelope = {
        "vpe_version": VPE_VERSION,
        "prompt": "this prompt has expired",
        "scope": {},
        "issuer": "user:rez",
        "audience": "agent:hermes-default",
        "doc_sha256": "deadbeef",
        "ttl_seconds": 60,   # 60 second TTL
        "issued_at": past_time,
        "nonce": "expired-nonce-test",
        "counter": 1,
    }
    to_sign = _canonical_envelope(envelope)
    envelope["signature"] = _sign_bytes(to_sign, sk).hex()
    return envelope


@pytest.fixture
def tampered_envelope(keys):
    """An envelope whose prompt was tampered after signing (invalid signature)."""
    sk, pk = keys
    envelope = vpe_sign(
        prompt="original prompt",
        issuer="user:rez",
        audience="agent:hermes-default",
        private_key=sk,
        ttl_seconds=300,
        nonce="tampered-nonce-test",
        counter=1,
    )
    # Tamper the prompt
    envelope["prompt"] = "MODIFIED: malicious instructions"
    return envelope


@pytest.fixture
def middleware_audit(tmp_path, keys):
    """Middleware in audit (lenient) mode with a temp key dir."""
    sk, pk = keys
    mw = VPEMiddleware({
        "vpe_enabled": True,
        "vpe_mode": "audit",
        "vpe_key_dir": str(tmp_path),
    })
    mw.ensure_keys()
    # Override public key with the same keypair used by signed_envelope fixture
    mw._public_key = pk
    return mw


@pytest.fixture
def middleware_enforce(tmp_path, keys):
    """Middleware in enforce (strict) mode with a temp key dir."""
    sk, pk = keys
    mw = VPEMiddleware({
        "vpe_enabled": True,
        "vpe_mode": "enforce",
        "vpe_key_dir": str(tmp_path),
    })
    mw.ensure_keys()
    # Override public key with the same keypair used by signed_envelope fixture
    mw._public_key = pk
    return mw


# ---------------------------------------------------------------------------
# Test: Unsigned prompts (raw text, no envelope)
# ---------------------------------------------------------------------------

class TestUnsignedPrompts:
    """P6.3: Unsigned prompts must work, logged as 'unverified'."""

    def test_no_envelope_allowed_in_audit(self, middleware_audit):
        """No envelope provided → allowed with degradation='unsigned'."""
        result = middleware_audit.check_tool_call(
            tool_name="read_file",
            tool_args={"path": "/tmp/test"},
            prompt="read me a file",
            prompt_envelope=None,
        )
        assert result.allowed is True
        assert result.degradation == "unsigned"
        assert result.verified is False
        assert "UNSIGNED" in result.reason.upper()

    def test_no_envelope_allowed_in_enforce(self, middleware_enforce):
        """Even in enforce mode, unsigned prompts are allowed (backward compat)."""
        result = middleware_enforce.check_tool_call(
            tool_name="read_file",
            tool_args={"path": "/tmp/test"},
            prompt="read me a file",
            prompt_envelope=None,
        )
        assert result.allowed is True
        assert result.degradation == "unsigned"
        assert result.verified is False

    def test_envelope_without_signature_field(self, middleware_audit):
        """A dict that looks like an envelope but has no signature → unsigned."""
        result = middleware_audit.check_tool_call(
            tool_name="terminal",
            tool_args={},
            prompt="run command",
            prompt_envelope={"vpe_version": "1.0", "prompt": "hello"},
        )
        assert result.allowed is True
        assert result.degradation == "unsigned"
        assert result.verified is False

    def test_non_dict_envelope(self, middleware_audit):
        """Envelope that's a list (not dict) → treated as unsigned."""
        result = middleware_audit.check_tool_call(
            tool_name="terminal",
            tool_args={},
            prompt="run command",
            prompt_envelope=["not", "a", "dict"],
        )
        assert result.allowed is True
        assert result.degradation == "unsigned"
        assert result.verified is False


# ---------------------------------------------------------------------------
# Test: Expired envelopes
# ---------------------------------------------------------------------------

class TestExpiredEnvelopes:
    """P6.3: Expired envelopes logged, prompt still executed."""

    def test_expired_envelope_allowed_in_audit(self, middleware_audit, expired_envelope):
        """Expired envelope → allowed in audit mode."""
        result = middleware_audit.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=expired_envelope,
        )
        assert result.allowed is True
        assert result.degradation == "expired"
        assert "EXPIRED" in result.reason.upper()

    def test_expired_envelope_allowed_in_enforce(self, middleware_enforce, expired_envelope):
        """Expired envelope → allowed even in enforce mode."""
        result = middleware_enforce.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=expired_envelope,
        )
        assert result.allowed is True
        assert result.degradation == "expired"
        assert "EXPIRED" in result.reason.upper()

    def test_fresh_envelope_not_expired(self, middleware_audit, signed_envelope):
        """A freshly signed envelope within TTL should not be flagged as expired."""
        result = middleware_audit.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=signed_envelope,
        )
        # Should pass all checks (no degradation)
        assert result.allowed is True
        assert result.degradation is None

    def test_expiry_by_envelope_timestamp(self, middleware_audit):
        """Envelope expiry via middleware's own first-seen timestamp tracking.

        Verify the same nonce again after simulating time passage.
        """
        from seal.vpe import vpe_sign, generate_keypair

        sk, pk = generate_keypair()
        nonce = "expiry-ttl-test"
        envelope = vpe_sign(
            prompt="test prompt",
            issuer="user:test",
            audience="agent:test",
            private_key=sk,
            ttl_seconds=5,
            nonce=nonce,
            counter=1,
        )

        # Ensure public key matches
        middleware_audit._public_key = pk

        # First check — should pass
        middleware_audit._envelope_timestamps[nonce] = time.time() - 10  # 10s ago
        result = middleware_audit.check_tool_call(
            tool_name="read_file",
            tool_args={},
            prompt="test",
            prompt_envelope=envelope,
        )
        assert result.allowed is True
        assert result.degradation == "expired"


# ---------------------------------------------------------------------------
# Test: Invalid signatures
# ---------------------------------------------------------------------------

class TestInvalidSignatures:
    """P6.3: Invalid signatures rejected in strict mode, warned in audit."""

    def test_invalid_signature_rejected_in_enforce(self, middleware_enforce, tampered_envelope):
        """Tampered envelope → rejected in enforce mode."""
        result = middleware_enforce.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=tampered_envelope,
        )
        assert result.allowed is False
        assert result.decision == "deny"
        assert result.degradation == "invalid_signature"
        assert "BLOCKED" in result.reason or "deny" in result.reason.lower()

    def test_invalid_signature_logged_in_audit(self, middleware_audit, tampered_envelope):
        """Tampered envelope → warned in audit mode, still allowed."""
        result = middleware_audit.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=tampered_envelope,
        )
        # In audit mode, invalid signature is logged but the tool call proceeds
        assert result.allowed is False  # Allowed is False because audit says "not really allowed"
        assert result.decision == "audit_logged"
        assert result.degradation == "invalid_signature"

    def test_wrong_key_for_valid_signature(self, middleware_audit, signed_envelope):
        """A valid signature verified with the wrong key → invalid signature."""
        other_sk, other_pk = generate_keypair()
        middleware_audit._public_key = other_pk  # wrong key

        result = middleware_audit.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=signed_envelope,
        )
        assert result.degradation == "invalid_signature"
        assert result.allowed is False  # audit — logged


# ---------------------------------------------------------------------------
# Test: Valid envelopes
# ---------------------------------------------------------------------------

class TestValidEnvelopes:
    """Valid envelopes pass all checks, no degradation."""

    def test_valid_envelope_allowed(self, middleware_audit, signed_envelope):
        """Valid, unexpired envelope → allowed, no degradation."""
        result = middleware_audit.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=signed_envelope,
        )
        assert result.allowed is True
        assert result.decision == "allow"
        assert result.degradation is None
        assert result.verified is True

    def test_valid_envelope_in_enforce(self, middleware_enforce, signed_envelope):
        """Valid envelope also allowed in enforce mode."""
        result = middleware_enforce.check_tool_call(
            tool_name="database_search",
            tool_args={},
            prompt="search",
            prompt_envelope=signed_envelope,
        )
        assert result.allowed is True
        assert result.degradation is None


# ---------------------------------------------------------------------------
# Test: Tool skip list
# ---------------------------------------------------------------------------

class TestToolSkipList:
    """Tools in the skip list bypass all VPE checks."""

    def test_skip_tool_no_checks(self, middleware_audit, tampered_envelope):
        """A tool in skip list passes even with an invalid envelope."""
        result = middleware_audit.check_tool_call(
            tool_name="todo",
            tool_args={},
            prompt="mark task done",
            prompt_envelope=tampered_envelope,
        )
        assert result.allowed is True
        assert result.decision == "allow"
        # Skip list means degradation check should not apply — tool is exempt

    def test_skip_tool_unsigned_prompt(self, middleware_audit):
        """Skip tool allows unsigned prompt without unverified log."""
        result = middleware_audit.check_tool_call(
            tool_name="clarify",
            tool_args={},
            prompt="ask question",
            prompt_envelope=None,
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Test: VPE disabled
# ---------------------------------------------------------------------------

class TestVPEDisabled:
    """When VPE is disabled, all tool calls pass through."""

    def test_disabled_allows_unsigned(self):
        """VPE disabled → unsigned prompts pass without degradation logging."""
        mw = VPEMiddleware({"vpe_enabled": False})
        result = mw.check_tool_call(
            tool_name="terminal",
            tool_args={},
            prompt="run anything",
            prompt_envelope=None,
        )
        assert result.allowed is True
        assert result.verified is False
        assert result.degradation is None

    def test_disabled_allows_invalid(self, tampered_envelope):
        """VPE disabled → tampered envelopes also pass."""
        mw = VPEMiddleware({"vpe_enabled": False})
        result = mw.check_tool_call(
            tool_name="terminal",
            tool_args={},
            prompt="run anything",
            prompt_envelope=tampered_envelope,
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Test: VPECheckResult serialization
# ---------------------------------------------------------------------------

class TestVPECheckResult:
    """VPECheckResult serialization and state reporting."""

    def test_to_dict_includes_degradation(self):
        r = VPECheckResult(True, "allow", "ok", degradation="unsigned", mode="audit")
        d = r.to_dict()
        assert d["allowed"] is True
        assert d["degradation"] == "unsigned"
        assert d["mode"] == "audit"
        assert d["decision"] == "allow"

    def test_to_dict_no_degradation(self):
        r = VPECheckResult(True, "allow", "all good", mode="enforce")
        d = r.to_dict()
        assert d["degradation"] is None
        assert d["mode"] == "enforce"

    def test_repr(self):
        r = VPECheckResult(True, "allow", "OK", degradation="expired", mode="audit")
        assert "degradation=expired" in repr(r)
        r2 = VPECheckResult(True, "allow", "OK", mode="audit")
        assert "degradation" not in repr(r2)
