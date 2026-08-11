"""Unit tests for seal.vpe — the Verified Prompt Envelope core.

Covers: VPEResult, dual-backend crypto (nacl path via a fake nacl module
injected into sys.modules, plus the real cryptography fallback), canonical
serialisation, sign/verify lifecycle, every vpe_verify check, and the
key-file helpers.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

from seal import vpe
from seal._base import VPE_VERSION

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _install_fake_nacl(monkeypatch) -> None:
    """Inject a minimal fake ``nacl`` package backed by cryptography.

    Lets tests exercise the nacl-preferred code paths in an environment where
    PyNaCl is not installed (CI may lack it), without installing anything.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    class BadSignatureError(Exception):
        pass

    bindings = types.ModuleType("nacl.bindings")

    def crypto_sign_keypair():
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key().public_bytes_raw()
        return pk, sk.private_bytes_raw() + pk  # (pk, seed||pk)

    def crypto_sign_seed_keypair(seed):
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pk = sk.public_key().public_bytes_raw()
        return pk, seed + pk

    def crypto_sign(data, sk_full):
        sk = Ed25519PrivateKey.from_private_bytes(sk_full[:32])
        return sk.sign(data) + data  # nacl returns signature || message

    def crypto_sign_open(signed, pk):
        sig, msg = signed[:64], signed[64:]
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return msg
        except InvalidSignature:
            raise BadSignatureError()

    bindings.crypto_sign_keypair = crypto_sign_keypair
    bindings.crypto_sign_seed_keypair = crypto_sign_seed_keypair
    bindings.crypto_sign = crypto_sign
    bindings.crypto_sign_open = crypto_sign_open

    exceptions = types.ModuleType("nacl.exceptions")
    exceptions.BadSignatureError = BadSignatureError

    nacl = types.ModuleType("nacl")
    nacl.__path__ = []  # look like a package so `import nacl.bindings` works
    nacl.bindings = bindings
    nacl.exceptions = exceptions

    monkeypatch.setitem(sys.modules, "nacl", nacl)
    monkeypatch.setitem(sys.modules, "nacl.bindings", bindings)
    monkeypatch.setitem(sys.modules, "nacl.exceptions", exceptions)


@pytest.fixture
def fake_nacl(monkeypatch):
    _install_fake_nacl(monkeypatch)
    return monkeypatch


# ---------------------------------------------------------------------------
# VPEResult
# ---------------------------------------------------------------------------


class TestVPEResult:
    def test_valid_result_is_truthy(self):
        result = vpe.VPEResult(True)
        assert bool(result) is True
        assert result.valid is True
        assert result.reason == ""
        assert result.envelope is None

    def test_invalid_result_is_falsy(self):
        result = vpe.VPEResult(False, "boom")
        assert bool(result) is False
        assert result.reason == "boom"

    def test_repr(self):
        assert repr(vpe.VPEResult(True)) == "<VPEResult VALID: >"
        assert repr(vpe.VPEResult(False, "boom")) == "<VPEResult INVALID: boom>"

    def test_slots_defined(self):
        assert vpe.VPEResult.__slots__ == ("valid", "reason", "envelope")


# ---------------------------------------------------------------------------
# Dual-backend crypto
# ---------------------------------------------------------------------------


class TestCrypto:
    def test_generate_keypair_returns_32_byte_keys(self):
        sk, pk = vpe.generate_keypair()
        assert len(sk) == 32
        assert len(pk) == 32
        assert sk != pk

    def test_generate_keypair_unique(self):
        sk1, _ = vpe.generate_keypair()
        sk2, _ = vpe.generate_keypair()
        assert sk1 != sk2

    def test_sign_verify_roundtrip_crypto_backend(self):
        sk, pk = vpe.generate_keypair()
        data = b"the quick brown fox"
        sig = vpe._sign_bytes(data, sk)
        assert len(sig) == 64
        assert vpe._verify_bytes(data, sig, pk) is True

    def test_verify_rejects_tampered_data_crypto_backend(self):
        sk, pk = vpe.generate_keypair()
        sig = vpe._sign_bytes(b"original", sk)
        assert vpe._verify_bytes(b"tampered", sig, pk) is False

    def test_verify_rejects_tampered_signature_crypto_backend(self):
        sk, pk = vpe.generate_keypair()
        sig = vpe._sign_bytes(b"data", sk)
        bad = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        assert vpe._verify_bytes(b"data", bad, pk) is False

    def test_verify_rejects_wrong_key_crypto_backend(self):
        sk, _ = vpe.generate_keypair()
        _, other_pk = vpe.generate_keypair()
        sig = vpe._sign_bytes(b"data", sk)
        assert vpe._verify_bytes(b"data", sig, other_pk) is False

    def test_nacl_path_generate_sign_verify(self, fake_nacl):
        sk, pk = vpe.generate_keypair()
        assert len(sk) == 32 and len(pk) == 32
        sig = vpe._sign_bytes(b"nacl-path", sk)
        assert len(sig) == 64
        assert vpe._verify_bytes(b"nacl-path", sig, pk) is True
        assert vpe._verify_bytes(b"tampered", sig, pk) is False

    def test_nacl_and_crypto_paths_interop(self, fake_nacl):
        # Sign via the nacl path, then drop the fake and verify via cryptography.
        with fake_nacl.context() as m:
            _install_fake_nacl(m)
            sk, pk = vpe.generate_keypair()
            env = vpe.vpe_sign(
                "interop", "issuer:test", "audience:test", private_key=sk, public_key=pk
            )
        # fake nacl is gone now; vpe_verify must fall back to cryptography
        assert vpe.vpe_verify(env).valid

    def test_vpe_sign_raises_without_crypto(self, monkeypatch):
        monkeypatch.setattr(vpe, "_nacl_sign_available", lambda: False)
        with pytest.raises(RuntimeError, match="nacl.*cryptography"):
            vpe.vpe_sign(
                "p", "issuer:test", "audience:test",
                private_key=b"\x01" * 32,
            )

    def test_vpe_verify_reports_missing_crypto(self, monkeypatch):
        monkeypatch.setattr(vpe, "_ensure_nacl", lambda: False)
        env = {
            "vpe_version": VPE_VERSION,
            "prompt": "p",
            "scope": {},
            "issuer": "i",
            "audience": "a",
            "doc_sha256": "",
            "iat": 1,
            "ttl_seconds": 300,
            "nonce": "n",
            "counter": 1,
            "cert_chain": None,
        }
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == vpe._ERROR_MISSING_CRYPTO


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------


class TestCanonicalEnvelope:
    def _base_env(self) -> dict:
        return {
            "vpe_version": VPE_VERSION,
            "prompt": "hello",
            "scope": {"b": 2, "a": 1},
            "issuer": "issuer:test",
            "audience": "audience:test",
            "doc_sha256": "abc",
            "iat": 1234,
            "ttl_seconds": 300,
            "nonce": "nonce-1",
            "counter": 1,
            "cert_chain": None,
        }

    def test_deterministic(self):
        env = self._base_env()
        assert vpe._canonical_envelope(env) == vpe._canonical_envelope(env)

    def test_scope_keys_sorted(self):
        env = self._base_env()
        env["scope"] = {"z": 1, "m": 2, "a": 3}
        env2 = dict(env)
        env2["scope"] = {"a": 3, "m": 2, "z": 1}
        assert vpe._canonical_envelope(env) == vpe._canonical_envelope(env2)

    def test_cert_chain_none_omitted(self):
        env = self._base_env()
        env2 = dict(env)
        env2.pop("cert_chain")
        assert vpe._canonical_envelope(env) == vpe._canonical_envelope(env2)

    def test_signature_and_public_key_excluded(self):
        env = self._base_env()
        env2 = dict(env)
        env2["signature"] = "f" * 128
        env2["public_key"] = "0" * 64
        assert vpe._canonical_envelope(env) == vpe._canonical_envelope(env2)

    def test_missing_fields_defaulted(self):
        env = self._base_env()
        minimal = {"prompt": "hello", "scope": {"a": 1}, "issuer": "issuer:test"}
        env["scope"] = {"a": 1}
        env["issuer"] = "issuer:test"
        for key in ("audience", "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain"):
            minimal[key] = env.get(key)
        assert vpe._canonical_envelope(env) == vpe._canonical_envelope(minimal)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestSign:
    @pytest.fixture
    def keypair(self):
        return vpe.generate_keypair()

    def test_sign_creates_full_envelope(self, keypair):
        sk, pk = keypair
        env = vpe.vpe_sign("hello", "issuer:test", "audience:test", private_key=sk)
        assert env["vpe_version"] == VPE_VERSION
        assert env["prompt"] == "hello"
        assert env["issuer"] == "issuer:test"
        assert env["audience"] == "audience:test"
        assert env["scope"] == {}
        assert env["ttl_seconds"] == vpe.DEFAULT_TTL_SECONDS
        assert env["counter"] == 1
        assert env["cert_chain"] is None
        assert len(env["nonce"]) == 32
        assert len(env["signature"]) == 128  # 64 bytes hex

    def test_sign_auto_hashes_prompt(self, keypair):
        import hashlib

        sk, _ = keypair
        env = vpe.vpe_sign("hello", "issuer:test", "audience:test", private_key=sk)
        assert env["doc_sha256"] == hashlib.sha256(b"hello").hexdigest()

    def test_sign_respects_explicit_doc_sha256(self, keypair):
        sk, _ = keypair
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, doc_sha256="deadbeef",
        )
        assert env["doc_sha256"] == "deadbeef"

    def test_sign_embeds_public_key_when_given(self, keypair):
        sk, pk = keypair
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test", private_key=sk, public_key=pk
        )
        assert env["public_key"] == pk.hex()

    def test_sign_respects_explicit_nonce_and_counter(self, keypair):
        sk, _ = keypair
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, nonce="fixed-nonce", counter=7,
        )
        assert env["nonce"] == "fixed-nonce"
        assert env["counter"] == 7

    def test_sign_scope_passthrough(self, keypair):
        sk, _ = keypair
        scope = {"allowed_tools": ["read"], "max_cost": 5}
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test", private_key=sk, scope=scope
        )
        assert env["scope"] == scope

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("prompt", ""),
            ("issuer", ""),
            ("audience", ""),
        ],
    )
    def test_sign_rejects_empty_required_fields(self, keypair, field, value):
        sk, _ = keypair
        kwargs = {"prompt": "p", "issuer": "i", "audience": "a"}
        kwargs[field] = value
        with pytest.raises(ValueError, match=f"{field} must not be empty"):
            vpe.vpe_sign(private_key=sk, **kwargs)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerify:
    @pytest.fixture
    def envelope(self):
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, counter=1,
        )
        return env

    def test_valid_envelope(self, envelope):
        result = vpe.vpe_verify(envelope)
        assert result.valid is True
        assert result.reason == ""
        assert result.envelope is envelope

    def test_valid_envelope_from_param_key(self, envelope):
        result = vpe.vpe_verify(envelope, public_key=bytes.fromhex(envelope["public_key"]))
        assert result.valid is True

    @pytest.mark.parametrize("field", vpe.SIGNED_FIELDS)
    def test_missing_required_field(self, envelope, field):
        env = dict(envelope)
        env.pop(field)
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == f"missing required field: {field}"

    def test_version_mismatch(self, envelope):
        env = dict(envelope)
        env["vpe_version"] = "9.9"
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == f"envelope version mismatch: expected {VPE_VERSION}, got 9.9"

    def test_expired_envelope(self, envelope, monkeypatch):
        monkeypatch.setattr(vpe.time, "time", lambda: 1_000_000)
        # Re-sign so iat is anchored at the frozen time.
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, ttl_seconds=300,
        )
        monkeypatch.setattr(vpe.time, "time", lambda: 1_000_000 + 301)
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "envelope has expired"

    def test_expiry_skipped(self, envelope, monkeypatch):
        sk, pk = vpe.generate_keypair()
        monkeypatch.setattr(vpe.time, "time", lambda: 1_000_000)
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, ttl_seconds=1,
        )
        monkeypatch.setattr(vpe.time, "time", lambda: 1_000_000 + 999)
        result = vpe.vpe_verify(env, skip_checks=["expiry"])
        assert result.valid is True

    def test_missing_public_key(self, envelope):
        env = dict(envelope)
        env.pop("public_key")
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == vpe._ERROR_PUBLIC_KEY_MISSING

    def test_invalid_public_key_hex(self, envelope):
        env = dict(envelope)
        env["public_key"] = "not-hex!!"
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "invalid public_key format (not hex)"

    def test_invalid_public_key_length(self, envelope):
        env = dict(envelope)
        env["public_key"] = "00" * 16  # 16 bytes
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "invalid public_key length: expected 32 bytes, got 16"

    def test_invalid_signature_hex(self, envelope):
        env = dict(envelope)
        env["signature"] = "xyz"
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "invalid signature format (not hex)"

    def test_invalid_signature_length(self, envelope):
        env = dict(envelope)
        env["signature"] = "ab" * 32  # 32 bytes
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "invalid signature length: expected 64 bytes, got 32"

    def test_tampered_prompt_fails_signature(self, envelope):
        env = dict(envelope)
        env["prompt"] = "evil"
        result = vpe.vpe_verify(env)
        assert result.valid is False
        assert result.reason == "signature verification failed"

    def test_wrong_key_fails_signature(self, envelope):
        _, other_pk = vpe.generate_keypair()
        result = vpe.vpe_verify(envelope, public_key=other_pk)
        assert result.valid is False
        assert result.reason == "signature verification failed"

    def test_nonce_replay_detected(self, envelope):
        seen = set()
        assert vpe.vpe_verify(envelope, seen_nonces=seen).valid is True
        result = vpe.vpe_verify(envelope, seen_nonces=seen)
        assert result.valid is False
        assert result.reason == "nonce replay detected"

    def test_replay_skipped(self, envelope):
        seen = {envelope["nonce"]}
        result = vpe.vpe_verify(envelope, seen_nonces=seen, skip_checks=["replay"])
        assert result.valid is True

    def test_counter_non_monotonic(self, envelope):
        result = vpe.vpe_verify(envelope, last_counter=1)
        assert result.valid is False
        assert result.reason == "non-monotonic counter: 1 <= 1"

    def test_counter_ok_when_last_lower(self, envelope):
        result = vpe.vpe_verify(envelope, last_counter=0)
        assert result.valid is True

    def test_counter_skipped(self, envelope):
        result = vpe.vpe_verify(envelope, last_counter=99, skip_checks=["counter"])
        assert result.valid is True

    def test_scope_tool_allowed(self, envelope):
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, scope={"allowed_tools": ["read", "write"]},
        )
        result = vpe.vpe_verify(env, actual_args={"_tool_name": "read"})
        assert result.valid is True

    def test_scope_tool_denied(self, envelope):
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, scope={"allowed_tools": ["read"]},
        )
        result = vpe.vpe_verify(env, actual_args={"_tool_name": "exec"})
        assert result.valid is False
        assert result.reason == "tool 'exec' not in allowed_tools: ['read']"

    def test_scope_max_cost(self, envelope):
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, scope={"max_cost": 5},
        )
        assert vpe.vpe_verify(env, actual_args={"_estimated_cost": 5}).valid is True
        result = vpe.vpe_verify(env, actual_args={"_estimated_cost": 6})
        assert result.valid is False
        assert result.reason == "estimated cost 6 exceeds max_cost 5"

    def test_scope_skipped(self, envelope):
        sk, pk = vpe.generate_keypair()
        env = vpe.vpe_sign(
            "hello", "issuer:test", "audience:test",
            private_key=sk, public_key=pk, scope={"allowed_tools": ["read"]},
        )
        result = vpe.vpe_verify(
            env, actual_args={"_tool_name": "exec"}, skip_checks=["scope"]
        )
        assert result.valid is True


# ---------------------------------------------------------------------------
# Key file helpers
# ---------------------------------------------------------------------------


class TestKeyFiles:
    def test_save_creates_files_and_dir(self, tmp_path):
        sk, pk = vpe.generate_keypair()
        vpe.save_keypair(sk, pk, str(tmp_path))
        assert (tmp_path / "vpe_private.key").exists()
        assert (tmp_path / "vpe_public.key").exists()

    def test_save_writes_hex_and_0600_perms(self, tmp_path):
        sk, pk = vpe.generate_keypair()
        vpe.save_keypair(sk, pk, str(tmp_path))
        priv = (tmp_path / "vpe_private.key").read_text().strip()
        pub = (tmp_path / "vpe_public.key").read_text().strip()
        assert bytes.fromhex(priv) == sk
        assert bytes.fromhex(pub) == pk
        assert (tmp_path / "vpe_private.key").stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "vpe_public.key").stat().st_mode & 0o777 == 0o600

    def test_load_roundtrip(self, tmp_path):
        sk, pk = vpe.generate_keypair()
        vpe.save_keypair(sk, pk, str(tmp_path))
        assert vpe.load_keypair(str(tmp_path)) == (sk, pk)

    def test_load_or_generate_generates_when_missing(self, tmp_path):
        sk, pk = vpe.load_or_generate_keypair(str(tmp_path))
        assert len(sk) == 32 and len(pk) == 32
        assert (tmp_path / "vpe_private.key").exists()

    def test_load_or_generate_loads_when_present(self, tmp_path):
        sk, pk = vpe.generate_keypair()
        vpe.save_keypair(sk, pk, str(tmp_path))
        loaded_sk, loaded_pk = vpe.load_or_generate_keypair(str(tmp_path))
        assert (loaded_sk, loaded_pk) == (sk, pk)

    def test_save_expands_tilde(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            os.path, "expanduser", lambda p: str(tmp_path / "keys") if p == "~/keys" else p
        )
        sk, pk = vpe.generate_keypair()
        vpe.save_keypair(sk, pk, "~/keys")
        assert (tmp_path / "keys" / "vpe_private.key").exists()

    def test_load_or_generate_expands_tilde(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            os.path, "expanduser", lambda p: str(tmp_path / "keys") if p == "~/keys" else p
        )
        sk, pk = vpe.load_or_generate_keypair("~/keys")
        assert len(sk) == 32 and len(pk) == 32
        assert (tmp_path / "keys" / "vpe_private.key").exists()
