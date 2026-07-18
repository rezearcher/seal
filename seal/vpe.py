"""
VPE Core — Verified Prompt Envelope Protocol.

Ed25519-signed prompt envelopes for cryptographic provenance verification
of AI agent prompts. Uses dual-backend (nacl preferred, cryptography fallback).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any

from seal._base import (
    VPE_VERSION,
    _ENVELOPE_FIELDS,
    _canonical_json,
)

SIGNED_FIELDS = _ENVELOPE_FIELDS

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

DEFAULT_TTL_SECONDS = 300

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

VPEEnvelope = dict[str, Any]


class VPEResult:
    """Result of a VPE verification.

    Attributes:
        valid: True if all checks pass.
        reason: Human-readable explanation (empty on success).
        envelope: The verified envelope (if valid), or None.
    """

    __slots__ = ("valid", "reason", "envelope")

    def __init__(self, valid: bool, reason: str = "", envelope: VPEEnvelope | None = None):
        self.valid = valid
        self.reason = reason
        self.envelope = envelope

    def __repr__(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return f"<VPEResult {status}: {self.reason}>"

    def __bool__(self) -> bool:
        return self.valid


# ---------------------------------------------------------------------------
# Dual-backend crypto (nacl preferred, cryptography fallback)
# ---------------------------------------------------------------------------

_KEY_CACHE: dict[str, tuple] = {}


def _ensure_nacl() -> bool:
    try:
        import nacl.bindings  # noqa: F401

        return True
    except ImportError:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401

            return True
        except ImportError:
            return False


def _nacl_sign_available() -> bool:
    return _ensure_nacl()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair (nacl/crypto dual-backend)."""
    try:
        import nacl.bindings

        pk, sk_full = nacl.bindings.crypto_sign_keypair()
        return (sk_full[:32], pk)
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        sk = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        pk = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return (sk, pk)


def _sign_bytes(data: bytes, private_key: bytes) -> bytes:
    """Sign data with Ed25519 (nacl preferred, crypto fallback)."""
    try:
        import nacl.bindings

        pk_from_seed, sk_full = nacl.bindings.crypto_sign_seed_keypair(private_key)
        return nacl.bindings.crypto_sign(data, sk_full)[:64]
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(private_key).sign(data)


def _verify_bytes(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature (nacl preferred, crypto fallback)."""
    try:
        import nacl.bindings
        import nacl.exceptions

        try:
            nacl.bindings.crypto_sign_open(signature + data, public_key)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
    except ImportError:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Canonical serialisation (vpe.py flavour conforming to core.py's field order)
# ---------------------------------------------------------------------------


def _canonical_envelope(envelope: VPEEnvelope, skip_signature: bool = True) -> bytes:
    """Serialize the signable portion of an envelope to bytes.

    Only SIGNED_FIELDS are included, in the order they appear in the envelope,
    matching core.py's canonical field order and scope sorting.
    """
    payload = {}
    for key in SIGNED_FIELDS:
        if key in envelope:
            value = envelope[key]
            if key == "cert_chain" and value is None:
                continue
            if key == "scope" and isinstance(value, dict):
                value = dict(sorted(value.items()))
            payload[key] = value
    return _canonical_json(payload)


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def vpe_sign(
    prompt: str,
    issuer: str,
    audience: str,
    *,
    private_key: bytes,
    scope: dict[str, Any] | None = None,
    doc_sha256: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    nonce: str | None = None,
    counter: int = 1,
    public_key: bytes | None = None,
) -> VPEEnvelope:
    """Create a signed VPE envelope.

    Args:
        prompt: The prompt text being authorized.
        issuer: Who is authorizing this (e.g. "user:rez").
        audience: Which agent should execute (e.g. "agent:hermes-default").
        private_key: 32-byte Ed25519 private (seed) key.
        scope: Capability restrictions.
        doc_sha256: SHA-256 of source document (auto from prompt if None).
        ttl_seconds: Seconds until expiry (default 300).
        nonce: Unique value for replay prevention (auto-generated).
        counter: Monotonic counter for skipped-prompt detection.
        public_key: Embed in envelope for self-contained verification.
    """
    if not _nacl_sign_available():
        raise RuntimeError("Ed25519 signing requires the 'nacl' (PyNaCl) or 'cryptography' library.")
    if not prompt:
        raise ValueError("prompt must not be empty")
    if not issuer:
        raise ValueError("issuer must not be empty")
    if not audience:
        raise ValueError("audience must not be empty")

    envelope: VPEEnvelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope or {},
        "issuer": issuer,
        "audience": audience,
        "doc_sha256": doc_sha256 if doc_sha256 is not None else hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "ttl_seconds": ttl_seconds,
        "iat": int(time.time()),
        "nonce": nonce or secrets.token_hex(16),
        "counter": counter,
        "cert_chain": None,
    }
    if public_key is not None:
        envelope["public_key"] = public_key.hex()
    envelope["signature"] = _sign_bytes(_canonical_envelope(envelope), private_key).hex()
    return envelope


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

_ERROR_MISSING_CRYPTO = "no crypto library available (install pynacl or cryptography)"
_ERROR_PUBLIC_KEY_MISSING = "no public_key in envelope and no public_key provided"


def _check_required_fields(envelope: VPEEnvelope) -> str | None:
    for field in SIGNED_FIELDS:
        if field not in envelope:
            return f"missing required field: {field}"
    return None


def _check_version(envelope: VPEEnvelope) -> str | None:
    v = envelope.get("vpe_version", "")
    return None if v == VPE_VERSION else f"envelope version mismatch: expected {VPE_VERSION}, got {v}"


def _check_expiry(envelope: VPEEnvelope) -> str | None:
    ttl = envelope.get("ttl_seconds", 0)
    if ttl <= 0:
        return None
    iat = envelope.get("iat", 0)
    if iat <= 0:
        return None
    return None if int(time.time()) <= iat + ttl else "envelope has expired"


def _check_nonce_replay(nonce: str, seen_nonces: set | None = None) -> str | None:
    if seen_nonces is not None and nonce in seen_nonces:
        return "nonce replay detected"
    if seen_nonces is not None:
        seen_nonces.add(nonce)
    return None


def _check_counter_monotonic(counter: int, last_counter: int | None = None) -> str | None:
    if last_counter is not None and counter <= last_counter:
        return f"non-monotonic counter: {counter} <= {last_counter}"
    return None


def _check_scope(envelope: VPEEnvelope, actual_args: dict[str, Any] | None = None) -> str | None:
    scope = envelope.get("scope", {})
    if not scope or actual_args is None:
        return None
    allowed_tools = scope.get("allowed_tools")
    if allowed_tools is not None:
        tool_name = actual_args.get("_tool_name", "")
        if tool_name and tool_name not in allowed_tools:
            return f"tool '{tool_name}' not in allowed_tools: {allowed_tools}"
    max_cost = scope.get("max_cost")
    if max_cost is not None:
        estimated_cost = actual_args.get("_estimated_cost", 0)
        if estimated_cost > max_cost:
            return f"estimated cost {estimated_cost} exceeds max_cost {max_cost}"
    return None


def vpe_verify(
    envelope: VPEEnvelope,
    *,
    public_key: bytes | None = None,
    seen_nonces: set | None = None,
    last_counter: int | None = None,
    actual_args: dict[str, Any] | None = None,
    skip_checks: list[str] | None = None,
) -> VPEResult:
    """Verify a VPE envelope.

    Checks: required fields, crypto, version, TTL, signature, nonce replay,
    counter monotonic, scope constraints.

    Args:
        envelope: The VPE envelope dict to verify.
        public_key: 32-byte Ed25519 public key (extracted from envelope if None).
        seen_nonces: Optional set for replay detection.
        last_counter: Optional last counter for monotonicity check.
        actual_args: Optional tool-call args for scope validation.
        skip_checks: Check names to skip (expiry, replay, counter, scope).
    """
    skip = set(skip_checks or [])

    err = _check_required_fields(envelope)
    if err:
        return VPEResult(False, err)
    if not _ensure_nacl():
        return VPEResult(False, _ERROR_MISSING_CRYPTO)
    if "version" not in skip:
        err = _check_version(envelope)
        if err:
            return VPEResult(False, err)
    if "expiry" not in skip:
        err = _check_expiry(envelope)
        if err:
            return VPEResult(False, err)

    pk = public_key
    if pk is None:
        pk_hex = envelope.get("public_key", "")
        if not pk_hex:
            return VPEResult(False, _ERROR_PUBLIC_KEY_MISSING)
        try:
            pk = bytes.fromhex(pk_hex)
        except ValueError:
            return VPEResult(False, "invalid public_key format (not hex)")
    if len(pk) != 32:
        return VPEResult(False, f"invalid public_key length: expected 32 bytes, got {len(pk)}")

    sig_hex = envelope.get("signature", "")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return VPEResult(False, "invalid signature format (not hex)")
    if len(sig) != 64:
        return VPEResult(False, f"invalid signature length: expected 64 bytes, got {len(sig)}")

    to_verify = _canonical_envelope(envelope)
    if not _verify_bytes(to_verify, sig, pk):
        return VPEResult(False, "signature verification failed")

    if "replay" not in skip:
        err = _check_nonce_replay(envelope.get("nonce", ""), seen_nonces)
        if err:
            return VPEResult(False, err)
    if "counter" not in skip:
        err = _check_counter_monotonic(envelope.get("counter", 0), last_counter)
        if err:
            return VPEResult(False, err)
    if "scope" not in skip:
        err = _check_scope(envelope, actual_args)
        if err:
            return VPEResult(False, err)

    return VPEResult(True, "", envelope)


# ---------------------------------------------------------------------------
# Key file helpers
# ---------------------------------------------------------------------------


def save_keypair(private_key: bytes, public_key: bytes, path: str) -> None:
    os.makedirs(path, exist_ok=True)
    priv_path = os.path.join(path, "vpe_private.key")
    pub_path = os.path.join(path, "vpe_public.key")
    for p, data in [(priv_path, private_key), (pub_path, public_key)]:
        with open(p, "wb") as f:
            f.write(data.hex().encode("utf-8"))
        os.chmod(p, 0o600)


def load_keypair(path: str) -> tuple[bytes, bytes]:
    priv_path = os.path.join(path, "vpe_private.key")
    pub_path = os.path.join(path, "vpe_public.key")
    with open(priv_path) as f:
        private_key = bytes.fromhex(f.read().strip())
    with open(pub_path) as f:
        public_key = bytes.fromhex(f.read().strip())
    return (private_key, public_key)


def load_or_generate_keypair(path: str) -> tuple[bytes, bytes]:
    priv_path = os.path.join(path, "vpe_private.key")
    if os.path.exists(priv_path):
        return load_keypair(path)
    sk, pk = generate_keypair()
    save_keypair(sk, pk, path)
    return (sk, pk)
