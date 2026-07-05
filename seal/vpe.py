"""
VPE Core — Verified Prompt Envelope Protocol.

Ed25519-signed prompt envelopes for cryptographic provenance verification
of AI agent prompts.

Public API:
    vpe_sign(prompt, scope, issuer, audience, ...) -> dict
    vpe_verify(envelope) -> VPEResult
    VPE_VERSION
    VPEResult (namedtuple with valid: bool, reason: str)
    VPEEnvelope (type alias for dict)

Protocol version: 1.0
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from typing import Any

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

VPE_VERSION = "1.0"
"""Current protocol version string."""

DEFAULT_TTL_SECONDS = 300
"""Default envelope time-to-live in seconds (5 minutes)."""

SIGNED_FIELDS = [
    "vpe_version",
    "prompt",
    "scope",
    "issuer",
    "audience",
    "doc_sha256",
    "iat",
    "ttl_seconds",
    "nonce",
    "counter",
    "cert_chain",
]
"""Fields that are signed in order (excluding 'signature' itself)."""

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

VPEEnvelope = dict[str, Any]
"""A signed VPE envelope as a JSON-serializable dict."""


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
# Ed25519 key helpers
# ---------------------------------------------------------------------------

_KEY_CACHE: dict[str, tuple] = {}


def _ensure_nacl() -> bool:
    """Check that the NaCl/cryptography library is available.

    Returns True if available, False otherwise.  Callers should fall back
    gracefully when crypto is absent (emit "unverified" envelopes).
    """
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
    """Check if we have a signing-capable crypto backend."""
    return _ensure_nacl()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair.

    Returns:
        (private_seed_bytes, public_key_bytes) — private seed is 32 bytes,
        public key is 32 bytes.
    """
    try:
        import nacl.bindings
        # nacl returns (pk_32, sk_64) where sk_64 = seed_32 || pk_32
        pk, sk_full = nacl.bindings.crypto_sign_keypair()
        sk = sk_full[:32]  # store only the 32-byte seed
        return (sk, pk)
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
    """Sign data with an Ed25519 private key.

    Args:
        data: The bytes to sign.
        private_key: 32-byte Ed25519 private seed key.

    Returns:
        64-byte signature.
    """
    try:
        import nacl.bindings
        # nacl needs the full 64-byte secret key (seed || pk), so
        # derive it from the 32-byte seed
        pk_from_seed, sk_full = nacl.bindings.crypto_sign_seed_keypair(private_key)
        return nacl.bindings.crypto_sign(data, sk_full)[:64]
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(data)


def _verify_bytes(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature over data.

    Args:
        data: The signed bytes.
        signature: 64-byte signature.
        public_key: 32-byte Ed25519 public key.

    Returns:
        True if the signature is valid.
    """
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
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Canonical serialization
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    """Serialize to canonical JSON using key insertion order (no whitespace).

    This matches core.py's approach: field order is driven by the caller
    (_canonical_envelope builds payload in SIGNED_FIELDS order), NOT
    alphabetical sort_keys. Both signer and verifier must produce
    identical bytes.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


def _canonical_envelope(envelope: VPEEnvelope, skip_signature: bool = True) -> bytes:
    """Serialize the signable portion of an envelope to bytes.

    Only SIGNED_FIELDS are included, in the order they appear in the envelope.
    If skip_signature is True, the 'signature' key is excluded.
    """
    payload = {}
    for key in SIGNED_FIELDS:
        if key in envelope:
            value = envelope[key]
            # Match core.py: omit cert_chain when None
            if key == "cert_chain" and value is None:
                continue
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
        issuer: Who/what is authorizing this (e.g. "user:rez").
        audience: Which agent should execute (e.g. "agent:hermes-default").
        private_key: 32-byte Ed25519 private (seed) key.

    Keyword Args:
        scope: Capability restrictions (allowed_tools, max_tokens, etc.).
        doc_sha256: SHA-256 of the source document this prompt binds to.
        ttl_seconds: Seconds until expiry from now (default 300).
        nonce: Unique value for replay prevention (auto-generated if None).
        counter: Monotonic counter for skipped-prompt detection.
        public_key: Optionally embed the public key in the envelope for
                    self-contained verification.

    Returns:
        A VPEEnvelope dict with all fields plus 'signature'.
    """
    if not _nacl_sign_available():
        raise RuntimeError(
            "Ed25519 signing requires the 'nacl' (PyNaCl) or 'cryptography' library. "
            "Install with: pip install pynacl"
        )

    if not prompt:
        raise ValueError("prompt must not be empty")
    if not issuer:
        raise ValueError("issuer must not be empty")
    if not audience:
        raise ValueError("audience must not be empty")

    if nonce is None:
        nonce = secrets.token_hex(16)

    if scope is None:
        scope = {}

    if doc_sha256 is None:
        doc_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    envelope: VPEEnvelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope,
        "issuer": issuer,
        "audience": audience,
        "doc_sha256": doc_sha256,
        "ttl_seconds": ttl_seconds,
        "iat": int(time.time()),
        "nonce": nonce,
        "counter": counter,
        "cert_chain": None,
    }

    if public_key is not None:
        envelope["public_key"] = public_key.hex()

    # Canonicalize and sign
    to_sign = _canonical_envelope(envelope)
    envelope["signature"] = _sign_bytes(to_sign, private_key).hex()

    return envelope


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


_ERROR_MISSING_CRYPTO = "no crypto library available (install pynacl or cryptography)"
_ERROR_INVALID_SIGNATURE = "signature verification failed"
_ERROR_EXPIRED = "envelope has expired"
_ERROR_VERSION_MISMATCH = "envelope version mismatch"
_ERROR_MISSING_FIELD = "missing required field: {}"
_ERROR_TAMPERED = "envelope content has been tampered with (signature mismatch)"
_ERROR_PUBLIC_KEY_MISSING = "no public_key in envelope and no public_key provided"


def _check_required_fields(envelope: VPEEnvelope) -> str | None:
    """Check that all SIGNED_FIELDS are present.

    Returns None if OK, or an error string.
    """
    for field in SIGNED_FIELDS:
        if field not in envelope:
            return _ERROR_MISSING_FIELD.format(field)
    return None


def _check_version(envelope: VPEEnvelope) -> str | None:
    """Check that vpe_version is compatible."""
    version = envelope.get("vpe_version", "")
    if version != VPE_VERSION:
        return f"{_ERROR_VERSION_MISMATCH}: expected {VPE_VERSION}, got {version}"
    return None


def _check_expiry(envelope: VPEEnvelope) -> str | None:
    """Check TTL expiry."""
    ttl = envelope.get("ttl_seconds", 0)
    if ttl <= 0:
        return None  # no expiry
    issued_at = envelope.get("iat", 0)
    if issued_at <= 0:
        return None  # no timestamp, skip TTL check
    now = int(time.time())
    if now > issued_at + ttl:
        return _ERROR_EXPIRED
    return None


def _check_nonce_replay(nonce: str, seen_nonces: set | None = None) -> str | None:
    """Check if a nonce has been seen before (replay prevention).

    Args:
        nonce: The nonce string from the envelope.
        seen_nonces: Optional set of previously seen nonces.

    Returns:
        Error string if replayed, None otherwise.
    """
    if seen_nonces is not None and nonce in seen_nonces:
        return "nonce replay detected"
    if seen_nonces is not None:
        seen_nonces.add(nonce)
    return None


def _check_counter_monotonic(counter: int, last_counter: int | None = None) -> str | None:
    """Check that the counter is monotonic.

    Args:
        counter: The counter value from the envelope.
        last_counter: The last counter value seen from this issuer+audience.

    Returns:
        Error string if non-monotonic, None otherwise.
    """
    if last_counter is not None and counter <= last_counter:
        return f"non-monotonic counter: {counter} <= {last_counter}"
    return None


def _check_scope(envelope: VPEEnvelope, actual_args: dict[str, Any] | None = None) -> str | None:
    """Check scope constraints against actual arguments.

    Args:
        envelope: The VPE envelope.
        actual_args: Optional dict of actual tool arguments to validate.

    Returns:
        Error string if scope is violated, None otherwise.
    """
    scope = envelope.get("scope", {})
    if not scope or actual_args is None:
        return None  # no scope constraints to check

    # allowed_tools check
    allowed_tools = scope.get("allowed_tools")
    if allowed_tools is not None:
        tool_name = actual_args.get("_tool_name", "")
        if tool_name and tool_name not in allowed_tools:
            return f"tool '{tool_name}' not in allowed_tools: {allowed_tools}"

    # max_cost check
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

    Checks performed (in order):
        1. Required fields present
        2. Crypto library available
        3. Protocol version match
        4. TTL expiry (if ttl_seconds > 0 and iat set)
        5. Signature validity
        6. Nonce replay (if seen_nonces provided)
        7. Counter monotonic (if last_counter provided)
        8. Scope constraints (if actual_args provided)

    Args:
        envelope: The VPE envelope dict to verify.

    Keyword Args:
        public_key: 32-byte Ed25519 public key. If not provided, extracted
                    from envelope['public_key'] (hex).
        seen_nonces: Optional set for replay detection.
        last_counter: Optional last counter for monotonicity check.
        actual_args: Optional tool-call arguments for scope validation.
        skip_checks: Optional list of check names to skip.
                    Valid values: ["expiry", "replay", "counter", "scope"].

    Returns:
        VPEResult with valid=True/False and reason.
    """
    skip = set(skip_checks or [])

    # 1. Required fields
    err = _check_required_fields(envelope)
    if err:
        return VPEResult(False, err)

    # 2. Crypto
    if not _ensure_nacl():
        return VPEResult(False, _ERROR_MISSING_CRYPTO)

    # 3. Version
    if "version" not in skip:
        err = _check_version(envelope)
        if err:
            return VPEResult(False, err)

    # 4. Expiry
    if "expiry" not in skip:
        err = _check_expiry(envelope)
        if err:
            return VPEResult(False, err)

    # 5. Signature
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
        return VPEResult(False, _ERROR_INVALID_SIGNATURE)

    # 6. Nonce replay
    if "replay" not in skip:
        err = _check_nonce_replay(envelope.get("nonce", ""), seen_nonces)
        if err:
            return VPEResult(False, err)

    # 7. Counter monotonic
    if "counter" not in skip:
        err = _check_counter_monotonic(envelope.get("counter", 0), last_counter)
        if err:
            return VPEResult(False, err)

    # 8. Scope
    if "scope" not in skip:
        err = _check_scope(envelope, actual_args)
        if err:
            return VPEResult(False, err)

    return VPEResult(True, "", envelope)


# ---------------------------------------------------------------------------
# Key file helpers
# ---------------------------------------------------------------------------


def save_keypair(private_key: bytes, public_key: bytes, path: str) -> None:
    """Save a keypair to disk (hex-encoded, chmod 0600).

    Args:
        private_key: 32-byte Ed25519 private key.
        public_key: 32-byte Ed25519 public key.
        path: Directory path. Keys saved as <path>/vpe_private.key and <path>/vpe_public.key.
    """
    os.makedirs(path, exist_ok=True)
    priv_path = os.path.join(path, "vpe_private.key")
    pub_path = os.path.join(path, "vpe_public.key")

    for p, data in [(priv_path, private_key), (pub_path, public_key)]:
        with open(p, "wb") as f:
            f.write(data.hex().encode("utf-8"))
        os.chmod(p, 0o600)


def load_keypair(path: str) -> tuple[bytes, bytes]:
    """Load a keypair from disk.

    Args:
        path: Directory path. Keys read from <path>/vpe_private.key and <path>/vpe_public.key.

    Returns:
        (private_key_bytes, public_key_bytes)
    """
    priv_path = os.path.join(path, "vpe_private.key")
    pub_path = os.path.join(path, "vpe_public.key")

    with open(priv_path) as f:
        private_key = bytes.fromhex(f.read().strip())
    with open(pub_path) as f:
        public_key = bytes.fromhex(f.read().strip())

    return (private_key, public_key)


def load_or_generate_keypair(path: str) -> tuple[bytes, bytes]:
    """Load existing keypair from disk, or generate and save a new one.

    Args:
        path: Directory path for key files.

    Returns:
        (private_key, public_key)
    """
    priv_path = os.path.join(path, "vpe_private.key")
    if os.path.exists(priv_path):
        return load_keypair(path)
    sk, pk = generate_keypair()
    save_keypair(sk, pk, path)
    return (sk, pk)
