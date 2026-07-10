"""
VPE Backward-Compatibility Shim — original dict-based API delegating to
``seal.core`` (the consolidated single implementation).

All new code should import directly from ``seal.core`` instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from typing import Any

from seal.core import (
    VPE_VERSION,
    _sign_bytes,
)
from seal.core import (
    _canonical_json as _core_canonical_json,
)
from seal.core import (
    generate_key_pair as _core_generate_key_pair,
)
from seal.core import (
    vpe_verify as _core_verify,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VPEEnvelope = dict[str, Any]
DEFAULT_TTL_SECONDS = 300
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

# ---------------------------------------------------------------------------
# VPEResult — result type for verification
# ---------------------------------------------------------------------------


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
        return f"<VPEResult {'VALID' if self.valid else 'INVALID'}: {self.reason}>"

    def __bool__(self) -> bool:
        return self.valid


# ---------------------------------------------------------------------------
# Legacy helpers (re-exported from core with backward-compat names)
# ---------------------------------------------------------------------------


def _ensure_nacl() -> bool:
    return True


def _nacl_sign_available() -> bool:
    return True


_KEY_CACHE: dict[str, tuple] = {}


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair (backward-compat tuple API)."""
    pair = _core_generate_key_pair()
    return (pair["private_key"], pair["public_key"])


def _canonical_json(obj: Any) -> bytes:
    return _core_canonical_json(obj)


def _canonical_envelope(envelope: VPEEnvelope, skip_signature: bool = True) -> bytes:
    """Serialize the signable portion of an envelope (SIGNED_FIELDS order)."""
    payload = {}
    for key in SIGNED_FIELDS:
        if key in envelope:
            value = envelope[key]
            if key == "cert_chain" and value is None:
                continue
            if key == "scope" and isinstance(value, dict):
                value = dict(sorted(value.items()))
            payload[key] = value
    return _core_canonical_json(payload)


# ---------------------------------------------------------------------------
# Sign (backward-compat dict-returning API)
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
    """Create a signed VPE envelope (returns dict, not JSON string)."""
    if not prompt:
        raise ValueError("prompt must not be empty")
    if not issuer:
        raise ValueError("issuer must not be empty")
    if not audience:
        raise ValueError("audience must not be empty")

    nonce = nonce or secrets.token_hex(16)
    doc_sha256 = doc_sha256 or hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    env: VPEEnvelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope or {},
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
        env["public_key"] = public_key.hex()

    env["signature"] = _sign_bytes(_canonical_envelope(env), private_key).hex()
    return env


# ---------------------------------------------------------------------------
# Verify helpers & Verify (backward-compat dict + VPEResult API)
# ---------------------------------------------------------------------------

_ERROR_MISSING_FIELD = "missing required field: {}"
_ERROR_PUBLIC_KEY_MISSING = "no public_key in envelope and no public_key provided"


def _check_required_fields(envelope: VPEEnvelope) -> str | None:
    for field in SIGNED_FIELDS:
        if field not in envelope:
            return _ERROR_MISSING_FIELD.format(field)
    return None


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
    """Verify a VPE envelope (dict input, VPEResult output).

    Checks: 1) required fields, 2) version, 3) TTL expiry,
    4) signature, 5) nonce replay, 6) counter monotonic, 7) scope.
    """
    skip = set(skip_checks or [])

    # 1. Required fields
    err = _check_required_fields(envelope)
    if err:
        return VPEResult(False, err)

    # 2-4. Delegate version check, TTL, and signature to core
    env_str = json.dumps(envelope, separators=(",", ":"))
    core_result = _core_verify(env_str, public_key=public_key)
    if not core_result["valid"]:
        return VPEResult(False, core_result["reason"])

    # 5. Nonce replay
    if "replay" not in skip:
        err = _check_nonce_replay(envelope.get("nonce", ""), seen_nonces)
        if err:
            return VPEResult(False, err)

    # 6. Counter monotonic
    if "counter" not in skip:
        err = _check_counter_monotonic(envelope.get("counter", 0), last_counter)
        if err:
            return VPEResult(False, err)

    # 7. Scope
    if "scope" not in skip:
        err = _check_scope(envelope, actual_args)
        if err:
            return VPEResult(False, err)

    return VPEResult(True, "", envelope)


# ---------------------------------------------------------------------------
# Key file helpers
# ---------------------------------------------------------------------------


def save_keypair(private_key: bytes, public_key: bytes, path: str) -> None:
    """Save a keypair to disk (hex-encoded, chmod 0600)."""
    os.makedirs(path, exist_ok=True)
    for p, data in [
        (os.path.join(path, "vpe_private.key"), private_key),
        (os.path.join(path, "vpe_public.key"), public_key),
    ]:
        with open(p, "wb") as f:
            f.write(data.hex().encode("utf-8"))
        os.chmod(p, 0o600)


def load_keypair(path: str) -> tuple[bytes, bytes]:
    """Load a keypair from disk (hex-encoded)."""
    with open(os.path.join(path, "vpe_private.key")) as f:
        private_key = bytes.fromhex(f.read().strip())
    with open(os.path.join(path, "vpe_public.key")) as f:
        public_key = bytes.fromhex(f.read().strip())
    return (private_key, public_key)


def load_or_generate_keypair(path: str) -> tuple[bytes, bytes]:
    """Load an existing keypair or generate + save a new one."""
    priv_path = os.path.join(path, "vpe_private.key")
    if os.path.exists(priv_path):
        return load_keypair(path)
    sk, pk = generate_keypair()
    save_keypair(sk, pk, path)
    return (sk, pk)
