"""VPE Core — Ed25519 signing and verification of prompt envelopes.

Dual backend: uses ``cryptography`` library as the primary Ed25519 backend, with
``nacl`` (PyNaCl) as an optional fallback when cryptography is unavailable.
"""

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from seal.store import NonceStore

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

VPE_VERSION = "1.0"

_ENVELOPE_FIELDS = [
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

_STRIPPABLE_FIELD_DEFAULTS: dict = {
    "vpe_version": VPE_VERSION,
    "scope": {},
    "issuer": "",
    "audience": "",
    "doc_sha256": "",
    "iat": None,
    "counter": None,
    "cert_chain": None,
}

_DEFAULT_TTL = 300


def _is_strippable_ttl(value) -> bool:
    return value in (_DEFAULT_TTL, 0)


def _strip_empty_fields(envelope: dict) -> dict:
    result = {}
    for key, value in envelope.items():
        if key == "ttl_seconds":
            if _is_strippable_ttl(value):
                continue
        elif key in _STRIPPABLE_FIELD_DEFAULTS:
            if value == _STRIPPABLE_FIELD_DEFAULTS[key]:
                continue
        result[key] = value
    return result


# ---------------------------------------------------------------------------
# Dual-backend Ed25519 Crypto (cryptography primary, nacl fallback)
# ---------------------------------------------------------------------------


def _sign_bytes(data: bytes, private_key: bytes) -> bytes:
    try:
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(data)
    except ImportError:
        import nacl.bindings  # type: ignore[import-untyped]

        _, sk_full = nacl.bindings.crypto_sign_seed_keypair(private_key)
        return nacl.bindings.crypto_sign(data, sk_full)[:64]


def _verify_bytes(data: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        pk.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except ImportError:
        import nacl.bindings  # type: ignore[import-untyped]
        import nacl.exceptions  # type: ignore[import-untyped]

        try:
            nacl.bindings.crypto_sign_open(signature + data, public_key)
            return True
        except nacl.exceptions.BadSignatureError:
            return False


def _nacl_sign_available() -> bool:
    return True


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_key_pair() -> dict:
    try:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return {
            "private_key": private_key.private_bytes_raw(),
            "public_key": public_key.public_bytes_raw(),
        }
    except ImportError:
        import nacl.bindings  # type: ignore[import-untyped]

        pk, sk_full = nacl.bindings.crypto_sign_keypair()
        return {"private_key": sk_full[:32], "public_key": pk}


def _load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------

_CANONICAL_DEFAULTS: dict = {
    "vpe_version": VPE_VERSION,
    "scope": {},
    "issuer": "",
    "audience": "",
    "doc_sha256": "",
    "iat": None,
    "ttl_seconds": 300,
    "nonce": "",
    "counter": None,
    "cert_chain": None,
}


def _canonical_json(envelope: dict) -> bytes:
    ordered = OrderedDict()
    for field in _ENVELOPE_FIELDS:
        default = _CANONICAL_DEFAULTS.get(field, "")
        if field == "scope":
            value = envelope.get("scope", default)
            if isinstance(value, dict):
                value = OrderedDict(sorted(value.items()))
            ordered[field] = value
        elif field == "cert_chain":
            value = envelope.get("cert_chain", default)
            if value is not None:
                ordered[field] = value
        else:
            ordered[field] = envelope.get(field, default)
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def _make_nonce() -> str:
    return secrets.token_hex(16)


def vpe_sign(
    prompt: str,
    scope: dict | None = None,
    issuer: str = "",
    audience: str = "",
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    nonce: str | None = None,
    counter: int | None = None,
    *,
    private_key: bytes,
    cert_chain: list | None = None,
    compact: bool = False,
) -> str:
    """Sign a prompt and produce a VPE envelope JSON string.

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry from now (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter (not set by default).
        private_key: Raw Ed25519 private key bytes.
        cert_chain: Optional certificate chain (root->leaf).
        compact: If True, strip empty/default fields from JSON output.

    Returns:
        Signed envelope as a JSON string.
    """
    envelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope or {},
        "issuer": issuer,
        "audience": audience,
        "doc_sha256": doc_sha256,
        "iat": int(time.time()),
        "ttl_seconds": ttl_seconds,
        "nonce": nonce if nonce is not None else _make_nonce(),
        "counter": counter,
        "cert_chain": cert_chain,
        "signature": "",
    }

    canon = _canonical_json(envelope)
    signature = _sign_bytes(canon, private_key)
    envelope["signature"] = signature.hex()

    if compact:
        envelope = _strip_empty_fields(envelope)

    return json.dumps(envelope, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def vpe_verify(
    envelope_str: str,
    *,
    public_key: bytes | None = None,
    trust_anchor: bytes | None = None,
    not_before: int | None = None,
    not_after: int | None = None,
    nonce_store: NonceStore | None = None,
) -> dict:
    """Verify a VPE envelope string.

    Two modes: **Direct key** (``public_key``) — verify against a known key.
    **Cert-chain** (``trust_anchor``) — walk cert_chain to extract leaf key.

    Checks: 1) JSON parse, 2) version match, 3) signature present,
    4) scope is dict, 5) nonce non-empty, 6) counter is int,
    7) TTL type check, 8) nonce replay (via NonceStore),
    9) public key resolution, 10) crypto signature, 11) TTL expiry,
    12) key time constraints (not_before/not_after).

    Args:
        envelope_str: The JSON envelope from ``vpe_sign``.
        public_key: Raw Ed25519 public key (for direct verification).
        trust_anchor: Raw Ed25519 root CA key (for chain verification).
        not_before: Optional Unix timestamp — key valid after this.
        not_after: Optional Unix timestamp — key valid before this.
        nonce_store: Optional ``NonceStore`` for replay detection.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}"}

    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_signature"}

    scope = envelope.get("scope", {})
    if not isinstance(scope, dict):
        return {"valid": False, "reason": "scope_not_dict"}

    nonce = envelope.get("nonce", "")
    if not isinstance(nonce, str) or nonce == "":
        return {"valid": False, "reason": "missing_or_empty_nonce"}

    counter = envelope.get("counter")
    if counter is not None and not isinstance(counter, int):
        return {"valid": False, "reason": "counter_not_integer"}

    ttl = envelope.get("ttl_seconds", 0)
    if not isinstance(ttl, int):
        return {"valid": False, "reason": "ttl_not_integer"}

    if nonce_store is not None and ttl > 0:
        if not nonce_store.add(nonce):
            return {"valid": False, "reason": "nonce_reused"}

    cert_chain = envelope.get("cert_chain")
    if trust_anchor is not None and cert_chain is not None:
        chain_result = verify_cert_chain(cert_chain, trust_anchor=trust_anchor)
        if not chain_result["valid"]:
            return {"valid": False, "reason": f"cert_chain_failed: {chain_result['reason']}"}
        effective_pk_bytes = chain_result["leaf_public_key"]
    elif public_key is not None:
        effective_pk_bytes = public_key
    else:
        return {"valid": False, "reason": "no_verification_key: provide public_key or trust_anchor"}

    verify_envelope = dict(envelope)
    verify_envelope["signature"] = ""
    canon = _canonical_json(verify_envelope)

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return {"valid": False, "reason": "invalid_signature_encoding"}

    if not _verify_bytes(canon, sig_bytes, effective_pk_bytes):
        return {"valid": False, "reason": "signature_mismatch"}

    now = int(time.time())
    if ttl > 0:
        iat = envelope.get("iat")
        if iat is None:
            pass
        elif not isinstance(iat, int):
            return {"valid": False, "reason": "iat_not_integer"}
        elif now - iat > ttl:
            return {"valid": False, "reason": "envelope_expired"}

    if not_before is not None and now < not_before:
        return {"valid": False, "reason": "key_not_yet_valid"}
    if not_after is not None and now >= not_after:
        return {"valid": False, "reason": "key_expired"}

    return {"valid": True, "reason": "ok"}


# ---------------------------------------------------------------------------
# HMAC-SHA256 alternative (internal/low-security contexts)
# ---------------------------------------------------------------------------

HMAC_SIGNATURE_BYTES = 32


def vpe_sign_hmac(
    prompt: str,
    scope: dict | None = None,
    issuer: str = "",
    audience: str = "",
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    nonce: str | None = None,
    counter: int | None = None,
    *,
    shared_secret: bytes,
    compact: bool = False,
) -> str:
    """Sign a prompt with HMAC-SHA256 (symmetric, 10-100x faster, stdlib-only).

    Ed25519: asymmetric, public-verify, non-repudiation.
    HMAC: symmetric, secret-key, faster, stdlib-only.

    Use HMAC when all signers/verifiers share a trust boundary, throughput
    matters, or zero crypto deps needed.  Don't use for public verifiability.

    Args:
        prompt: The actionable instruction to sign.
        scope: Capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 of source document.
        ttl_seconds: Seconds until expiry (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        shared_secret: HMAC key (min 32 bytes).
        compact: Strip defaults from JSON output.

    Returns:
        Signed envelope as a JSON string.
    """
    if not isinstance(shared_secret, bytes) or len(shared_secret) == 0:
        raise ValueError("shared_secret must be non-empty bytes")

    envelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope or {},
        "issuer": issuer,
        "audience": audience,
        "doc_sha256": doc_sha256,
        "iat": int(time.time()),
        "ttl_seconds": ttl_seconds,
        "nonce": nonce if nonce is not None else _make_nonce(),
        "counter": counter,
        "signature": "",
    }

    canon = _canonical_json(envelope)
    envelope["signature"] = hmac.new(shared_secret, canon, hashlib.sha256).hexdigest()

    if compact:
        envelope = _strip_empty_fields(envelope)

    return json.dumps(envelope, separators=(",", ":"))


def vpe_verify_hmac(
    envelope_str: str,
    *,
    shared_secret: bytes,
    not_before: int | None = None,
    not_after: int | None = None,
) -> dict:
    """Verify a HMAC-SHA256 signed VPE envelope.

    Checks: 1) JSON parse, 2) version, 3) signature, 4) scope is dict,
    5) nonce non-empty, 6) counter is int, 7) TTL is int,
    8) HMAC signature, 9) TTL expiry, 10) key time constraints.

    Args:
        envelope_str: The JSON envelope from ``vpe_sign_hmac``.
        shared_secret: HMAC key (must match sign-time secret).
        not_before: Optional key validity start.
        not_after: Optional key validity end.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}"}

    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_signature"}

    scope = envelope.get("scope", {})
    if not isinstance(scope, dict):
        return {"valid": False, "reason": "scope_not_dict"}

    nonce = envelope.get("nonce", "")
    if not isinstance(nonce, str) or nonce == "":
        return {"valid": False, "reason": "missing_or_empty_nonce"}

    counter = envelope.get("counter")
    if counter is not None and not isinstance(counter, int):
        return {"valid": False, "reason": "counter_not_integer"}

    ttl = envelope.get("ttl_seconds", 0)
    if not isinstance(ttl, int):
        return {"valid": False, "reason": "ttl_not_integer"}

    verify_envelope = dict(envelope)
    verify_envelope["signature"] = ""
    canon = _canonical_json(verify_envelope)
    expected = hmac.new(shared_secret, canon, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig_hex, expected):
        return {"valid": False, "reason": "signature_mismatch"}

    now = int(time.time())
    if ttl > 0:
        iat = envelope.get("iat")
        if iat is None:
            pass
        elif not isinstance(iat, int):
            return {"valid": False, "reason": "iat_not_integer"}
        elif now - iat > ttl:
            return {"valid": False, "reason": "envelope_expired"}

    if not_before is not None and now < not_before:
        return {"valid": False, "reason": "key_not_yet_valid"}
    if not_after is not None and now >= not_after:
        return {"valid": False, "reason": "key_expired"}

    return {"valid": True, "reason": "ok"}


# ---------------------------------------------------------------------------
# Certificate chain — hierarchical key support (P9.1)
# ---------------------------------------------------------------------------
#
# Self-describing JSON certs: each carries subject+issuer Ed25519 public keys.
# Chain: root CA -> intermediate -> leaf signing key (root-first in cert_chain).

CERT_VERSION = "1.0"
_CERT_DEFAULT_TTL = 365 * 24 * 3600


def _make_cert_serial() -> str:
    return secrets.token_hex(8)


def _canonical_cert(cert: dict) -> bytes:
    ordered = OrderedDict()
    ordered["cert_version"] = cert.get("cert_version", "")
    ordered["subject_id"] = cert.get("subject_id", "")
    ordered["subject_public_key"] = cert.get("subject_public_key", "")
    ordered["issuer_id"] = cert.get("issuer_id", "")
    ordered["issuer_public_key"] = cert.get("issuer_public_key", "")
    ordered["serial"] = cert.get("serial", "")
    ordered["not_before"] = cert.get("not_before", 0)
    ordered["not_after"] = cert.get("not_after", 0)
    ordered["metadata"] = cert.get("metadata", {})
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def create_certificate(
    *,
    subject_public_key: bytes,
    subject_id: str,
    issuer_private_key: bytes,
    issuer_id: str,
    issuer_public_key: bytes,
    serial: str = "",
    not_before: int | None = None,
    not_after: int | None = None,
    metadata: dict | None = None,
) -> dict:
    """Create a signed certificate binding a subject key to an issuer.

    Self-describing: carries both subject+issuer public keys so verifiers
    only need the root trust anchor.

    Args:
        subject_public_key: Public key being certified (raw 32 bytes).
        subject_id: Identity string (e.g. ``"ca:interm-01"``).
        issuer_private_key: Private key of the signing issuer.
        issuer_id: Identity of the issuer.
        issuer_public_key: Issuer's public key (raw 32 bytes).
        serial: Unique serial (auto-generated if omitted).
        not_before: Validity start (default: now).
        not_after: Validity end (default: now + 1 year).
        metadata: Optional extra metadata.

    Returns:
        The signed certificate (dict).
    """
    now = int(time.time())
    cert = {
        "cert_version": CERT_VERSION,
        "subject_id": subject_id,
        "subject_public_key": subject_public_key.hex(),
        "issuer_id": issuer_id,
        "issuer_public_key": issuer_public_key.hex(),
        "serial": serial or _make_cert_serial(),
        "not_before": not_before if not_before is not None else now,
        "not_after": not_after if not_after is not None else now + _CERT_DEFAULT_TTL,
        "metadata": metadata or {},
        "signature": "",
    }
    canon = _canonical_cert(cert)
    cert["signature"] = _sign_bytes(canon, issuer_private_key).hex()
    return cert


def verify_certificate(cert: dict, *, parent_public_key: bytes) -> dict:
    """Verify a single certificate's signature.

    Args:
        cert: Certificate dict (from ``create_certificate``).
        parent_public_key: Raw Ed25519 public key of the parent CA.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    sig_hex = cert.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_cert_signature"}

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return {"valid": False, "reason": "invalid_cert_signature_encoding"}

    verify = dict(cert)
    verify["signature"] = ""
    canon = _canonical_cert(verify)

    if _verify_bytes(canon, sig_bytes, parent_public_key):
        return {"valid": True, "reason": "ok"}
    else:
        return {"valid": False, "reason": "cert_signature_mismatch"}


def verify_cert_chain(chain: list, *, trust_anchor: bytes) -> dict:
    """Walk a certificate chain root->leaf and verify every link.

    Args:
        chain: List of cert dicts root-first (index 0 = root, -1 = leaf).
        trust_anchor: Raw Ed25519 root CA public key.

    Returns:
        dict with ``valid``, ``reason``, ``leaf_public_key``.
    """
    if not chain:
        return {"valid": False, "reason": "empty_cert_chain", "leaf_public_key": None}

    root = chain[0]
    try:
        root_subject_pk = bytes.fromhex(root.get("subject_public_key", ""))
    except ValueError:
        return {"valid": False, "reason": "invalid_root_public_key_hex", "leaf_public_key": None}

    if root_subject_pk != trust_anchor:
        return {"valid": False, "reason": "root_public_key_mismatch_trust_anchor", "leaf_public_key": None}

    result = verify_certificate(root, parent_public_key=trust_anchor)
    if not result["valid"]:
        return {"valid": False, "reason": f"root_cert_failed: {result['reason']}", "leaf_public_key": None}

    parent_public_key = trust_anchor
    for i in range(1, len(chain)):
        cert = chain[i]
        result = verify_certificate(cert, parent_public_key=parent_public_key)
        if not result["valid"]:
            return {"valid": False, "reason": f"chain_link_{i}_failed: {result['reason']}", "leaf_public_key": None}

        try:
            parent_public_key = bytes.fromhex(cert.get("subject_public_key", ""))
        except ValueError:
            return {"valid": False, "reason": f"chain_link_{i}_invalid_public_key_hex", "leaf_public_key": None}

    return {"valid": True, "reason": "ok", "leaf_public_key": parent_public_key}


# ---------------------------------------------------------------------------
# Multi-signature (N-of-M) support
# ---------------------------------------------------------------------------

_MULTI_ENVELOPE_FIELDS = _ENVELOPE_FIELDS + ["threshold"]


def _canonical_json_multi(envelope: dict) -> bytes:
    ordered = OrderedDict()
    for field in _MULTI_ENVELOPE_FIELDS:
        if field == "scope":
            value = envelope.get("scope", {})
            if isinstance(value, dict):
                value = OrderedDict(sorted(value.items()))
            ordered[field] = value
        elif field == "threshold":
            value = envelope.get("threshold")
            if value is not None:
                ordered[field] = value
        else:
            ordered[field] = envelope.get(field, "")
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def vpe_sign_multi(
    prompt: str,
    scope: dict | None = None,
    issuer: str = "",
    audience: str = "",
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    nonce: str | None = None,
    counter: int | None = None,
    threshold: int = 1,
    *,
    private_key: bytes,
    key_id: str = "default",
    existing_envelope: str | None = None,
) -> str:
    """Create or incrementally update a multi-signature VPE envelope.

    First signer (existing_envelope=None): fresh envelope with signatures array.
    Additional signer (existing_envelope): appends signature, checks no key_id reuse.

    Args:
        prompt: The actionable instruction to sign.
        scope: Capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 of source document.
        ttl_seconds: Seconds until expiry (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        threshold: Min distinct signatures required (>=1).
        private_key: Raw Ed25519 private key bytes.
        key_id: Unique identifier for this signer.
        existing_envelope: Previous multi-sig JSON, or None for fresh.

    Returns:
        Multi-sig envelope as a JSON string.
    """
    if threshold < 1:
        raise ValueError(f"threshold must be >= 1, got {threshold}")

    if existing_envelope is not None:
        existing = json.loads(existing_envelope)
        if not isinstance(existing, dict):
            raise ValueError("existing_envelope is not a JSON object")

        existing_sigs = existing.get("signatures", [])
        if not isinstance(existing_sigs, list):
            raise ValueError("existing_envelope.signatures is not a list")

        for entry in existing_sigs:
            if entry.get("key_id") == key_id:
                raise ValueError(f"key_id {key_id!r} has already signed this envelope")

        canon = _canonical_json_multi(existing)
        sig_bytes = _sign_bytes(canon, private_key)
        new_entry = {"key_id": key_id, "sig": sig_bytes.hex()}
        envelope = dict(existing)
        envelope["signatures"] = existing_sigs + [new_entry]
        return json.dumps(envelope, separators=(",", ":"))

    else:
        envelope = {
            "vpe_version": VPE_VERSION,
            "prompt": prompt,
            "scope": scope or {},
            "issuer": issuer,
            "audience": audience,
            "doc_sha256": doc_sha256,
            "ttl_seconds": ttl_seconds,
            "nonce": nonce if nonce is not None else _make_nonce(),
            "counter": counter,
            "threshold": threshold,
            "signatures": [],
        }
        canon = _canonical_json_multi(envelope)
        sig_bytes = _sign_bytes(canon, private_key)
        envelope["signatures"] = [{"key_id": key_id, "sig": sig_bytes.hex()}]
        return json.dumps(envelope, separators=(",", ":"))


def vpe_verify_multi(
    envelope_str: str,
    *,
    public_keys: dict[str, bytes],
    not_before: int | None = None,
    not_after: int | None = None,
) -> dict:
    """Verify a multi-signature VPE envelope against an N-of-M threshold.

    Checks: 1) JSON parse, 2) version, 3-4) threshold+signatures present,
    5-8) each sig valid, key_id known, no duplicates, 9) count >= threshold,
    10) key time constraints.

    Args:
        envelope_str: Multi-sig envelope JSON.
        public_keys: Mapping of key_id -> raw Ed25519 public key bytes.
        not_before: Key validity start.
        not_after: Key validity end.

    Returns:
        dict with ``valid``, ``reason``, ``details``.
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}", "details": {}}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict", "details": {}}

    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}", "details": {}}

    threshold = envelope.get("threshold")
    if threshold is None:
        return {"valid": False, "reason": "missing_threshold", "details": {}}
    if not isinstance(threshold, int) or threshold < 1:
        return {"valid": False, "reason": f"invalid_threshold: {threshold}", "details": {}}

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) == 0:
        return {"valid": False, "reason": "missing_or_empty_signatures", "details": {}}

    seen_key_ids: set[str] = set()
    valid_count = 0
    details = {
        "threshold": threshold,
        "signature_count": len(signatures),
        "valid_signatures": [],
        "invalid_signatures": [],
        "duplicate_key_ids": [],
        "unknown_key_ids": [],
    }

    for i, entry in enumerate(signatures):
        if not isinstance(entry, dict):
            details["invalid_signatures"].append({"index": i, "reason": "entry_not_dict"})
            continue

        key_id = entry.get("key_id", "")
        sig = entry.get("sig", "")

        if not isinstance(key_id, str) or not key_id:
            details["invalid_signatures"].append({"index": i, "reason": "missing_or_empty_key_id"})
            continue

        if not isinstance(sig, str) or not sig:
            details["invalid_signatures"].append({"index": i, "key_id": key_id, "reason": "missing_or_empty_sig"})
            continue

        if key_id in seen_key_ids:
            details["duplicate_key_ids"].append(key_id)
            continue
        seen_key_ids.add(key_id)

        if key_id not in public_keys:
            details["unknown_key_ids"].append(key_id)
            continue

        try:
            sig_bytes = bytes.fromhex(sig)
        except ValueError:
            details["invalid_signatures"].append({"index": i, "key_id": key_id, "reason": "invalid_sig_encoding"})
            continue

        canon = _canonical_json_multi(envelope)
        if _verify_bytes(canon, sig_bytes, public_keys[key_id]):
            valid_count += 1
            details["valid_signatures"].append(key_id)
        else:
            details["invalid_signatures"].append({"index": i, "key_id": key_id, "reason": "signature_mismatch"})

    now = int(time.time())
    if not_before is not None and now < not_before:
        return {"valid": False, "reason": "key_not_yet_valid", "details": details}
    if not_after is not None and now >= not_after:
        return {"valid": False, "reason": "key_expired", "details": details}

    has_issues = (
        len(details["invalid_signatures"]) > 0
        or len(details["duplicate_key_ids"]) > 0
        or len(details["unknown_key_ids"]) > 0
    )
    if valid_count >= threshold and not has_issues:
        return {"valid": True, "reason": "ok", "details": details}
    else:
        reasons = []
        if valid_count < threshold:
            reasons.append(f"insufficient_valid_signatures: {valid_count} < {threshold}")
        if details["duplicate_key_ids"]:
            reasons.append(f"duplicate_key_ids: {details['duplicate_key_ids']}")
        if details["unknown_key_ids"]:
            reasons.append(f"unknown_key_ids: {details['unknown_key_ids']}")
        if details["invalid_signatures"]:
            reasons.append(f"invalid_signatures: {len(details['invalid_signatures'])} failed")
        return {"valid": False, "reason": "; ".join(reasons), "details": details}


# ---------------------------------------------------------------------------
# Hardware-backed signing (P9.4)
# ---------------------------------------------------------------------------

SIG_ALG_ED25519 = "ed25519"
SIG_ALG_ECDSA_P256 = "ecdsa-p256"


def vpe_sign_hardware(
    prompt: str,
    scope: dict | None = None,
    issuer: str = "",
    audience: str = "",
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    nonce: str | None = None,
    counter: int | None = None,
    *,
    provider_name: str = "",
) -> str:
    """Sign a prompt using a hardware-backed key (YubiKey, TPM, Secure Enclave)
    or fallback Ed25519.  The envelope carries ``sig_algorithm`` for the verifier.

    Args:
        prompt: The actionable instruction to sign.
        scope: Capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 of source document.
        ttl_seconds: Seconds until expiry (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        provider_name: Explicit provider (e.g. ``"yubikey"``). Empty=auto-detect.

    Returns:
        Signed envelope as JSON string.
    """
    from seal.hardware import HsmManager

    mgr = HsmManager()
    if provider_name:
        provider = mgr.get_provider(provider_name)
        if provider is None:
            raise ValueError(
                f"hardware provider {provider_name!r} not available. Available: {[p.name for p in mgr.discover()]}"
            )
    else:
        provider = mgr.default_provider

    envelope = {
        "vpe_version": VPE_VERSION,
        "prompt": prompt,
        "scope": scope or {},
        "issuer": issuer,
        "audience": audience,
        "doc_sha256": doc_sha256,
        "ttl_seconds": ttl_seconds,
        "nonce": nonce if nonce is not None else _make_nonce(),
        "counter": counter,
        "sig_algorithm": provider.sig_algorithm,
        "signature": "",
    }

    canon = _canonical_json(_strip_sig_alg(envelope))
    key = provider.generate(f"vpe_{issuer}" if issuer else "vpe_default")
    sig_bytes = provider.sign(canon, key.key_id)
    envelope["signature"] = sig_bytes.hex()
    return json.dumps(envelope, separators=(",", ":"))


def _strip_sig_alg(envelope: dict) -> dict:
    d = dict(envelope)
    d.pop("sig_algorithm", None)
    return d


def vpe_verify_hardware(
    envelope_str: str,
    *,
    public_key: bytes,
    sig_algorithm: str = SIG_ALG_ED25519,
) -> dict:
    """Verify a VPE envelope signed by a hardware provider.

    Supports Ed25519 and ECDSA-P256.  For Ed25519 delegates to ``vpe_verify()``.

    Args:
        envelope_str: The JSON envelope.
        public_key: Raw public key (32 bytes Ed25519 or SPKI DER for ECDSA).
        sig_algorithm: ``"ed25519"`` (default) or ``"ecdsa-p256"``.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    if sig_algorithm == SIG_ALG_ED25519:
        return vpe_verify(envelope_str, public_key=public_key)

    if sig_algorithm != SIG_ALG_ECDSA_P256:
        return {"valid": False, "reason": f"unsupported_sig_algorithm: {sig_algorithm}"}

    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}"}

    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_signature"}

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return {"valid": False, "reason": "invalid_signature_encoding"}

    verify_envelope = _strip_sig_alg(dict(envelope))
    verify_envelope["signature"] = ""
    canon = _canonical_json(verify_envelope)

    from seal.hardware import verify_ecdsa_p256

    if verify_ecdsa_p256(sig_bytes, canon, public_key):
        return {"valid": True, "reason": "ok"}
    else:
        return {"valid": False, "reason": "signature_mismatch"}


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def envelope_to_json(envelope: dict) -> str:
    return json.dumps(envelope, separators=(",", ":"))


def envelope_from_json(data: str) -> dict:
    return json.loads(data)
