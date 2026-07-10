"""VPE Core — Ed25519 signing and verification of prompt envelopes (cryptography-only)."""

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict

from cryptography.exceptions import InvalidSignature

from seal._base import (
    _ENVELOPE_FIELDS,
    HMAC_SIGNATURE_BYTES,
    VPE_VERSION,
    _canonical_json,
    _load_private_key,
    _load_public_key,
    _make_nonce,
    _strip_empty_fields,
    generate_key_pair,
)

# -- re-export for backward compatibility ------------------------------------
__all__ = [
    "HMAC_SIGNATURE_BYTES",
    "VPE_VERSION",
    "generate_key_pair",
    "vpe_sign",
    "vpe_verify",
    "vpe_sign_hmac",
    "vpe_verify_hmac",
    "vpe_sign_multi",
    "vpe_verify_multi",
    "vpe_sign_hardware",
    "vpe_verify_hardware",
    "create_certificate",
    "verify_certificate",
    "verify_cert_chain",
    "envelope_to_json",
    "envelope_from_json",
]

# ---------------------------------------------------------------------------
# Sign (Ed25519)
# ---------------------------------------------------------------------------


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
    """Sign a prompt, return VPE envelope JSON string.

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        private_key: Raw Ed25519 private key bytes.
        cert_chain: Certificate chain for hierarchical key support.
        compact: Strip empty/default fields from wire format.
    """
    sk = _load_private_key(private_key)
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
    envelope["signature"] = sk.sign(canon).hex()
    if compact:
        envelope = _strip_empty_fields(envelope)
    return json.dumps(envelope, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Verify (Ed25519)
# ---------------------------------------------------------------------------


def vpe_verify(
    envelope_str: str,
    *,
    public_key: bytes | None = None,
    trust_anchor: bytes | None = None,
    not_before: int | None = None,
    not_after: int | None = None,
    nonce_store=None,
) -> dict:
    """Verify a VPE envelope string.

    Two verification modes:

    **Direct key** (``public_key``):
        Verify the envelope signature directly against the provided public key.

    **Cert-chain** (``trust_anchor``):
        When the envelope contains a ``cert_chain`` field, walks the chain to
        extract the leaf public key. The ``trust_anchor`` must match the root
        certificate's subject public key.

    Checks: JSON parse, version, signature, TTL expiry, scope is dict, nonce
    present, nonce replay, counter type, cert chain, key time constraints.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}
    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    if envelope.get("vpe_version", VPE_VERSION) != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {envelope.get('vpe_version')}"}

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

    pk = _load_public_key(effective_pk_bytes)
    try:
        pk.verify(sig_bytes, canon)
    except InvalidSignature:
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
    """Sign a prompt with HMAC-SHA256 for internal/low-security contexts.

    Symmetric-only (no non-repudiation), 32-byte signatures vs 64-byte Ed25519.

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        shared_secret: HMAC key bytes (min 32 bytes recommended).
        compact: Strip empty/default fields from wire format.
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
    Checks: JSON parse, version, signature, TTL, scope, nonce, counter,
    constant-time HMAC comparison, key time constraints.
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}
    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    if envelope.get("vpe_version", VPE_VERSION) != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {envelope.get('vpe_version')}"}

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
    """Create a signed certificate binding a subject key to an issuer."""
    sk = _load_private_key(issuer_private_key)
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
    cert["signature"] = sk.sign(canon).hex()
    return cert


def verify_certificate(cert: dict, *, parent_public_key: bytes) -> dict:
    """Verify a single certificate's signature against a parent public key."""
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
    pk = _load_public_key(parent_public_key)
    try:
        pk.verify(sig_bytes, canon)
        return {"valid": True, "reason": "ok"}
    except InvalidSignature:
        return {"valid": False, "reason": "cert_signature_mismatch"}


def verify_cert_chain(chain: list, *, trust_anchor: bytes) -> dict:
    """Walk a certificate chain root->leaf and verify every link.

    Returns:
        dict: {"valid": bool, "reason": str, "leaf_public_key": bytes | None}
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
    """Create or add a signature to a multi-sig VPE envelope.

    First signer: creates fresh envelope with ``signatures`` array.
    Additional signer: parses existing, validates prior sigs, appends.
    """
    if threshold < 1:
        raise ValueError(f"threshold must be >= 1, got {threshold}")
    sk = _load_private_key(private_key)

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
        sig_bytes = sk.sign(canon)
        envelope = dict(existing)
        envelope["signatures"] = existing_sigs + [{"key_id": key_id, "sig": sig_bytes.hex()}]
        return json.dumps(envelope, separators=(",", ":"))

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
    envelope["signatures"] = [{"key_id": key_id, "sig": sk.sign(canon).hex()}]
    return json.dumps(envelope, separators=(",", ":"))


def vpe_verify_multi(
    envelope_str: str,
    *,
    public_keys: dict[str, bytes],
    not_before: int | None = None,
    not_after: int | None = None,
) -> dict:
    """Verify a multi-sig VPE envelope against an N-of-M threshold.
    Checks: parse, version, threshold, signatures, no duplicates,
    key lookup, Ed25519 verify, at least threshold valid, key time bounds.
    """
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}", "details": {}}
    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict", "details": {}}

    if envelope.get("vpe_version", VPE_VERSION) != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {envelope.get('vpe_version')}", "details": {}}

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
        try:
            pk = _load_public_key(public_keys[key_id])
            canon = _canonical_json_multi(envelope)
            pk.verify(sig_bytes, canon)
            valid_count += 1
            details["valid_signatures"].append(key_id)
        except InvalidSignature:
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
    """Sign a prompt using a hardware-backed key (YubiKey, TPM, etc)."""
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
    envelope["signature"] = provider.sign(canon, key.key_id).hex()
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
    """Verify a VPE envelope that may use a hardware-backed signature.
    Supports Ed25519 and ECDSA-P256.
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
    if envelope.get("vpe_version", VPE_VERSION) != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {envelope.get('vpe_version')}"}
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
    return {"valid": False, "reason": "signature_mismatch"}


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def envelope_to_json(envelope: dict) -> str:
    return json.dumps(envelope, separators=(",", ":"))


def envelope_from_json(data: str) -> dict:
    return json.loads(data)
