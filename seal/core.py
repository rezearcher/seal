"""VPE Core — Ed25519 signing and verification of prompt envelopes."""

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

# Ordered field list — the canonical serialisation order used for signing.
# Every field except `signature` appears exactly once, in this order.
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

# Fields that can be stripped from the wire format when at their default value.
# The canonical JSON used for signing always includes all fields (with defaults
# for missing keys), so stripping is purely a transport-size optimisation.
_STRIPPABLE_FIELD_DEFAULTS: dict = {
    "vpe_version": VPE_VERSION,  # "1.0" — canonical default matches
    "scope": {},                 # empty scope = no restrictions
    "issuer": "",                # empty issuer
    "audience": "",              # empty audience
    "doc_sha256": "",            # empty doc hash
    "iat": None,                 # no iat — backward-compat envelope
    "counter": None,             # no counter — canonical default is null
    "cert_chain": None,          # no cert chain
}

# ttl_seconds is special: strip when at default (300) or 0 (no expiry)
_DEFAULT_TTL = 300


def _is_strippable_ttl(value) -> bool:
    """True if *ttl_seconds* is at its default value (300) or 0 (no expiry)."""
    return value in (_DEFAULT_TTL, 0)


def _strip_empty_fields(envelope: dict) -> dict:
    """Return a copy of *envelope* with optional default/empty fields removed.

    Only removes fields from ``_STRIPPABLE_FIELD_DEFAULTS`` when their value
    matches the default, plus ``ttl_seconds`` when value is 300 or 0.
    All other fields (``prompt``, ``nonce``, ``signature``) are kept.
    """
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
# Key management
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def generate_key_pair() -> dict:
    """Generate a new Ed25519 key pair.

    Returns:
        dict: ``{"private_key": bytes, "public_key": bytes}``
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "private_key": private_key.private_bytes_raw(),
        "public_key": public_key.public_bytes_raw(),
    }


def _load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------

# Per-field defaults for canonical JSON reconstruction.
# These match the actual default values used in vpe_sign / vpe_sign_hmac,
# so stripped envelopes (missing keys) still produce identical canonical bytes.
_CANONICAL_DEFAULTS: dict = {
    "vpe_version": VPE_VERSION,  # "1.0"
    "scope": {},                 # empty dict
    "issuer": "",
    "audience": "",
    "doc_sha256": "",
    "iat": None,
    "ttl_seconds": 300,          # default TTL
    "nonce": "",
    "counter": None,
    "cert_chain": None,
}


def _canonical_json(envelope: dict) -> bytes:
    """Canonical JSON encoding of VPE fields (minus signature) for signing.

    Uses the field order from ``_ENVELOPE_FIELDS``, sorts ``scope`` keys
    lexicographically, applies per-field defaults for missing keys, and
    produces a deterministic byte string.

    Missing cert_chain is omitted from output (None).
    """
    ordered = OrderedDict()
    for field in _ENVELOPE_FIELDS:
        default = _CANONICAL_DEFAULTS.get(field, "")
        if field == "scope":
            # Sort scope keys for deterministic JSON
            value = envelope.get("scope", default)
            if isinstance(value, dict):
                value = OrderedDict(sorted(value.items()))
            ordered[field] = value
        elif field == "cert_chain":
            # Optional — only include when present
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
        compact: If True, strip empty/default fields from the wire
            format to reduce envelope size. The canonical JSON used for
            verification still resolves defaults, so stripped envelopes
            verify transparently with ``vpe_verify()``.

    Returns:
        Signed envelope as a JSON string.
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
    signature = sk.sign(canon)
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

    Two verification modes:

    **Direct key** (``public_key``):
        Verify the envelope signature directly against the provided public key.
        This is the classic mode — the caller knows which key signed the envelope.

    **Cert-chain** (``trust_anchor``):
        When the envelope contains a ``cert_chain`` field (root->leaf certificate
        chain), the chain is walked to extract the leaf public key. The envelope
        signature is then verified against that leaf key. The ``trust_anchor``
        must match the root certificate's subject public key.

        If the envelope has no ``cert_chain`` and ``trust_anchor`` is given,
        falls back to using the ``public_key`` param (or errors if neither is
        provided). If both ``public_key`` and ``trust_anchor`` are given,
        ``trust_anchor`` takes precedence when a cert_chain is present.

    Checks performed:
        1. JSON parse validity.
        2. Version match (``1.0``).
        3. Cryptographic signature using the provided public key.
        4. TTL expiry (if ``ttl_seconds > 0``).
        5. Scope is a dict.
        6. Nonce is present and is a non-empty string.
        7. Nonce replay check against NonceStore (if ``nonce_store`` is set and ``ttl_seconds > 0``).
        8. Counter, if present, is an integer.
        9. Cert chain verification (if trust_anchor provided).
        10. Key time constraints: not_before / not_after.

    Args:
        envelope_str: The JSON envelope produced by ``vpe_sign``.
        public_key: Raw Ed25519 public key bytes (for direct verification).
            Required when ``trust_anchor`` is not given, or when no
            ``cert_chain`` is in the envelope.
        trust_anchor: Raw Ed25519 public key of the root CA (for chain
            verification). When set and a cert_chain is present, walks the
            chain and uses the extracted leaf key.
        not_before: Optional Unix timestamp - key becomes valid at this time.
        not_after: Optional Unix timestamp - key expires at this time.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    # 1. Parse
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    # 2. Version
    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}"}

    # 3. Signature present
    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_signature"}

    # 4. Scope is dict
    scope = envelope.get("scope", {})
    if not isinstance(scope, dict):
        return {"valid": False, "reason": "scope_not_dict"}

    # 5. Nonce present
    nonce = envelope.get("nonce", "")
    if not isinstance(nonce, str) or nonce == "":
        return {"valid": False, "reason": "missing_or_empty_nonce"}

    # 6. Counter type check (if present)
    counter = envelope.get("counter")
    if counter is not None and not isinstance(counter, int):
        return {"valid": False, "reason": "counter_not_integer"}

    # 7. TTL check
    ttl = envelope.get("ttl_seconds", 0)
    if not isinstance(ttl, int):
        return {"valid": False, "reason": "ttl_not_integer"}

    # 8. Nonce replay check (skip when ttl=0 — no replay window)
    if nonce_store is not None and ttl > 0:
        if not nonce_store.add(nonce):
            return {"valid": False, "reason": "nonce_reused"}

    # 9. Determine effective public key
    cert_chain = envelope.get("cert_chain")

    if trust_anchor is not None and cert_chain is not None:
        chain_result = verify_cert_chain(cert_chain, trust_anchor=trust_anchor)
        if not chain_result["valid"]:
            return {"valid": False,
                    "reason": f"cert_chain_failed: {chain_result['reason']}"}
        effective_pk_bytes = chain_result["leaf_public_key"]
    elif public_key is not None:
        effective_pk_bytes = public_key
    else:
        return {"valid": False,
                "reason": "no_verification_key: provide public_key or trust_anchor"}

    # 10. Cryptographic signature verification
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

    # 11. TTL expiry
    now = int(time.time())
    if ttl > 0:
        iat = envelope.get("iat")
        if iat is None:
            # No issued-at timestamp — can't enforce TTL. Treat as no expiry
            # to maintain backward compatibility with envelopes signed
            # before iat was introduced.
            pass
        elif not isinstance(iat, int):
            return {"valid": False, "reason": "iat_not_integer"}
        elif now - iat > ttl:
            return {"valid": False, "reason": "envelope_expired"}

    # 12. Key time constraints (not_before / not_after)
    if not_before is not None and now < not_before:
        return {"valid": False, "reason": "key_not_yet_valid"}
    if not_after is not None and now >= not_after:
        return {"valid": False, "reason": "key_expired"}

    return {"valid": True, "reason": "ok"}


# ---------------------------------------------------------------------------
# HMAC-SHA256 alternative (internal/low-security contexts)
# ---------------------------------------------------------------------------

HMAC_SIGNATURE_BYTES = 32
"""HMAC-SHA256 produces a 32-byte (64 hex char) signature vs. Ed25519's 64 bytes."""


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

    Identical envelope format to ``vpe_sign()`` but uses symmetric
    HMAC-SHA256 instead of Ed25519 asymmetric signatures.

    **Trade-offs vs. Ed25519:**

    +--------------------------------------+-----------------------------+-------------------------------+
    | Dimension                             | Ed25519 (vpe_sign)          | HMAC-SHA256 (vpe_sign_hmac)   |
    +--------------------------------------+-----------------------------+-------------------------------+
    | Speed                                 | ~O(n) asymmetric ops        | ~O(n) symmetric — 10-100x     |
    |                                      |                             | faster for typical payloads   |
    | Signature size                        | 64 bytes (128 hex chars)    | 32 bytes (64 hex chars)       |
    | Key management                        | Key pair (private + public) | Single shared secret          |
    | Non-repudiation                       | Yes — only key holder signs | No — anyone with the secret   |
    |                                      |                             | can sign                      |
    | Key distribution                      | Public key is shareable     | Secret must be shared out-of- |
    |                                      |                             | band to all verifiers/signers  |
    | Trust model                           | Asymmetric — verify with    | Symmetric — verify = sign     |
    |                                      | public key, sign with       | capability: same secret used  |
    |                                      | private key                 | for both                      |
    | Quantum resistance                    | None (Ed25519 is broken by  | Stronger (SHA-256 resistance  |
    |                                      | Shor's algorithm)           | is still debated)             |
    | Use case                              | Public / cross-domain       | Internal / single-domain      |
    |                                      | / audit-worthy signatures   | / performance-critical paths  |
    +--------------------------------------+-----------------------------+-------------------------------+

    **When to use HMAC:**
    - All signers and verifiers run inside the same trust boundary
      (same process, same service mesh, same VPC).
    - Throughput matters more than public verifiability.
    - You need zero extra crypto dependencies (HMAC is stdlib-only).

    **When NOT to use HMAC:**
    - You need third-party verifiability (audit, compliance,
      non-repudiation).
    - Verifiers cannot be trusted with the signing secret.
    - You need public-key distribution (Ed25519's public keys
      can be published freely).

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry from now (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter (not set by default).
        shared_secret: HMAC key bytes. Must be kept secret.
            Minimum recommended length: 32 bytes (256 bits).

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
    signature = hmac.new(shared_secret, canon, hashlib.sha256).hexdigest()
    envelope["signature"] = signature

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

    Checks performed (same as ``vpe_verify()`` except uses HMAC):
        1. JSON parse validity.
        2. Version match (``1.0``).
        3. Cryptographic HMAC-SHA256 signature using the shared secret.
        4. TTL expiry (if ``ttl_seconds > 0``).
        5. Scope is a dict.
        6. Nonce is present and is a non-empty string.
        7. Counter, if present, is an integer.
        8. Key time constraints: not_before / not_after.

    Args:
        envelope_str: The JSON envelope produced by ``vpe_sign_hmac``.
        shared_secret: HMAC key bytes (must match the secret used at sign time).
        not_before: Optional Unix timestamp — key becomes valid at this time.
        not_after: Optional Unix timestamp — key expires at this time.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """

    # 1. Parse
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}"}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict"}

    # 2. Version
    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}"}

    # 3. Signature present
    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        return {"valid": False, "reason": "missing_signature"}

    # 4. Scope is dict
    scope = envelope.get("scope", {})
    if not isinstance(scope, dict):
        return {"valid": False, "reason": "scope_not_dict"}

    # 5. Nonce present
    nonce = envelope.get("nonce", "")
    if not isinstance(nonce, str) or nonce == "":
        return {"valid": False, "reason": "missing_or_empty_nonce"}

    # 6. Counter type check (if present)
    counter = envelope.get("counter")
    if counter is not None and not isinstance(counter, int):
        return {"valid": False, "reason": "counter_not_integer"}

    # 7. TTL check
    ttl = envelope.get("ttl_seconds", 0)
    if not isinstance(ttl, int):
        return {"valid": False, "reason": "ttl_not_integer"}

    # 8. HMAC-SHA256 signature verification
    verify_envelope = dict(envelope)
    verify_envelope["signature"] = ""
    canon = _canonical_json(verify_envelope)

    expected = hmac.new(shared_secret, canon, hashlib.sha256).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(sig_hex, expected):
        return {"valid": False, "reason": "signature_mismatch"}

    # 9. TTL expiry
    now = int(time.time())
    if ttl > 0:
        iat = envelope.get("iat")
        if iat is None:
            # No issued-at timestamp — can't enforce TTL. Treat as no expiry
            # to maintain backward compatibility with envelopes signed
            # before iat was introduced.
            pass
        elif not isinstance(iat, int):
            return {"valid": False, "reason": "iat_not_integer"}
        elif now - iat > ttl:
            return {"valid": False, "reason": "envelope_expired"}

    # 10. Key time constraints (not_before / not_after)
    if not_before is not None and now < not_before:
        return {"valid": False, "reason": "key_not_yet_valid"}
    if not_after is not None and now >= not_after:
        return {"valid": False, "reason": "key_expired"}

    return {"valid": True, "reason": "ok"}


# ---------------------------------------------------------------------------
# Certificate chain — hierarchical key support (P9.1)
# ---------------------------------------------------------------------------
#
# Certificates are self-describing JSON structures. Each certificate carries
# both the subject's and issuer's Ed25519 public keys so verification only
# needs the root trust anchor. No external CA infrastructure required.
#
# Chain:  root CA → intermediate → leaf signing key
# Chain is stored root-first in the envelope's ``cert_chain`` field.
# The leaf key signs the envelope; the chain proves the leaf key's lineage.
#
# Certificate fields (in canonical signing order):
#   cert_version, subject_id, subject_public_key (hex), issuer_id,
#   issuer_public_key (hex), serial, not_before, not_after, metadata, signature
#
# The ``issuer_public_key`` in a cert is the public key that signed it.
# For the root (self-signed), issuer_public_key == subject_public_key.
#

CERT_VERSION = "1.0"

# Default validity: 1 year from creation
_CERT_DEFAULT_TTL = 365 * 24 * 3600


def _make_cert_serial() -> str:
    """Generate a unique hex serial number for a certificate."""
    return secrets.token_hex(8)


def _canonical_cert(cert: dict) -> bytes:
    """Deterministic JSON encoding of a certificate (minus signature)."""
    # Decode any hex-encoded bytes in metadata back to clean state
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

    The certificate is self-describing: it carries both the subject's and
    issuer's public keys as hex strings, so verifiers only need the root
    trust anchor to walk the full chain.

    Args:
        subject_public_key: The public key being certified (raw 32 bytes).
        subject_id: Identity string for the subject (e.g. ``"ca:interm-01"``).
        issuer_private_key: Private key of the issuer signing this cert.
        issuer_id: Identity string for the issuer (e.g. ``"ca:root-001"``).
        issuer_public_key: Public key of the issuer (raw 32 bytes).
        serial: Unique serial string (auto-generated if omitted).
        not_before: Unix epoch seconds for validity start
            (defaults to now).
        not_after: Unix epoch seconds for validity end
            (defaults to now + 1 year).
        metadata: Optional dict of additional cert metadata.

    Returns:
        dict: The signed certificate (JSON-serializable).
    """
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
    signature = sk.sign(canon)
    cert["signature"] = signature.hex()
    return cert


def verify_certificate(cert: dict, *, parent_public_key: bytes) -> dict:
    """Verify a single certificate's signature against a parent public key.

    Args:
        cert: Certificate dict (as returned by ``create_certificate``).
        parent_public_key: Raw Ed25519 public key of the parent CA
            (the issuer whose ``subject_public_key`` signed this cert).

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

    pk = _load_public_key(parent_public_key)
    try:
        pk.verify(sig_bytes, canon)
        return {"valid": True, "reason": "ok"}
    except InvalidSignature:
        return {"valid": False, "reason": "cert_signature_mismatch"}


def verify_cert_chain(chain: list, *, trust_anchor: bytes) -> dict:
    """Walk a certificate chain root→leaf and verify every link.

    Args:
        chain: List of certificate dicts **root first** (index 0 = root CA,
            index -1 = leaf signing key).
        trust_anchor: Raw Ed25519 public key of the root CA authority.
            This must match the ``subject_public_key`` in the root cert.

    Returns:
        dict: ``{"valid": bool, "reason": str, "leaf_public_key": bytes | None}``
            ``leaf_public_key`` is the extracted leaf key on success, None on failure.
    """
    if not chain:
        return {"valid": False, "reason": "empty_cert_chain", "leaf_public_key": None}

    # --- Root cert: verify self-signature matches trust anchor ---
    root = chain[0]
    try:
        root_subject_pk = bytes.fromhex(root.get("subject_public_key", ""))
    except ValueError:
        return {"valid": False, "reason": "invalid_root_public_key_hex", "leaf_public_key": None}

    if root_subject_pk != trust_anchor:
        return {"valid": False, "reason": "root_public_key_mismatch_trust_anchor",
                "leaf_public_key": None}

    # Verify root self-signature using our trust anchor
    result = verify_certificate(root, parent_public_key=trust_anchor)
    if not result["valid"]:
        return {"valid": False, "reason": f"root_cert_failed: {result['reason']}",
                "leaf_public_key": None}

    # --- Walk intermediate chain ---
    parent_public_key = trust_anchor

    for i in range(1, len(chain)):
        cert = chain[i]
        result = verify_certificate(cert, parent_public_key=parent_public_key)
        if not result["valid"]:
            return {"valid": False,
                    "reason": f"chain_link_{i}_failed: {result['reason']}",
                    "leaf_public_key": None}

        # The subject of this cert becomes the parent for the next link
        try:
            parent_public_key = bytes.fromhex(cert.get("subject_public_key", ""))
        except ValueError:
            return {"valid": False,
                    "reason": f"chain_link_{i}_invalid_public_key_hex",
                    "leaf_public_key": None}

    # Last cert's subject_public_key is the leaf key
    return {"valid": True, "reason": "ok", "leaf_public_key": parent_public_key}


# ---------------------------------------------------------------------------
# Multi-signature (N-of-M) support
# ---------------------------------------------------------------------------

_MULTI_ENVELOPE_FIELDS = _ENVELOPE_FIELDS + ["threshold"]
"""Field order for multi-sig canonical JSON.

Includes everything from single-sig plus ``threshold``.
``signatures`` is excluded (it's added after signing, like ``signature``).
"""


def _canonical_json_multi(envelope: dict) -> bytes:
    """Canonical JSON encoding of VPE fields for multi-signature envelopes.

    Includes ``threshold`` in the payload so it's cryptographically
    protected from tampering.  Excludes ``signature`` and ``signatures``
    (both are added after signing, like the single-sig counterpart).

    When ``threshold`` is absent from the envelope the output is identical
    to ``_canonical_json()``, preserving backward compatibility with
    single-sig canonical payloads.
    """
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
            # absent → skip so payload matches single-sig exactly
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

    Can be used in two modes:

    **First signer** (``existing_envelope`` is ``None``):
        Creates a fresh envelope with the given ``threshold``, signs it,
        and returns a JSON envelope containing a ``signatures`` array
        with one entry and no top-level ``signature`` field.

    **Additional signer** (``existing_envelope`` provided as a previous
        multi-sig envelope JSON string):
        Parses the existing envelope, validates that all prior signatures
        are still cryptographically valid (optional defence-in-depth),
        verifies the caller's ``key_id`` hasn't already signed, then adds
        a new signature entry.

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry from now (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter.
        threshold: Minimum number of distinct valid signatures required.
            Must be >= 1.  Immutable once set on the envelope.
        private_key: Raw Ed25519 private key bytes.
        key_id: Identifier for this signer's key.  Must be unique
            per signature in the final envelope.
        existing_envelope: A previous multi-sig envelope to append
            this signature to, or ``None`` to create a fresh one.

    Returns:
        Multi-sig envelope as a JSON string.
    """
    if threshold < 1:
        raise ValueError(f"threshold must be >= 1, got {threshold}")

    sk = _load_private_key(private_key)

    if existing_envelope is not None:
        # --- Add signature to existing envelope ---
        existing = json.loads(existing_envelope)
        if not isinstance(existing, dict):
            raise ValueError("existing_envelope is not a JSON object")

        # Pull existing signatures array, or convert single-sig to multi
        existing_sigs = existing.get("signatures", [])
        if not isinstance(existing_sigs, list):
            raise ValueError("existing_envelope.signatures is not a list")

        # Verify caller hasn't already signed with this key_id
        for entry in existing_sigs:
            if entry.get("key_id") == key_id:
                raise ValueError(f"key_id {key_id!r} has already signed this envelope")

        # Build canonical payload from existing envelope (excludes signatures)
        canon = _canonical_json_multi(existing)

        # Sign and append
        sig_bytes = sk.sign(canon)
        new_entry = {"key_id": key_id, "sig": sig_bytes.hex()}
        envelope = dict(existing)
        envelope["signatures"] = existing_sigs + [new_entry]
        return json.dumps(envelope, separators=(",", ":"))

    else:
        # --- Create fresh multi-sig envelope ---
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
        sig_bytes = sk.sign(canon)
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

    Checks performed:
        1. JSON parse validity.
        2. Version match (``1.0``).
        3. ``threshold`` is present and is a positive integer.
        4. ``signatures`` array is present and non-empty.
        5. Each signature entry has ``key_id`` and ``sig``.
        6. No duplicate ``key_id`` values (each signer signs once).
        7. Each ``key_id`` has a corresponding public key in the lookup.
        8. Each Ed25519 signature is valid against the canonical payload.
        9. Number of distinct valid signatures >= ``threshold``.
        10. Key time constraints: not_before / not_after.

    Args:
        envelope_str: Multi-sig envelope JSON produced by ``vpe_sign_multi``.
        public_keys: Mapping of ``key_id`` → raw Ed25519 public key bytes
            for every expected signer.
        not_before: Optional Unix timestamp — key becomes valid at this time.
        not_after: Optional Unix timestamp — key expires at this time.

    Returns:
        dict: ``{"valid": bool, "reason": str, "details": dict}``
    """
    # 1. Parse
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_json: {exc}", "details": {}}

    if not isinstance(envelope, dict):
        return {"valid": False, "reason": "invalid_json: not a dict", "details": {}}

    # 2. Version
    version = envelope.get("vpe_version", VPE_VERSION)
    if version != VPE_VERSION:
        return {"valid": False, "reason": f"unsupported_version: {version}", "details": {}}

    # 3. Threshold
    threshold = envelope.get("threshold")
    if threshold is None:
        return {"valid": False, "reason": "missing_threshold", "details": {}}
    if not isinstance(threshold, int) or threshold < 1:
        return {"valid": False, "reason": f"invalid_threshold: {threshold}", "details": {}}

    # 4. Signatures array
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) == 0:
        return {"valid": False, "reason": "missing_or_empty_signatures", "details": {}}

    # 5-6. Validate entries, check for duplicates
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
            details["invalid_signatures"].append(
                {"index": i, "reason": "entry_not_dict"}
            )
            continue

        key_id = entry.get("key_id", "")
        sig = entry.get("sig", "")

        if not isinstance(key_id, str) or not key_id:
            details["invalid_signatures"].append(
                {"index": i, "reason": "missing_or_empty_key_id"}
            )
            continue

        if not isinstance(sig, str) or not sig:
            details["invalid_signatures"].append(
                {"index": i, "key_id": key_id, "reason": "missing_or_empty_sig"}
            )
            continue

        # Check for duplicate key_id
        if key_id in seen_key_ids:
            details["duplicate_key_ids"].append(key_id)
            continue
        seen_key_ids.add(key_id)

        # Check key_id is known
        if key_id not in public_keys:
            details["unknown_key_ids"].append(key_id)
            continue

        # 7. Verify signature
        try:
            sig_bytes = bytes.fromhex(sig)
        except ValueError:
            details["invalid_signatures"].append(
                {"index": i, "key_id": key_id, "reason": "invalid_sig_encoding"}
            )
            continue

        try:
            pk = _load_public_key(public_keys[key_id])
            canon = _canonical_json_multi(envelope)
            pk.verify(sig_bytes, canon)
            valid_count += 1
            details["valid_signatures"].append(key_id)
        except InvalidSignature:
            details["invalid_signatures"].append(
                {"index": i, "key_id": key_id, "reason": "signature_mismatch"}
            )

    # 8. Check threshold
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
            reasons.append(
                f"insufficient_valid_signatures: {valid_count} < {threshold}"
            )
        if details["duplicate_key_ids"]:
            reasons.append(f"duplicate_key_ids: {details['duplicate_key_ids']}")
        if details["unknown_key_ids"]:
            reasons.append(f"unknown_key_ids: {details['unknown_key_ids']}")
        if details["invalid_signatures"]:
            reasons.append(
                f"invalid_signatures: {len(details['invalid_signatures'])} failed"
            )
        return {
            "valid": False,
            "reason": "; ".join(reasons),
            "details": details,
        }


# ---------------------------------------------------------------------------
# Hardware-backed signing (P9.4)
# ---------------------------------------------------------------------------
#
# Signature algorithm identifiers used by hardware providers.
# Defined here to avoid a circular import (hardware.py already imports
# from cryptography, not from core).

SIG_ALG_ED25519 = "ed25519"
SIG_ALG_ECDSA_P256 = "ecdsa-p256"

#
# Main entry points:
#   vpe_sign_hardware()   — sign using a detected HSM or fallback to Ed25519
#   vpe_verify_hardware() — verify envelopes signed by a hardware provider
#
# The ``sig_algorithm`` field in the envelope tells the verifier whether to
# use Ed25519 (``"ed25519"``) or ECDSA-P256-ECDSA (``"ecdsa-p256"``).
# When absent, Ed25519 is assumed (backward compatible).
#


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
    """Sign a prompt using a hardware-backed key.

    Detects available hardware (YubiKey, TPM, Secure Enclave) or falls
    back to a software Ed25519 key.  The resulting envelope carries a
    ``sig_algorithm`` field so the verifier knows which path to take.

    Args:
        prompt: The actionable instruction to sign.
        scope: Least-privilege capabilities dict.
        issuer: Who authorised this prompt.
        audience: Which agent should execute.
        doc_sha256: SHA-256 binding to a source document.
        ttl_seconds: Seconds until expiry from now (0 = no expiry).
        nonce: Unique value (auto-generated if omitted).
        counter: Monotonic counter (not set by default).
        provider_name: Explicit provider name (e.g. ``"yubikey"``,
            ``"tpm"``, ``"enclave"``).  Empty string = auto-detect.

    Returns:
        Signed envelope as a JSON string.
    """
    from seal.hardware import HsmManager

    mgr = HsmManager()
    if provider_name:
        provider = mgr.get_provider(provider_name)
        if provider is None:
            raise ValueError(
                f"hardware provider {provider_name!r} not available. "
                f"Available: {[p.name for p in mgr.discover()]}"
            )
    else:
        provider = mgr.default_provider

    # Build the envelope (without signature)
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

    # Generate a key if we don't have one yet
    key = provider.generate(f"vpe_{issuer}" if issuer else "vpe_default")
    sig_bytes = provider.sign(canon, key.key_id)

    envelope["signature"] = sig_bytes.hex()
    return json.dumps(envelope, separators=(",", ":"))


def _strip_sig_alg(envelope: dict) -> dict:
    """Remove ``sig_algorithm`` from the envelope before canonical hashing.

    The ``sig_algorithm`` field is metadata about *how* the signature was
    produced, not data being signed.  Excluding it keeps the canonical
    payload identical to a software-signed envelope when Ed25519 is used.
    """
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

    Supports both ``"ed25519"`` and ``"ecdsa-p256"`` signature algorithms.
    When ``sig_algorithm`` is ``"ed25519"``, delegates to ``vpe_verify()``.

    Args:
        envelope_str: The JSON envelope string.
        public_key: Raw public key bytes (32 bytes for Ed25519, SPKI DER
            for ECDSA P-256).
        sig_algorithm: ``"ed25519"`` (default) or ``"ecdsa-p256"``.

    Returns:
        dict: ``{"valid": bool, "reason": str}``
    """
    if sig_algorithm == SIG_ALG_ED25519:
        return vpe_verify(envelope_str, public_key=public_key)

    if sig_algorithm != SIG_ALG_ECDSA_P256:
        return {"valid": False, "reason": f"unsupported_sig_algorithm: {sig_algorithm}"}

    # --- Verify ECDSA P-256 ---
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

    # Build canonical payload (same as Ed25519 path — sig_algorithm excluded)
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
    """Serialize a VPE envelope dict to JSON."""
    return json.dumps(envelope, separators=(",", ":"))


def envelope_from_json(data: str) -> dict:
    """Parse a VPE envelope JSON string into a dict."""
    return json.loads(data)
