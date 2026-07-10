"""Shared VPE protocol core — constants, canonical serialization, helpers."""

import json
import secrets
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

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

HMAC_SIGNATURE_BYTES = 32

# ---------------------------------------------------------------------------
# Field stripping (wire-format size optimisation)
# ---------------------------------------------------------------------------


def _is_strippable_ttl(value) -> bool:
    return value in (_DEFAULT_TTL, 0)


def _strip_empty_fields(envelope: dict) -> dict:
    """Return a copy of *envelope* with optional default/empty fields removed."""
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
# Helpers
# ---------------------------------------------------------------------------


def _make_nonce() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------


def _canonical_json(envelope: dict) -> bytes:
    """Deterministic canonical JSON of VPE fields (minus signature) for signing.

    Uses ``_ENVELOPE_FIELDS`` ordering, sorts ``scope`` keys lexicographically,
    applies per-field defaults for missing keys, and omits ``cert_chain`` when
    None.
    """
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
# Key management (cryptography-only — used by seal.core)
# ---------------------------------------------------------------------------


def _load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def generate_key_pair() -> dict:
    """Generate an Ed25519 key pair via *cryptography* backend.

    Returns:
        dict: ``{"private_key": bytes, "public_key": bytes}``
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "private_key": private_key.private_bytes_raw(),
        "public_key": public_key.public_bytes_raw(),
    }
