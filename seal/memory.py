"""Memory-trust API — axis-3 (memory integrity) layer.

Signs and verifies memory records using VPE envelopes.  A memory record is
stored content with provenance: who wrote it (writer/agent id), into what
namespace, with what scope.  VPE is reused so signing, verification, and
tamper-detection come for free.

Model mapping to VPE fields:
  content   → prompt
  writer    → issuer
  namespace → audience
"""

from __future__ import annotations

import json

from seal.core import (
    _ENVELOPE_FIELDS,
    vpe_sign,
    vpe_verify,
)
from seal.store import NonceStore

# ---------------------------------------------------------------------------
# The complete set of known top-level VPE fields (signed payload + signature)
# ---------------------------------------------------------------------------

_KNOWN_FIELDS: frozenset[str] = frozenset(_ENVELOPE_FIELDS) | {"signature"}


# ---------------------------------------------------------------------------
# sign_memory
# ---------------------------------------------------------------------------


def sign_memory(
    content: str,
    *,
    writer: str,
    namespace: str = "default",
    scope: dict | None = None,
    ttl_seconds: int = 0,
    private_key: bytes,
    nonce: str | None = None,
) -> str:
    """Sign a memory record and return it as a VPE envelope JSON string.

    Args:
        content: The memory content to sign and store.
        writer: Identity of the agent writing this record (maps to VPE issuer).
        namespace: Logical namespace for this record (maps to VPE audience).
        scope: Optional capability/context dict for the envelope.
        ttl_seconds: Seconds until expiry. Default 0 = no expiry, matching the
            long-lived semantics of persistent memory records.
        private_key: Raw Ed25519 private key bytes.
        nonce: Unique nonce. Auto-generated when omitted.

    Returns:
        Signed envelope as a JSON string.
    """
    return vpe_sign(
        prompt=content,
        issuer=writer,
        audience=namespace,
        scope=scope,
        ttl_seconds=ttl_seconds,
        private_key=private_key,
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# verify_memory
# ---------------------------------------------------------------------------


def verify_memory(
    record: str,
    *,
    public_key: bytes,
    trusted_writers: set[str] | None = None,
    expected_namespace: str | None = None,
    nonce_store: NonceStore | None = None,
) -> dict:
    """Verify a signed memory record.

    Checks performed, in order:
      1. Reject if not parseable or missing ``vpe_version`` → ``no-memory-envelope``.
      2. Reject any top-level key outside the known VPE field set + ``signature``
         → ``unsigned_field:<key>`` (extra-field injection defence).
      3. ``vpe_verify`` — propagates its reason on failure.
      4. If ``trusted_writers`` given and issuer not in it → ``untrusted_writer``.
      5. If ``expected_namespace`` given and audience ≠ it → ``cross_namespace``.
      6. Otherwise valid; includes decoded content, writer, namespace.

    Args:
        record: JSON string produced by ``sign_memory``.
        public_key: Raw Ed25519 public key bytes.
        trusted_writers: Optional set of allowed writer identities (issuers).
        expected_namespace: Optional required namespace (audience).
        nonce_store: Optional NonceStore for replay prevention.

    Returns:
        dict with keys: ``valid`` (bool), ``reason`` (str),
        ``content`` (str | None), ``writer`` (str | None),
        ``namespace`` (str | None).
    """
    _fail = {"valid": False, "reason": "", "content": None, "writer": None, "namespace": None}

    # 1. Parse + basic sanity
    try:
        envelope = json.loads(record)
    except (json.JSONDecodeError, ValueError):
        return {**_fail, "reason": "no-memory-envelope"}

    if not isinstance(envelope, dict) or "vpe_version" not in envelope:
        return {**_fail, "reason": "no-memory-envelope"}

    # 2. Extra-field check — reject any key not in the known VPE field set
    for key in envelope:
        if key not in _KNOWN_FIELDS:
            return {**_fail, "reason": f"unsigned_field:{key}"}

    # 3. Cryptographic verification
    result = vpe_verify(record, public_key=public_key, nonce_store=nonce_store)
    if not result["valid"]:
        return {**_fail, "reason": result["reason"]}

    # Decode issuer/audience for subsequent checks
    writer = envelope.get("issuer", "")
    namespace = envelope.get("audience", "")
    content = envelope.get("prompt", "")

    # 4. Trusted-writer check
    if trusted_writers is not None and writer not in trusted_writers:
        return {**_fail, "reason": "untrusted_writer"}

    # 5. Namespace check
    if expected_namespace is not None and namespace != expected_namespace:
        return {**_fail, "reason": "cross_namespace"}

    return {
        "valid": True,
        "reason": "ok",
        "content": content,
        "writer": writer,
        "namespace": namespace,
    }


# ---------------------------------------------------------------------------
# verify_on_recall
# ---------------------------------------------------------------------------


def verify_on_recall(
    records: list[str],
    *,
    public_key: bytes,
    trusted_writers: set[str] | None = None,
    expected_namespace: str | None = None,
    nonce_store: NonceStore | None = None,
) -> dict:
    """Verify provenance of a batch of retrieved memory records.

    Only accepted records (valid signature, trusted writer, correct namespace)
    should enter an agent's context.

    Args:
        records: List of JSON strings produced by ``sign_memory``.
        public_key: Raw Ed25519 public key bytes.
        trusted_writers: Optional set of allowed writer identities.
        expected_namespace: Optional required namespace.
        nonce_store: Optional NonceStore for replay prevention.

    Returns:
        dict with:
          ``accepted``: list of dicts ``{content, writer, namespace}`` for valid records.
          ``rejected``: list of dicts ``{reason, record_index}`` for invalid records.
    """
    accepted: list[dict] = []
    rejected: list[dict] = []

    for idx, record in enumerate(records):
        result = verify_memory(
            record,
            public_key=public_key,
            trusted_writers=trusted_writers,
            expected_namespace=expected_namespace,
            nonce_store=nonce_store,
        )
        if result["valid"]:
            accepted.append({
                "content": result["content"],
                "writer": result["writer"],
                "namespace": result["namespace"],
            })
        else:
            rejected.append({
                "reason": result["reason"],
                "record_index": idx,
            })

    return {"accepted": accepted, "rejected": rejected}
