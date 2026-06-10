"""Memory trust — sign and verify memory records using VPE envelopes.

Sign a record when writing to agent memory; verify on recall so only
provenance-verified, writer-trusted, namespace-matching records enter
the agent's context.

Public surface::

    from seal.memory import sign_memory, verify_memory, verify_on_recall

    record = sign_memory("content", writer="agent:x", namespace="ns", private_key=priv)
    result = verify_memory(record, public_key=pub)
    if result["valid"]:
        content = result["content"]
"""

from __future__ import annotations

import json

from seal.core import vpe_sign, vpe_verify
from seal.store import NonceStore

# Fields present in a well-formed VPE envelope that may appear in memory records.
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

_KNOWN_FIELDS = frozenset(_ENVELOPE_FIELDS + ["signature"])

# ---------------------------------------------------------------------------
# Sign
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
    """Sign a memory record and return a VPE envelope JSON string.

    Args:
        content: The memory text to sign.
        writer: Identity of the agent writing this record (stored as ``issuer``).
        namespace: Logical bucket for the record (stored as ``audience``).
        scope: Optional capability dict; defaults to empty.
        ttl_seconds: 0 means no expiry (default for memory records).
        private_key: Raw Ed25519 private key bytes.
        nonce: Explicit nonce; auto-generated if omitted.

    Returns:
        Signed VPE envelope JSON string.
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
# Verify
# ---------------------------------------------------------------------------

_FAIL_TEMPLATE: dict = {
    "valid": False,
    "reason": "",
    "content": None,
    "writer": None,
    "namespace": None,
}


def verify_memory(
    record: str,
    *,
    public_key: bytes,
    trusted_writers: set[str] | None = None,
    expected_namespace: str | None = None,
    nonce_store: NonceStore | None = None,
) -> dict:
    """Verify a memory record envelope.

    Checks performed (in order):
        1. JSON parse validity and presence of ``vpe_version``.
        2. No unknown fields (unsigned extension protection).
        3. VPE signature verification (+ TTL / nonce replay if configured).
        4. Writer is in ``trusted_writers`` set (if provided).
        5. Namespace matches ``expected_namespace`` (if provided).

    Returns:
        dict with keys: ``valid`` (bool), ``reason`` (str),
        ``content`` (str | None), ``writer`` (str | None),
        ``namespace`` (str | None).
    """
    _fail: dict = {**_FAIL_TEMPLATE, "reason": ""}

    try:
        envelope = json.loads(record)
    except (json.JSONDecodeError, ValueError):
        return {**_fail, "reason": "no-memory-envelope"}

    if not isinstance(envelope, dict) or "vpe_version" not in envelope:
        return {**_fail, "reason": "no-memory-envelope"}

    for key in envelope:
        if key not in _KNOWN_FIELDS:
            return {**_fail, "reason": f"unsigned_field:{key}"}

    result = vpe_verify(record, public_key=public_key, nonce_store=nonce_store)

    if not result["valid"]:
        return {**_fail, "reason": result.get("reason", "invalid")}

    writer = envelope.get("issuer", "")
    namespace = envelope.get("audience", "")
    content = envelope.get("prompt", "")

    if trusted_writers is not None and writer not in trusted_writers:
        return {**_fail, "reason": "untrusted_writer"}

    if expected_namespace is not None and namespace != expected_namespace:
        return {**_fail, "reason": "cross_namespace"}

    return {
        "valid": True,
        "reason": "ok",
        "content": content,
        "writer": writer,
        "namespace": namespace,
    }


def verify_on_recall(
    records: list[str],
    *,
    public_key: bytes,
    trusted_writers: set[str] | None = None,
    expected_namespace: str | None = None,
    nonce_store: NonceStore | None = None,
) -> dict:
    """Verify a batch of memory records (e.g. a recall result set).

    Args:
        records: List of VPE envelope JSON strings.
        public_key: Raw Ed25519 public key bytes.
        trusted_writers: Optional set of allowed writer identities.
        expected_namespace: Optional namespace filter.
        nonce_store: Optional nonce store for replay protection.

    Returns:
        dict with keys:
            ``accepted`` — list of ``{content, writer, namespace}`` dicts,
            ``rejected`` — list of ``{reason, record_index}`` dicts.
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
            rejected.append({"reason": result["reason"], "record_index": idx})

    return {"accepted": accepted, "rejected": rejected}
