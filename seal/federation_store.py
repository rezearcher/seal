"""VPE federation persistence layer — trust anchor registry, trust bundle
serialization, and the cross-agent audit log.

Extracted verbatim from ``seal.federation`` (pure structural refactor; no
behavior change). DNS/DID discovery and federated sign/verify remain in
``seal.federation``, which re-exports the public names defined here so
existing imports keep working.
"""

from __future__ import annotations

import os
import json
import threading
from collections import OrderedDict
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from seal._base import _load_private_key, _load_public_key
from seal.audit import AuditLog
from dataclasses import dataclass, field


DEFAULT_REGISTRY_PATH = "~/.seal/trust_anchors.json"


class FederationError(Exception):
    """Raised when a federation operation encounters invalid or malformed data.

    Distinct from standard Python exceptions — callers catch this
    specifically to handle corrupted trust material, malformed DNS
    responses, or protocol violations without crashing the caller.
    """


# ---------------------------------------------------------------------------
# Trust anchor registry
# ---------------------------------------------------------------------------


@dataclass
class TrustAnchorRegistry:
    """File-based registry of pre-shared Ed25519 public keys.

    Maps agent identities (e.g. ``"agent:alice"``, ``"service:ci-bot"``)
    to hex-encoded Ed25519 public keys for cross-agent trust.

    The registry is stored as a JSON file at a configurable path
    (default: ``~/.seal/trust_anchors.json``).

    Thread-safe for concurrent read/write access.
    """

    path: str = DEFAULT_REGISTRY_PATH
    _anchors: dict[str, str] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _loaded: bool = False

    def __post_init__(self) -> None:
        """Lazy-load on first access; no I/O in __init__."""
        pass

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load()

    def _load(self) -> None:
        resolved = Path(self.path).expanduser()
        if resolved.exists():
            try:
                data = json.loads(resolved.read_text())
                if isinstance(data, dict):
                    self._anchors = {str(k): str(v) for k, v in data.items()}
            except (json.JSONDecodeError, OSError):
                self._anchors = {}
        self._loaded = True

    def save(self) -> None:
        """Persist the current registry to disk."""
        resolved = Path(self.path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            resolved.write_text(json.dumps(self._anchors, indent=2, sort_keys=True) + "\n")
            resolved.chmod(0o600)

    def lookup(self, agent_id: str) -> bytes | None:
        """Look up an agent's Ed25519 public key.

        Args:
            agent_id: Agent identity string (e.g. ``"agent:alice"``).

        Returns:
            Raw 32-byte Ed25519 public key, or ``None`` if unknown.
        """
        self._ensure_loaded()
        with self._lock:
            hex_key = self._anchors.get(agent_id)
        if hex_key is None:
            return None
        try:
            return bytes.fromhex(hex_key)
        except ValueError:
            return None

    def register(self, agent_id: str, public_key: bytes) -> None:
        """Register or update a trust anchor.

        Args:
            agent_id: Agent identity string.
            public_key: Raw 32-byte Ed25519 public key.
        """
        self._ensure_loaded()
        with self._lock:
            self._anchors[agent_id] = public_key.hex()

    def remove(self, agent_id: str) -> bool:
        """Remove a trust anchor.

        Args:
            agent_id: Agent identity string.

        Returns:
            ``True`` if the anchor existed and was removed.
        """
        self._ensure_loaded()
        with self._lock:
            return self._anchors.pop(agent_id, None) is not None

    def list_anchors(self) -> dict[str, str]:
        """Return all registered trust anchors (copy)."""
        self._ensure_loaded()
        with self._lock:
            return dict(self._anchors)

    def __contains__(self, agent_id: str) -> bool:
        self._ensure_loaded()
        with self._lock:
            return agent_id in self._anchors

    def __len__(self) -> int:
        self._ensure_loaded()
        with self._lock:
            return len(self._anchors)


# ---------------------------------------------------------------------------
# Trust anchor bundle export/import
# ---------------------------------------------------------------------------

_TRUST_BUNDLE_FIELDS = [
    "vpe_trust_bundle",
    "exported_at",
    "exporter_agent_id",
    "exporter_public_key_hex",
    "anchors",
]


def _canonical_trust_bundle(bundle: dict) -> bytes:
    """Deterministic canonical JSON of a trust bundle (minus signature).

    Uses ``_TRUST_BUNDLE_FIELDS`` ordering and sorts ``anchors`` keys
    lexicographically. Missing fields default to empty string or empty dict.
    """
    ordered: dict[str, object] = OrderedDict()
    for bundle_field in _TRUST_BUNDLE_FIELDS:
        if bundle_field == "anchors":
            value = bundle.get("anchors", {})
            if isinstance(value, dict):
                value = OrderedDict(sorted(value.items()))
            ordered[bundle_field] = value
        else:
            ordered[bundle_field] = bundle.get(bundle_field, "")
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def export_trust_bundle(
    registry: TrustAnchorRegistry,
    *,
    exporter_agent_id: str,
    private_key: bytes,
) -> str:
    """Export all registered trust anchors as a signed JSON bundle.

    The bundle is a JSON envelope with an Ed25519 signature (self-signed
    by the exporting agent), suitable for out-of-band transfer to another
    agent's trust anchor registry.

    Args:
        registry: The trust anchor registry to export from.
        exporter_agent_id: Identity of the exporting agent
            (e.g. ``\"agent:alice\"``).
        private_key: Raw Ed25519 private key bytes of the exporting agent.

    Returns:
        Signed JSON bundle string suitable for ``import_trust_bundle``.

    Raises:
        FederationError: If the registry is empty or the private key
            is invalid.
    """
    anchors = registry.list_anchors()
    if not anchors:
        raise FederationError("Cannot export trust bundle: no trust anchors registered")

    # Derive public key from the private key for bundle verification
    sk = _load_private_key(private_key)
    pk = sk.public_key()
    pk_bytes = pk.public_bytes_raw()

    # Build bundle payload (without signature)
    import datetime as _datetime

    bundle: dict[str, object] = {
        "vpe_trust_bundle": "1",
        "exported_at": _datetime.datetime.now(_datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exporter_agent_id": exporter_agent_id,
        "exporter_public_key_hex": pk_bytes.hex(),
        "anchors": dict(anchors),
    }

    # Sign the canonical payload
    canon = _canonical_trust_bundle(bundle)
    bundle["signature"] = sk.sign(canon).hex()

    return json.dumps(bundle, separators=(",", ":"))


def import_trust_bundle(
    bundle_str: str,
    registry: TrustAnchorRegistry,
    *,
    trusted_exporter_ids: set[str] | None = None,
) -> dict:
    """Verify and import trust anchors from a signed JSON bundle.

    Args:
        bundle_str: The signed JSON bundle string (from ``export_trust_bundle``).
        registry: The target trust anchor registry to import into.
        trusted_exporter_ids: Optional set of allowed exporter agent IDs.
            If provided, import is rejected unless the exporter's agent_id
            is in this set.

    Returns:
        dict: ``{\"ok\": bool, \"reason\": str, \"imported_count\": int,
        \"exporter_agent_id\": str}``

    Raises:
        FederationError: If the bundle is malformed, has an invalid
            version, signature verification fails, or the exporter is
            not trusted.
    """
    # Parse JSON
    try:
        bundle = json.loads(bundle_str)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FederationError(f"Invalid trust bundle JSON: {exc}") from exc

    if not isinstance(bundle, dict):
        raise FederationError("Trust bundle must be a JSON object")

    # Check version
    version = bundle.get("vpe_trust_bundle", "")
    if version != "1":
        raise FederationError(f"Unsupported trust bundle version: {version!r} — expected '1'")

    exporter_id = bundle.get("exporter_agent_id", "")
    if not exporter_id:
        raise FederationError("Trust bundle missing exporter_agent_id")

    pk_hex = bundle.get("exporter_public_key_hex", "")
    if not pk_hex:
        raise FederationError("Trust bundle missing exporter_public_key_hex")

    try:
        pk_bytes = bytes.fromhex(pk_hex)
        if len(pk_bytes) != 32:
            raise FederationError(f"Invalid public key length in bundle: {len(pk_bytes)} bytes, expected 32")
    except ValueError as exc:
        raise FederationError(f"Invalid exporter_public_key_hex (not valid hex): {exc}") from exc

    sig_hex = bundle.get("signature", "")
    if not sig_hex:
        raise FederationError("Trust bundle missing signature")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise FederationError(f"Invalid signature (not valid hex): {exc}") from exc

    # Check trusted exporter
    if trusted_exporter_ids is not None and exporter_id not in trusted_exporter_ids:
        raise FederationError(f"Untrusted exporter: {exporter_id!r} — not in trusted_exporter_ids")

    # Verify signature
    try:
        pk = _load_public_key(pk_bytes)
        canon = _canonical_trust_bundle(bundle)
        pk.verify(sig_bytes, canon)
    except InvalidSignature:
        raise FederationError("Trust bundle signature verification failed")
    except Exception as exc:
        raise FederationError(f"Trust bundle signature verification error: {exc}") from exc

    # Import anchors (idempotent — re-importing the same anchor is a no-op)
    anchors = bundle.get("anchors", {})
    if not isinstance(anchors, dict):
        raise FederationError("Trust bundle anchors must be a JSON object")

    imported_count = 0
    for agent_id, key_hex in anchors.items():
        if not isinstance(agent_id, str) or not isinstance(key_hex, str):
            continue
        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 32:
                continue
            # Idempotent: register even if already exists (register updates)
            registry.register(agent_id, key_bytes)
            imported_count += 1
        except (ValueError, TypeError):
            continue

    # Persist the updated registry
    registry.save()

    return {
        "ok": True,
        "reason": f"imported {imported_count} anchors from {exporter_id}",
        "imported_count": imported_count,
        "exporter_agent_id": exporter_id,
    }


# ---------------------------------------------------------------------------
# Cross-agent audit trail
# ---------------------------------------------------------------------------


@dataclass
class FederationAuditLog:
    """Cross-agent audit trail for VPE federation operations.

    Records issuance (Agent A signs a prompt for Agent B) and
    verification (Agent B verifies and accepts/rejects) events.

    Uses the existing ``seal.audit.AuditLog`` as the underlying store
    so all audit entries are written to the same append-only JSONL file.
    """

    audit: AuditLog = field(default_factory=AuditLog)

    def log_issuance(
        self,
        *,
        issuer: str,
        audience: str,
        prompt_summary: str,
        envelope_nonce: str,
        source: str = "federation",
    ) -> None:
        """Record that an issuer signed a prompt for an audience.

        Args:
            issuer: Who signed the envelope.
            audience: Intended recipient.
            prompt_summary: Short description or first N chars of the prompt.
            envelope_nonce: The envelope's nonce for correlation.
            source: How the trust anchor was resolved (registry, dns, did).
        """
        self.audit.log_access(
            label=f"vpe:federation:issuance:{issuer}->{audience}",
            caller=issuer,
            action="sign",
        )
        # Also write a structured cross-audit entry
        self._write_cross_entry(
            event_type="issuance",
            issuer=issuer,
            audience=audience,
            prompt_summary=prompt_summary[:80],
            envelope_nonce=envelope_nonce,
            source=source,
            result="granted",
        )

    def log_verification(
        self,
        *,
        issuer: str,
        verifier: str,
        envelope_nonce: str,
        result: str,
        source: str = "federation",
        reason: str = "",
    ) -> None:
        """Record that a verifier checked a federated envelope.

        Args:
            issuer: Who signed the envelope.
            verifier: Who verified it.
            envelope_nonce: The envelope's nonce for correlation.
            result: ``"granted"`` or ``"denied"``.
            source: How the trust anchor was resolved.
            reason: Human-readable reason (for denials).
        """
        self.audit.log_access(
            label=f"vpe:federation:verification:{issuer}->{verifier}",
            caller=verifier,
            action="verify",
        )
        self._write_cross_entry(
            event_type="verification",
            issuer=issuer,
            audience=verifier,
            prompt_summary="",
            envelope_nonce=envelope_nonce,
            source=source,
            result=result,
            reason=reason,
        )

    def _write_cross_entry(self, **fields: str) -> None:
        """Write a structured cross-audit entry to the audit log."""
        from seal.audit import _utc_now_iso

        entry: dict[str, object] = {
            "timestamp": _utc_now_iso(),
            "event": "vpe_cross_audit",
        }
        entry.update(fields)

        # Write to the same JSONL file via a raw append
        path = Path(self.audit.path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
