"""VPE federation — cross-agent trust for Verified Prompt Envelopes.

Implements trust anchor registry, DNS-based discovery, DID-based discovery
(did:key), federated verify/sign with audit logging, and cross-agent audit trails.

Agent A can sign a prompt for Agent B if they share a trust anchor.
Trust anchors are pre-shared via a file-based registry or discovered via DNS/DID.

Core constraint: No external service dependency for core federation.
DNS/DID discovery are optional enhancements; the trust anchor registry
is file-based by default.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from seal.audit import AuditLog
from seal.core import vpe_sign, vpe_verify

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REGISTRY_PATH = "~/.seal/trust_anchors.json"

# Base58 alphabet (Bitcoin-style, same as base58btc in multibase)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_LOOKUP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}

# Ed25519 multicodec prefix (varint-encoded as a single byte)
_ED25519_MULTICODEC_PREFIX = bytes([0xed])

# DNS prefix for VPE key discovery
_VPE_DNS_PREFIX = "_vpe."


# ---------------------------------------------------------------------------
# Base58BTC decode (stdlib-only, no dependencies)
# ---------------------------------------------------------------------------

def _base58btc_decode(s: str) -> bytes:
    """Decode a base58btc (Bitcoin-style) string to bytes.

    Args:
        s: Base58-encoded string (no multibase prefix).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the string contains invalid characters.
    """
    if not s:
        return b""

    # Count leading '1's (base58 encoding of zero bytes)
    leading_ones = 0
    for ch in s:
        if ch == "1":
            leading_ones += 1
        else:
            break

    # Decode the rest
    num = 0
    for ch in s:
        if ch not in _BASE58_LOOKUP:
            raise ValueError(f"Invalid base58 character: {ch!r}")
        num = num * 58 + _BASE58_LOOKUP[ch]

    # Convert to bytes
    if num == 0:
        return b"\x00" * leading_ones

    result = bytearray()
    while num > 0:
        result.append(num & 0xFF)
        num >>= 8
    result.reverse()

    # Prepend leading zeros
    return b"\x00" * leading_ones + bytes(result)


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
            resolved.write_text(
                json.dumps(self._anchors, indent=2, sort_keys=True) + "\n"
            )
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
# DNS-based trust anchor discovery (stdlib-only)
# ---------------------------------------------------------------------------

def _resolve_dns_txt(domain: str) -> list[str]:
    """Query TXT records for a domain using system tools.

    Tries ``dig`` first, falls back to ``host``, then returns empty on failure.

    Args:
        domain: Fully qualified domain name.

    Returns:
        List of TXT record values (concatenated strings).
    """
    # Try dig first
    try:
        result = subprocess.run(
            ["dig", "+short", "-t", "TXT", domain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            records = []
            for line in result.stdout.strip().splitlines():
                # dig output: "text" (quoted)
                line = line.strip().strip('"')
                if line:
                    records.append(line)
            return records
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Fallback to host
    try:
        result = subprocess.run(
            ["host", "-t", "TXT", domain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            records = []
            for line in result.stdout.strip().splitlines():
                # host output: "domain descriptive text "text""
                if "descriptive text" in line:
                    txt = line.split('"', 1)[-1]
                    txt = txt.rsplit('"', 1)[0] if '"' in txt else txt
                    if txt:
                        records.append(txt)
            return records
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return []


def resolve_via_dns(agent_domain: str) -> bytes | None:
    """Resolve an agent's VPE public key via DNS TXT record.

    Queries ``_vpe.<agent_domain>`` for a TXT record in the format::

        vpe-key=<hex_encoded_ed25519_public_key>

    Args:
        agent_domain: Domain name of the target agent
            (e.g. ``"hermes.internal.corp.com"``).

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if not found.
    """
    dns_name = f"{_VPE_DNS_PREFIX}{agent_domain}"
    records = _resolve_dns_txt(dns_name)

    for record in records:
        # Match vpe-key=<hex> (64 hex chars = 32 bytes)
        match = re.search(r"vpe-key=([a-fA-F0-9]{64})\b", record)
        if match:
            try:
                return bytes.fromhex(match.group(1).lower())
            except ValueError:
                continue

    return None


# ---------------------------------------------------------------------------
# DID-based trust anchor discovery (did:key)
# ---------------------------------------------------------------------------

def _decode_did_key(did_str: str) -> bytes | None:
    """Decode an Ed25519 public key from a ``did:key`` URI.

    Supports the ``did:key:z<base58btc>`` format (multibase base58btc
    with Ed25519 multicodec prefix ``0xed``).

    The format is::

        did:key:z<base58btc(multicodec_ed25519 + raw_public_key)>

    Args:
        did_str: Full DID string, e.g.
            ``"did:key:z6MkhaXgBZDvB5ABmTkVnYLSF2dQhGt3fJX3tLx3J3d9J6vR"``.

    Returns:
        Raw 32-byte Ed25519 public key, or ``None`` if parsing fails.
    """
    if not did_str.startswith("did:key:"):
        return None

    encoded = did_str[len("did:key:"):]
    if not encoded:
        return None

    # Multibase indicator: 'z' = base58btc
    if encoded[0] != "z":
        return None

    try:
        decoded = _base58btc_decode(encoded[1:])
    except (ValueError, OverflowError):
        return None

    if len(decoded) < 33:
        return None

    # First byte(s) = multicodec varint. Ed25519 = 0xed (1-byte varint)
    if decoded[0] != _ED25519_MULTICODEC_PREFIX[0]:
        return None

    public_key = decoded[1:]
    if len(public_key) != 32:
        return None

    return public_key


def resolve_via_did(did_str: str) -> bytes | None:
    """Resolve an Ed25519 public key from a did:key identifier.

    Alias for ``_decode_did_key``.  Separate function so the resolver API
    is consistent (all ``resolve_via_*`` return ``bytes | None``).

    Args:
        did_str: DID string (``"did:key:z..."``).

    Returns:
        Raw 32-byte Ed25519 public key, or ``None``.
    """
    return _decode_did_key(did_str)


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


# ---------------------------------------------------------------------------
# Resolution chain
# ---------------------------------------------------------------------------

@dataclass
class ResolutionResult:
    """Result of resolving a trust anchor.

    Attributes:
        public_key: The resolved Ed25519 public key (raw bytes), or None.
        source: How it was resolved (``"registry"``, ``"dns"``, ``"did"``, ``"none"``).
        agent_id: The resolved agent identity, if known.
    """
    public_key: bytes | None
    source: str = "none"
    agent_id: str = ""


def resolve_trust_anchor(
    issuer: str,
    *,
    registry: TrustAnchorRegistry | None = None,
    dns_domain: str | None = None,
    did_str: str | None = None,
) -> ResolutionResult:
    """Resolve a trust anchor for a given issuer using the available methods.

    Resolution order:
        1. Trust anchor registry (pre-shared keys)
        2. DNS discovery (TXT record)
        3. DID discovery (did:key)

    Args:
        issuer: The issuer identity string (e.g. ``"agent:alice"``).
        registry: Optional pre-configured registry instance.
        dns_domain: Optional domain for DNS TXT lookup.
        did_str: Optional did:key string for DID resolution.

    Returns:
        ``ResolutionResult`` with the resolved public key and source.
    """
    # 1. Registry
    if registry is not None:
        pk = registry.lookup(issuer)
        if pk is not None:
            return ResolutionResult(public_key=pk, source="registry", agent_id=issuer)

    # 2. DNS discovery
    if dns_domain is not None:
        pk = resolve_via_dns(dns_domain)
        if pk is not None:
            return ResolutionResult(public_key=pk, source="dns", agent_id=dns_domain)

    # 3. DID discovery
    if did_str is not None:
        pk = resolve_via_did(did_str)
        if pk is not None:
            did_agent = f"did:{did_str}"
            return ResolutionResult(public_key=pk, source="did", agent_id=did_agent)

    return ResolutionResult(public_key=None, source="none")


# ---------------------------------------------------------------------------
# Federated sign / verify
# ---------------------------------------------------------------------------

@dataclass
class FederatedSignResult:
    """Result of a federated signing operation."""
    envelope: str = ""
    nonce: str = ""
    error: str = ""


def vpe_federated_sign(
    prompt: str,
    *,
    issuer: str,
    audience: str,
    private_key: bytes,
    scope: dict | None = None,
    doc_sha256: str = "",
    ttl_seconds: int = 300,
    counter: int | None = None,
    audit_log: FederationAuditLog | None = None,
    **kwargs: object,
) -> FederatedSignResult:
    """Sign a VPE envelope for cross-agent federation.

    Wraps ``vpe_sign()`` and optionally logs the issuance to the
    cross-agent audit trail.

    Args:
        prompt: The actionable instruction.
        issuer: Who is signing (e.g. ``"agent:alice"``).
        audience: Who should execute (e.g. ``"agent:bob"``).
        private_key: Raw Ed25519 private key bytes.
        scope: Execution constraints.
        doc_sha256: SHA-256 binding to source document.
        ttl_seconds: Time-to-live in seconds.
        counter: Monotonic counter (auto-generated if omitted).
        audit_log: Optional audit log for cross-agent tracking.
        **kwargs: Additional keyword arguments passed to ``vpe_sign``.

    Returns:
        ``FederatedSignResult`` with the signed envelope and nonce.
    """
    try:
        envelope_str = vpe_sign(
            prompt=prompt,
            scope=scope,
            issuer=issuer,
            audience=audience,
            doc_sha256=doc_sha256,
            ttl_seconds=ttl_seconds,
            counter=counter,
            private_key=private_key,
        )
    except Exception as exc:
        return FederatedSignResult(error=str(exc))

    # Extract nonce for audit correlation
    import json as _json
    try:
        parsed = _json.loads(envelope_str)
        nonce = parsed.get("nonce", "")
    except (ValueError, _json.JSONDecodeError):
        nonce = ""

    if audit_log is not None:
        audit_log.log_issuance(
            issuer=issuer,
            audience=audience,
            prompt_summary=prompt[:80],
            envelope_nonce=nonce,
        )

    return FederatedSignResult(envelope=envelope_str, nonce=nonce)


def vpe_federated_verify(
    envelope_str: str,
    *,
    registry: TrustAnchorRegistry | None = None,
    dns_domain: str | None = None,
    did_str: str | None = None,
    issuer_override: str | None = None,
    audit_log: FederationAuditLog | None = None,
) -> dict:
    """Verify a VPE envelope using the federation trust resolution chain.

    Resolves the issuer's Ed25519 public key via:
        1. Trust anchor registry
        2. DNS TXT record
        3. did:key identifier

    Then delegates to ``vpe_verify()`` for the actual cryptographic check.

    Args:
        envelope_str: The VPE envelope JSON string.
        registry: Optional trust anchor registry.
        dns_domain: Optional domain for DNS TXT lookup.
        did_str: Optional did:key string for DID resolution.
        issuer_override: Override the issuer identity for key lookup
            (if not provided, uses the ``issuer`` field from the envelope).
        audit_log: Optional audit log for cross-agent tracking.

    Returns:
        dict: ``{"valid": bool, "reason": str, "source": str}``
    """
    # Parse envelope to get issuer
    try:
        import json as _json
        envelope = _json.loads(envelope_str)
    except (ValueError, _json.JSONDecodeError) as exc:
        result = {"valid": False, "reason": f"invalid_json: {exc}"}
        if audit_log is not None:
            audit_log.log_verification(
                issuer="unknown", verifier="unknown",
                envelope_nonce="", result="denied", reason=result["reason"],
            )
        return {**result, "source": "none"}

    if not isinstance(envelope, dict):
        result = {"valid": False, "reason": "invalid_json: not a dict"}
        if audit_log is not None:
            audit_log.log_verification(
                issuer="unknown", verifier="unknown",
                envelope_nonce="", result="denied", reason=result["reason"],
            )
        return {**result, "source": "none"}

    issuer = issuer_override or envelope.get("issuer", "")
    nonce = envelope.get("nonce", "")

    # Resolve trust anchor
    resolution = resolve_trust_anchor(
        issuer,
        registry=registry,
        dns_domain=dns_domain,
        did_str=did_str,
    )

    if resolution.public_key is None:
        reason = f"unknown_issuer: no trust anchor for {issuer!r}"
        if audit_log is not None:
            audit_log.log_verification(
                issuer=issuer, verifier="federation",
                envelope_nonce=nonce, result="denied",
                reason=reason, source="none",
            )
        return {"valid": False, "reason": reason, "source": "none"}

    # Delegate to vpe_verify
    verify_result = vpe_verify(envelope_str, public_key=resolution.public_key)

    # Augment result with source
    result = {
        "valid": verify_result.get("valid", False),
        "reason": verify_result.get("reason", "unknown"),
        "source": resolution.source,
    }

    if audit_log is not None:
        audit_log.log_verification(
            issuer=issuer,
            verifier="federation",
            envelope_nonce=nonce,
            result="granted" if result["valid"] else "denied",
            reason=result["reason"],
            source=resolution.source,
        )

    return result
