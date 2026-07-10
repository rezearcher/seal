"""
Division VPE Signer — Optional VPE signing of Division memory episodes.

Adds cryptographic audit trail to Division memory writes by wrapping
episode content in a VPE envelope before storage. This allows later
verification that a memory episode was created by a known agent and has
not been tampered with since creation.

Design:
  - Intercepts Division memory_remember calls (MCP write path)
  - Wraps episode value in a VPE envelope signed by the creating agent
  - Stores the signed envelope alongside (or in place of) the raw value
  - On recall, verifies the signature to detect tampering
  - Records all sign/verify operations in Division memory audit trail (P6.4b)

The integration uses a "signed value" wrapper format:
    {
        "__vpe_signed__": true,
        "vpe_version": "1.0",
        "value": <original_episode_value>,
        "signature": <hex_ed25519_signature>,
        "signed_by": "agent:hermes-default",
        "signed_at": 1234567890,
    }

Usage:
    from seal.integration.division_vpe_signer import DivisionVPESigner

    signer = DivisionVPESigner()
    signer.ensure_keys()

    # Before memory write
    signed_value = signer.wrap_for_storage(
        value={"key": "discovery", "data": "found RCE in /api"},
        domain="recon",
        agent="hermes",
    )

    # After memory recall
    result = signer.verify_stored_value(signed_value)
    if result.valid:
        print("Episode is authentic")
    else:
        print(f"Tampering detected: {result.reason}")

    # Optional: attach Division VPE audit trail (P6.4b)
    # Every sign/verify operation is recorded as a Division memory episode.
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    audit = DivisionVPEAudit()
    signer.set_audit(audit)
    # Now every wrap_for_storage / verify_stored_value call is logged
    # to Division memory as a VPE audit episode.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Try to import seal modules
try:
    from seal.vpe import (
        VPE_VERSION,
        VPEResult,
        _canonical_envelope,
        load_or_generate_keypair,
        vpe_sign,
        vpe_verify,
    )

    _SEAL_AVAILABLE = True
except ImportError:
    _SEAL_AVAILABLE = False
    VPEResult = None  # type: ignore

# Persistent nonce store for replay protection across process restarts
try:
    from seal.store import NonceStore

    _NONCE_STORE_AVAILABLE = True
except ImportError:
    _NONCE_STORE_AVAILABLE = False
    NonceStore = None  # type: ignore

# Try to import Division audit (may not be available)
try:
    from seal.integration.division_vpe_audit import DivisionVPEAudit

    _AUDIT_AVAILABLE = True
except ImportError:
    _AUDIT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Signed value format markers
# ---------------------------------------------------------------------------

_VPE_SIGNED_MARKER = "__vpe_signed__"
"""JSON key marker indicating a value is VPE-signed."""


# ---------------------------------------------------------------------------
# Division VPESigner
# ---------------------------------------------------------------------------


class DivisionVPESigner:
    """Optional VPE signer for Division memory episodes.

    Wraps memory values with cryptographic signatures for audit trail.
    Designed as middleware between the agent and Division's memory_remember
    MCP tool.

    Two operational modes:
      - sign: Wrap values with VPE signature before storage
      - verify: Check signature integrity on recall
      - bypass: Pass through unsigned (default)

    Keypair is stored in ~/.hermes/vpe-keys/ (same as Hermes middleware)
    so the Hermes agent and Division memory share the same trust anchor.
    """

    def __init__(
        self,
        key_dir: str | None = None,
        agent_name: str = "hermes-default",
        mode: str = "bypass",
        nonce_store: NonceStore | None = None,
    ):
        """Initialize the Division VPE signer.

        Args:
            key_dir: Directory for VPE keypair. Defaults to ~/.hermes/vpe-keys/.
            agent_name: Name of this agent for signing metadata.
            mode: "sign" (always sign), "verify" (always verify), "bypass" (no-op).
            nonce_store: Persistent NonceStore for replay protection across restarts.
                Defaults to a NonceStore at ~/.seal/store.db when seal.store is
                available. Pass an explicit instance (e.g. backed by a tmp_path DB)
                to control the path in tests. Pass None to fall back to an
                in-memory set (no cross-restart protection).
        """
        self._key_dir = key_dir or os.path.expanduser("~/.hermes/vpe-keys/")
        self._agent_name = agent_name
        self._mode = mode

        self._private_key: bytes | None = None
        self._public_key: bytes | None = None

        # Replay protection: prefer a persistent NonceStore so seen nonces
        # survive process restarts. Falls back to an in-memory set when
        # seal.store is unavailable.
        if nonce_store is not None:
            self._nonce_store: NonceStore | None = nonce_store
            self._seen_nonces: set | None = None
        elif _NONCE_STORE_AVAILABLE:
            self._nonce_store = NonceStore()
            self._seen_nonces = None
        else:
            self._nonce_store = None
            self._seen_nonces = set()

        # P6.4b: Optional Division memory audit trail
        self._audit: DivisionVPEAudit | None = None

    # ------------------------------------------------------------------
    # Audit trail integration (P6.4b)
    # ------------------------------------------------------------------

    def set_audit(self, audit: DivisionVPEAudit | None) -> None:
        """Attach a DivisionVPEAudit instance for recording sign/verify ops.

        When set, every ``wrap_for_storage`` and ``verify_stored_value``
        call logs its outcome as a Division memory episode via the audit
        trail.

        Args:
            audit: A configured ``DivisionVPEAudit`` instance, or None to
                   disable audit recording.
        """
        self._audit = audit

    def set_audit_from_func(self, remember_func: Callable, conversation_id: str = "vpe-audit-trail") -> None:
        """Convenience: create and attach a DivisionVPEAudit from a remember function.

        Args:
            remember_func: A callable compatible with Division's memory_remember.
            conversation_id: Division conversation ID for audit episodes.
        """
        if not _AUDIT_AVAILABLE:
            logger.warning("DivisionVPE: audit module not available")
            return
        audit = DivisionVPEAudit(
            conversation_id=conversation_id,
            remember_func=remember_func,
        )
        self.set_audit(audit)

    def _record_audit(
        self,
        envelope: dict[str, Any],
        result_valid: bool,
        operation: str,
        reason: str = "",
    ) -> None:
        """Record an audit entry for a sign/verify operation.

        Only active if ``self._audit`` is set.
        """
        if self._audit is None:
            return

        try:
            # Compute envelope hash via canonical serialization
            canonical = str(_canonical_envelope(envelope))
            env_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        except (TypeError, ValueError, KeyError):
            # Canonicalization failed — use a degraded hash derived from the nonce
            # for audit-record identification only. The "degraded:" prefix flags this
            # as an unreliable identifier for cross-referencing.
            env_hash = "degraded:" + envelope.get("nonce", "unknown")[:16]
            logger.warning(
                "DivisionVPE: envelope canonicalization failed for issuer='%s' — using degraded hash '%s'",
                envelope.get("issuer", self._agent_name),
                env_hash,
            )
            # Override reason so downstream reviewers know the hash is unreliable
            if not reason:
                reason = "hash_computation_failed"

        issuer = envelope.get("issuer", self._agent_name)
        vpe_result = "valid" if result_valid else "invalid"

        self._audit.record(
            envelope_hash=env_hash,
            issuer=issuer,
            result=vpe_result,
            reason=reason or f"operation={operation}",
            tool_name=f"division_vpe_signer:{operation}",
        )

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def ensure_keys(self) -> bool:
        """Ensure VPE keypair exists.

        Returns True if keys are available.
        """
        if not _SEAL_AVAILABLE:
            logger.warning("DivisionVPE: seal module not available")
            return False

        try:
            sk, pk = load_or_generate_keypair(self._key_dir)
            self._private_key = sk
            self._public_key = pk
            return True
        except Exception as exc:
            logger.warning("DivisionVPE: key setup failed: %s", exc)
            return False

    def set_mode(self, mode: str) -> None:
        """Change operational mode.

        Args:
            mode: "sign", "verify", or "bypass".
        """
        if mode not in ("sign", "verify", "bypass"):
            raise ValueError(f"Invalid mode: {mode}. Use 'sign', 'verify', or 'bypass'.")
        self._mode = mode

    # ------------------------------------------------------------------
    # Signing (for memory writes)
    # ------------------------------------------------------------------

    def wrap_for_storage(
        self,
        value: Any,
        domain: str = "",
        agent: str = "",
        key: str = "",
    ) -> Any:
        """Wrap a memory value with VPE signature before storage.

        In 'bypass' mode (default), the value is returned as-is.

        Args:
            value: The value to store (dict, list, str, etc.).
            domain: The Division memory domain.
            agent: The agent storing this episode.
            key: Optional episode key for context.

        Returns:
            If signing: a signed wrapper dict.
            If bypass: the original value unchanged.
        """
        if self._mode == "bypass" or not _SEAL_AVAILABLE:
            return value

        if self._private_key is None:
            ok = self.ensure_keys()
            if not ok:
                logger.warning("DivisionVPE: cannot sign, no keypair")
                return value

        # Serialize the value to JSON for signing
        try:
            value_json = json.dumps(value, default=str, sort_keys=True)
        except (TypeError, ValueError) as exc:
            logger.warning("DivisionVPE: cannot serialize value for signing: %s", exc)
            return value

        # Create a prompt-like string from the episode metadata + value
        sign_prompt = json.dumps(
            {
                "domain": domain or "",
                "agent": agent or self._agent_name,
                "key": key or "",
                "value": value_json,
            },
            sort_keys=True,
        )

        # Additional context for the VPE envelope
        scope = {
            "allowed_tools": ["memory_remember"],
            "allowed_domains": [domain] if domain else [],
        }

        try:
            envelope = vpe_sign(
                prompt=sign_prompt,
                issuer=f"agent:{agent or self._agent_name}",
                audience="division:memory",
                private_key=self._private_key,
                scope=scope,
                ttl_seconds=86400 * 365,  # 1 year — memory is long-lived
                public_key=self._public_key,
            )

            # Wrap the original value with the signature
            wrapper: dict[str, Any] = {
                _VPE_SIGNED_MARKER: True,
                "vpe_version": envelope.get("vpe_version", VPE_VERSION),
                "value": value,
                "signature": envelope.get("signature", ""),
                "signed_by": f"agent:{agent or self._agent_name}",
                "signed_at": int(time.time()),
                "nonce": envelope.get("nonce", ""),
                "public_key": (self._public_key or b"").hex(),
                "_original_envelope": envelope,
            }

            logger.info(
                "DivisionVPE: signed memory episode for domain='%s' agent='%s'",
                domain,
                agent,
            )

            # P6.4b: Record successful sign in audit trail
            self._record_audit(envelope, True, "sign")

            return wrapper

        except Exception as exc:
            logger.warning("DivisionVPE: signing failed: %s", exc)
            return value  # fall back to unsigned

    # ------------------------------------------------------------------
    # Verification (for memory reads)
    # ------------------------------------------------------------------

    def verify_stored_value(
        self,
        value: Any,
    ) -> VPEResult:
        """Verify a potentially signed memory value.

        Args:
            value: The value retrieved from memory. May be signed or unsigned.

        Returns:
            VPEResult with valid=True if the value is authentic.
            If the value is not signed, returns valid=True with note.
        """
        if not _SEAL_AVAILABLE:
            return VPEResult(True, "seal module not available — cannot verify")

        # Check if this is a signed wrapper
        if not isinstance(value, dict) or not value.get(_VPE_SIGNED_MARKER):
            return VPEResult(
                True,
                "unsigned value — no cryptographic verification available",
                envelope=None,
            )

        # Extract the original envelope and reconstruct it for verification
        envelope_data = value.get("_original_envelope", {})
        signature = value.get("signature", "")
        pk_hex = value.get("public_key", "")
        signed_by = value.get("signed_by", "unknown")
        signed_at = value.get("signed_at", 0)

        if not signature:
            return VPEResult(False, "signed wrapper has no signature field")

        # Try verifying using the stored envelope first
        if envelope_data:
            try:
                pk = value.get("public_key", "")
                pub_key = bytes.fromhex(pk) if pk else self._public_key

                # Check nonce replay before calling vpe_verify so we can use
                # the persistent NonceStore (survives restarts) rather than
                # the in-memory set that vpe_verify's seen_nonces uses.
                nonce = envelope_data.get("nonce", "")
                if nonce and self._nonce_store is not None:
                    if not self._nonce_store.add(nonce):
                        result = VPEResult(False, "nonce replay detected")
                        self._record_audit(envelope_data, False, "verify", reason=result.reason)
                        return result
                    # Nonce recorded; skip replay check inside vpe_verify
                    skip = ["expiry", "replay"]
                else:
                    skip = ["expiry"]

                result = vpe_verify(
                    envelope_data,
                    public_key=pub_key,
                    seen_nonces=self._seen_nonces,
                    skip_checks=skip,
                )
                # P6.4b: Record verification in audit trail
                self._record_audit(envelope_data, result.valid, "verify", reason=result.reason)
                return result
            except Exception as exc:
                logger.warning("DivisionVPE: verification error: %s", exc)
                # Fall through to basic signature check

        # Basic verification: check that we can extract a valid signature
        if self._public_key:
            try:
                pk_hex_actual = pk_hex or self._public_key.hex()
                pub_key = bytes.fromhex(pk_hex_actual) if isinstance(pk_hex_actual, str) else pk_hex_actual
                # Reconstruct envelope for verification
                check_envelope = {
                    "vpe_version": value.get("vpe_version", VPE_VERSION),
                    "prompt": json.dumps({"signed_by": signed_by, "signed_at": signed_at}, sort_keys=True),
                    "scope": {"allowed_tools": ["memory_remember"]},
                    "issuer": signed_by,
                    "audience": "division:memory",
                    "doc_sha256": "",
                    "ttl_seconds": 86400 * 365,
                    "iat": signed_at,
                    "nonce": value.get("nonce", ""),
                    "counter": 1,
                    "signature": signature,
                }
                if pub_key:
                    check_envelope["public_key"] = pub_key.hex() if isinstance(pub_key, bytes) else pub_key

                result = vpe_verify(
                    check_envelope,
                    public_key=pub_key if isinstance(pub_key, bytes) else None,
                    skip_checks=["expiry"],
                )
                # P6.4b: Record verification in audit trail
                self._record_audit(check_envelope, result.valid, "verify", reason=result.reason)
                return result
            except Exception as exc:
                return VPEResult(False, f"verification failed: {exc}")

        return VPEResult(
            False,
            "cannot verify: no public key available for the stored value",
        )

    # ------------------------------------------------------------------
    # Batch operations
    # ------------------------------------------------------------------

    def verify_batch(self, values: list[Any]) -> list[tuple[Any, VPEResult]]:
        """Verify a batch of memory values.

        Args:
            values: List of values from memory recall.

        Returns:
            List of (value, VPEResult) tuples.
        """
        results = []
        for value in values:
            result = self.verify_stored_value(value)
            results.append((value, result))
        return results

    def is_signed(self, value: Any) -> bool:
        """Check if a value is VPE-signed.

        Args:
            value: The value to check.

        Returns:
            True if the value is a VPE-signed wrapper.
        """
        return isinstance(value, dict) and value.get(_VPE_SIGNED_MARKER) is True

    def extract_value(self, value: Any) -> Any:
        """Extract the original value from a signed wrapper.

        Args:
            value: Potentially signed value.

        Returns:
            The original value (unwrapped), or the value as-is if not signed.
        """
        if self.is_signed(value):
            return value.get("value", value)
        return value
