"""
Hermes VPE Middleware — Optional VPE verification gate for Hermes Agent tool calls.

Integrates VPE (Verified Prompt Envelope) verification into the Hermes
tool call pipeline. When enabled, every tool call is checked against the
VPE envelope of the current prompt before execution.

Three verification decisions (P6.3 — Graceful Degradation):
  - **Unsigned prompts** (raw text): Logged as "unverified" with warning.
    Allowed in both strict and lenient modes (backward compatibility).
  - **Expired envelopes** (TTL exceeded): Logged as expired, prompt still
    executed. Allowed in both strict and lenient modes.
  - **Invalid signatures** (crypto failure): Rejected in strict (enforce)
    mode with clear error. Allowed but logged in lenient (audit) mode.

Two modes:
  - ENFORCE (strict): Invalid signatures rejected; other degradations logged.
  - AUDIT (lenient): All degradations logged-but-allowed.

Usage:
    from seal.integration.hermes_vpe_middleware import VPEMiddleware

    middleware = VPEMiddleware(mode="audit")
    result = middleware.check_tool_call(
        tool_name="terminal",
        tool_args={"command": "curl http://...", "timeout": 30},
        prompt="the original prompt text",
        prompt_envelope=signed_envelope,
    )
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

# Try to import seal — fall back gracefully if not installed
try:
    from seal.epd import EPDResult
    from seal.epd import scan as epd_scan
    from seal.vpe import (
        VPE_VERSION,
        VPEResult,
        load_or_generate_keypair,
    )
    from seal.vpe import (
        vpe_verify as _vpe_verify_raw,
    )

    _SEAL_AVAILABLE = True
except ImportError:
    _SEAL_AVAILABLE = False
    VPEResult = None  # type: ignore
    VPE_VERSION = "1.0"
    load_or_generate_keypair = None  # type: ignore
    _vpe_verify_raw = None  # type: ignore
    epd_scan = None  # type: ignore
    EPDResult = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Config keys read from Hermes config.yaml under security.vpe.*
# In Hermes config.yaml:
#   security:
#     vpe_enabled: false
#     vpe_mode: audit           # "audit" or "enforce"
#     vpe_key_dir: ~/.hermes/vpe-keys/
#     vpe_skip_tools: [list, of, tool, names]
#     vpe_epd_enabled: true
#     vpe_epd_min_confidence: 0.85

_CONFIG_DEFAULTS = {
    "vpe_enabled": False,
    "vpe_mode": "audit",
    "vpe_key_dir": os.path.expanduser("~/.hermes/vpe-keys/"),
    "vpe_skip_tools": ["todo", "memory", "clarify", "session_search"],
    "vpe_epd_enabled": True,
    "vpe_epd_min_confidence": 0.85,
}


def _load_config() -> dict[str, Any]:
    """Load VPE config from Hermes config.yaml, with env var overrides.

    Returns merged config dict.
    """
    config = dict(_CONFIG_DEFAULTS)

    # Try loading from Hermes config
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
        sec = cfg.get("security", {}) or {}
        vpe_cfg = sec.get("vpe", {}) or {}
        config.update(vpe_cfg)
    except (ImportError, Exception) as exc:
        logger.debug("VPE: couldn't load Hermes config: %s", exc)

    # Env var overrides
    env_overrides = {
        "vpe_enabled": os.getenv("VPE_ENABLED", "").lower() in ("1", "true", "yes"),
        "vpe_mode": os.getenv("VPE_MODE", ""),
        "vpe_key_dir": os.getenv("VPE_KEY_DIR", ""),
        "vpe_skip_tools": os.getenv("VPE_SKIP_TOOLS", ""),
        "vpe_epd_enabled": os.getenv("VPE_EPD_ENABLED", "").lower() in ("1", "true", "yes"),
    }
    for k, v in env_overrides.items():
        if v:
            if k == "vpe_skip_tools" and isinstance(v, str):
                config[k] = [t.strip() for t in v.split(",") if t.strip()]
            else:
                config[k] = v

    return config


# ---------------------------------------------------------------------------
# VPE Middleware
# ---------------------------------------------------------------------------


class VPECheckResult:
    """Result of a VPE middleware check.

    Attributes:
        allowed: True if the tool call is permitted.
        decision: "allow", "deny", or "audit_logged".
        reason: Human-readable explanation.
        verified: Whether VPE verification was actually performed.
        degradation: Type of degradation applied, or None if no degradation.
            One of: None, "unsigned", "expired", "invalid_signature", "verify_error".
        mode: The VPE mode at decision time ("audit" or "enforce").
    """

    __slots__ = ("allowed", "decision", "reason", "verified", "degradation", "mode")

    def __init__(
        self,
        allowed: bool,
        decision: str,
        reason: str = "",
        verified: bool = True,
        degradation: str | None = None,
        mode: str = "audit",
    ):
        self.allowed = allowed
        self.decision = decision
        self.reason = reason
        self.verified = verified
        self.degradation = degradation
        self.mode = mode

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "reason": self.reason,
            "verified": self.verified,
            "degradation": self.degradation,
            "mode": self.mode,
        }

    def __repr__(self) -> str:
        deg = f" [degradation={self.degradation}]" if self.degradation else ""
        return f"<VPECheckResult {self.decision}: {self.reason}{deg}>"


class VPEMiddleware:
    """VPE verification middleware for Hermes tool calls.

    Wraps tool call dispatch with VPE envelope verification and optional
    EPD scanning. Implements P6.3 graceful degradation:

    - Unsigned prompts (raw text): logged as "unverified" → allowed.
    - Expired envelopes: logged as expired → allowed (both strict/lenient).
    - Invalid signatures: rejected in enforce mode, allowed in audit mode.

    Usage:
        middleware = VPEMiddleware()
        middleware.ensure_keys()
        result = middleware.check_tool_call(
            tool_name="terminal",
            tool_args={"command": "ls"},
            prompt="the original prompt text",
        )
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize VPE middleware.

        Args:
            config: Override config dict. Keys match _CONFIG_DEFAULTS.
        """
        self.config = _load_config()
        if config:
            self.config.update(config)

        self._enabled = self.config.get("vpe_enabled", False)
        self._mode = self.config.get("vpe_mode", "audit")
        self._key_dir = self.config.get("vpe_key_dir", _CONFIG_DEFAULTS["vpe_key_dir"])
        self._skip_tools: list[str] = self.config.get("vpe_skip_tools", [])
        self._epd_enabled = self.config.get("vpe_epd_enabled", True)
        self._epd_min_confidence = float(self.config.get("vpe_epd_min_confidence", 0.85))

        # Keypair cache
        self._public_key: bytes | None = None
        self._private_key: bytes | None = None

        # Nonce replay cache (in-memory set)
        self._seen_nonces: set = set()

        # Envelope first-seen timestamps for TTL expiry checking
        # Keyed by nonce → time.time() when first verified
        self._envelope_timestamps: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def ensure_keys(self) -> bool:
        """Ensure VPE keypair exists, generating if necessary.

        Returns True if keys are available.
        """
        if not _SEAL_AVAILABLE:
            logger.warning("VPE: seal module not available — install pynacl or cryptography")
            return False

        try:
            priv_path = os.path.join(self._key_dir, "vpe_private.key")
            if os.path.exists(priv_path):
                sk, pk = load_or_generate_keypair(self._key_dir)
            else:
                sk, pk = load_or_generate_keypair(self._key_dir)
                logger.info("VPE: generated new keypair at %s", self._key_dir)

            self._private_key = sk
            self._public_key = pk
            return True
        except Exception as exc:
            logger.warning("VPE: key setup failed: %s", exc)
            return False

    def get_public_key_hex(self) -> str:
        """Get the public key as a hex string.

        Returns empty string if keys not loaded.
        """
        if self._public_key:
            return self._public_key.hex()
        return ""

    # ------------------------------------------------------------------
    # EPD scan
    # ------------------------------------------------------------------

    def _scan_prompt(self, prompt: str) -> dict[str, Any]:
        """Run EPD scan on a prompt.

        Returns scan result dict with 'clean', 'flags', 'llm_used' keys.
        """
        if not _SEAL_AVAILABLE or not self._epd_enabled:
            return {"clean": True, "flags": [], "llm_used": False}

        try:
            result = epd_scan(prompt)
            return {
                "clean": result.clean,
                "flags": [
                    {
                        "pattern_name": f.pattern_name,
                        "confidence": f.confidence,
                        "category": f.category,
                        "location": f.location_in_prompt,
                    }
                    for f in result.flags
                ],
                "llm_used": result.llm_used,
            }
        except Exception as exc:
            logger.warning("VPE: EPD scan failed: %s", exc)
            return {"clean": True, "flags": [], "llm_used": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Envelope TTL / expiry tracking
    # ------------------------------------------------------------------

    def _check_envelope_expiry(self, envelope: dict[str, Any]) -> str | None:
        """Check if an envelope has expired based on TTL and first-seen time.

        Since v1.0 envelopes carry an ``iat`` field (or legacy ``issued_at``),
        we maintain our own first-seen timestamp per nonce. This catches
        replay of expired envelopes.

        Args:
            envelope: The VPE envelope dict.

        Returns:
            An expiry reason string if expired, or None if still valid.
        """
        ttl = envelope.get("ttl_seconds", 0)
        if not isinstance(ttl, int) or ttl <= 0:
            return None  # no expiry configured

        nonce = envelope.get("nonce", "")
        if not nonce:
            return None

        # Check if we have a stored timestamp
        first_seen = self._envelope_timestamps.get(nonce)
        if first_seen is not None:
            elapsed = time.time() - first_seen
            if elapsed > ttl:
                return f"envelope expired: {elapsed:.0f}s elapsed > {ttl}s TTL"
            return None  # still within TTL

        # Check native iat field (primary) or legacy issued_at (backward compat)
        issued_at = envelope.get("iat") or envelope.get("issued_at")
        if isinstance(issued_at, (int, float)) and issued_at > 0:
            elapsed = time.time() - issued_at
            if elapsed > ttl:
                return f"envelope expired: {elapsed:.0f}s elapsed > {ttl}s TTL (iat)"
            return None

        # First time seeing this nonce — record it and treat as fresh
        self._envelope_timestamps[nonce] = time.time()
        return None

    # ------------------------------------------------------------------
    # Verification with graceful degradation
    # ------------------------------------------------------------------

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        prompt: str = "",
        prompt_envelope: dict[str, Any] | None = None,
    ) -> VPECheckResult:
        """Check if a tool call should be allowed.

        Implements P6.3 graceful degradation:
        - Unsigned (raw text) prompts: logged as unverified, always allowed.
        - Expired envelopes: logged, always allowed (both strict & lenient).
        - Invalid signatures: rejected in enforce mode, logged in audit mode.

        Args:
            tool_name: Name of the tool being called.
            tool_args: Arguments to the tool.
            prompt: The original prompt text (for EPD scanning).
            prompt_envelope: An optional VPE envelope dict to verify.

        Returns:
            VPECheckResult with the decision and degradation detail.
        """
        is_enforce = self._mode == "enforce"

        # Stage 1: Disabled
        if not self._enabled:
            return VPECheckResult(True, "allow", "VPE disabled", verified=False, mode=self._mode)

        # Stage 2: Skip tools
        if tool_name in self._skip_tools:
            return VPECheckResult(
                True,
                "allow",
                f"tool '{tool_name}' is in skip list",
                mode=self._mode,
            )

        # Stage 3: EPD scan (on prompt text, regardless of envelope)
        if prompt and self._epd_enabled:
            epd_result = self._scan_prompt(prompt)
            if not epd_result.get("clean", True):
                flags = epd_result.get("flags", [])
                reason = f"EPD injection scan flagged: {[f['pattern_name'] for f in flags]}"
                if is_enforce:
                    return VPECheckResult(False, "deny", reason, mode=self._mode)
                else:
                    logger.warning("VPE (audit): %s", reason)
                    return VPECheckResult(False, "audit_logged", reason, mode=self._mode)

        # Stage 4: Detect unsigned prompt (no envelope provided)
        if prompt_envelope is None:
            reason = "UNSIGNED PROMPT: no VPE envelope — logged as unverified"
            logger.warning("VPE (unsigned): %s", reason)
            # Unsigned prompts always work (core backward-compatibility constraint)
            return VPECheckResult(
                True,
                "allow",
                reason,
                verified=False,
                degradation="unsigned",
                mode=self._mode,
            )

        # Stage 5: Verify VPE envelope
        if not _SEAL_AVAILABLE:
            reason = "VPE verification requested but seal module unavailable"
            if is_enforce:
                return VPECheckResult(False, "deny", reason, verified=False, mode=self._mode)
            else:
                logger.warning("VPE (audit): %s", reason)
                return VPECheckResult(
                    False,
                    "audit_logged",
                    reason,
                    verified=False,
                    degradation="verify_error",
                    mode=self._mode,
                )

        # 5a: Try to verify the envelope
        # Parse if it's a string
        if isinstance(prompt_envelope, str):
            try:
                envelope = json.loads(prompt_envelope)
            except (json.JSONDecodeError, ValueError) as exc:
                reason = f"VPE envelope parse failed: {exc}"
                if is_enforce:
                    return VPECheckResult(False, "deny", reason, degradation="verify_error", mode=self._mode)
                else:
                    logger.warning("VPE (audit): %s", reason)
                    return VPECheckResult(
                        False,
                        "audit_logged",
                        reason,
                        degradation="verify_error",
                        mode=self._mode,
                    )
        else:
            envelope = prompt_envelope

        # 5b: Check for envelope-like structure (is this actually a VPE envelope?)
        # If it looks like raw text wrapped in a dict, treat as unsigned
        if not isinstance(envelope, dict):
            reason = "UNSIGNED PROMPT: envelope is not a dict — logged as unverified"
            logger.warning("VPE (unsigned): %s", reason)
            return VPECheckResult(
                True,
                "allow",
                reason,
                verified=False,
                degradation="unsigned",
                mode=self._mode,
            )

        # 5c: Check if this looks like a VPE envelope (has signature field)
        has_signature = bool(envelope.get("signature", ""))
        if not has_signature:
            reason = "UNSIGNED PROMPT: envelope has no signature — logged as unverified"
            logger.warning("VPE (unsigned): %s", reason)
            return VPECheckResult(
                True,
                "allow",
                reason,
                verified=False,
                degradation="unsigned",
                mode=self._mode,
            )

        # 5d: Check expiry FIRST (before crypto verify — it might be a
        # perfectly valid but expired signature)
        expiry_reason = self._check_envelope_expiry(envelope)
        if expiry_reason:
            logger.warning("VPE (expired): %s — allowing execution", expiry_reason)
            # Expired envelopes are allowed in both modes (P6.3 spec)
            return VPECheckResult(
                True,
                "allow",
                f"EXPIRED ENVELOPE: {expiry_reason} (mode: {self._mode})",
                degradation="expired",
                mode=self._mode,
            )

        # 5e: Run vpe_verify for full cryptographic verification
        try:
            result = _vpe_verify_raw(
                envelope,
                public_key=self._public_key,
                seen_nonces=self._seen_nonces,
                actual_args={"_tool_name": tool_name, **(tool_args or {})},
            )
        except Exception as exc:
            reason = f"VPE verify exception: {exc}"
            if is_enforce:
                return VPECheckResult(False, "deny", reason, degradation="verify_error", mode=self._mode)
            else:
                logger.warning("VPE (audit): %s", reason)
                return VPECheckResult(
                    False,
                    "audit_logged",
                    reason,
                    degradation="verify_error",
                    mode=self._mode,
                )

        # 5f: Handle verification result with graceful degradation
        if not result.valid:
            reason = result.reason

            # Check if this is an expiry failure from vpe_verify
            is_expiry = "expired" in reason.lower() or "expir" in reason.lower()

            if is_expiry:
                # Expired envelopes allowed in both modes
                logger.warning("VPE (expired): %s — allowing execution", reason)
                return VPECheckResult(
                    True,
                    "allow",
                    f"EXPIRED ENVELOPE: {reason} (mode: {self._mode})",
                    degradation="expired",
                    mode=self._mode,
                )

            # This is an invalid signature or other crypto failure
            if is_enforce:
                return VPECheckResult(
                    False,
                    "deny",
                    f"VPE BLOCKED: {reason}",
                    degradation="invalid_signature",
                    mode=self._mode,
                )
            else:
                logger.warning("VPE (audit): %s", reason)
                return VPECheckResult(
                    False,
                    "audit_logged",
                    f"VPE INVALID (audit mode): {reason}",
                    degradation="invalid_signature",
                    mode=self._mode,
                )

        # All checks passed
        return VPECheckResult(True, "allow", "all checks passed", mode=self._mode)


# ---------------------------------------------------------------------------
# Hermes Plugin Integration
# ---------------------------------------------------------------------------

# This is the pre_tool_call hook handler for the Hermes plugin system.
# The plugin registers this function to intercept tool calls.
#
# Hermes plugin format:
#   plugins/vpe-middleware/
#   ├── plugin.yaml
#   └── __init__.py
#
# plugin.yaml:
#   name: vpe-middleware
#   version: "1.0.0"
#   hooks:
#     - pre_tool_call
#
# __init__.py:
#   from seal.integration.hermes_vpe_middleware import on_pre_tool_call
#   def setup(ctx):
#       ctx.register_hook("pre_tool_call", on_pre_tool_call)


# Global middleware instance (created once, reused across calls)
_middleware: VPEMiddleware | None = None


def _get_middleware() -> VPEMiddleware:
    """Get or create the global VPE middleware instance."""
    global _middleware
    if _middleware is None:
        _middleware = VPEMiddleware()
        _middleware.ensure_keys()
    return _middleware


def on_pre_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    user_message: str = "",
    **kwargs,
) -> dict[str, Any] | None:
    """Pre-tool-call hook handler for Hermes plugin system.

    Called before every tool invocation. Return a dict with 'veto': True
    to block the call, or None to allow it.

    This handler logs all degradation events (unsigned, expired, invalid)
    whether or not the tool call is ultimately allowed.

    Returns:
        None to allow, or {"veto": True, "reason": "..."} to block.
    """
    middleware = _get_middleware()
    if not middleware._enabled:
        return None

    tool_name_str = str(tool_name)
    tool_args_dict = args if isinstance(args, dict) else {}

    result = middleware.check_tool_call(
        tool_name=tool_name_str,
        tool_args=tool_args_dict,
        prompt=user_message,
    )

    # Log all degradations regardless of allow/deny
    if result.degradation:
        prefix = result.degradation.upper()
        if result.allowed:
            log_fn = logger.warning
        else:
            log_fn = logger.error
        log_fn(
            "VPE %s: tool='%s' allowed=%s reason='%s' mode='%s'",
            prefix,
            tool_name_str,
            result.allowed,
            result.reason,
            result.mode,
        )

    if not result.allowed and result.decision == "deny":
        logger.warning(
            "VPE blocked tool call '%s': %s",
            tool_name_str,
            result.reason,
        )
        return {"veto": True, "reason": f"[VPE BLOCKED] {result.reason}"}

    if result.decision == "audit_logged":
        logger.info(
            "VPE audit: tool '%s' would have been blocked: %s",
            tool_name_str,
            result.reason,
        )

    return None


# ---------------------------------------------------------------------------
# Standalone CLI / config helper
# ---------------------------------------------------------------------------


def setup_vpe(mode: str = "audit", key_dir: str | None = None) -> VPEMiddleware:
    """Setup VPE middleware with defaults for Hermes integration.

    This is the recommended entry point for Hermes startup scripts.

    Args:
        mode: "audit" or "enforce".
        key_dir: Directory for VPE keypair. Defaults to ~/.hermes/vpe-keys/.

    Returns:
        Configured VPEMiddleware instance.
    """
    config = {"vpe_enabled": True, "vpe_mode": mode}
    if key_dir:
        config["vpe_key_dir"] = key_dir
    mw = VPEMiddleware(config)
    mw.ensure_keys()
    return mw


# ---------------------------------------------------------------------------
# Config snippet (for ~/.hermes/config.yaml)
# ---------------------------------------------------------------------------

_CONFIG_SNIPPET = """
# VPE (Verified Prompt Envelope) — cryptographic prompt provenance
# See: ~/projects/seal/integration/hermes_vpe_middleware.py
security:
  vpe:
    # Master ON/OFF — disable without uninstalling
    vpe_enabled: false
    # "audit" → log violations, allow execution
    # "enforce" → reject unverified tool calls
    vpe_mode: audit
    # Directory for the Ed25519 keypair
    vpe_key_dir: ~/.hermes/vpe-keys/
    # Tools exempt from VPE checks (internal tools)
    vpe_skip_tools: [todo, memory, clarify, session_search]
    # EPD (Embedded Prompt Detection) scanner
    vpe_epd_enabled: true
    # Minimum confidence threshold for EPD flags (0.0-1.0)
    vpe_epd_min_confidence: 0.85
"""

# vpe_key_dir layout:
#   ~/.hermes/vpe-keys/
#   ├── vpe_private.key    # Ed25519 private seed (32 bytes hex, chmod 0600)
#   └── vpe_public.key     # Ed25519 public key (32 bytes hex)
#
# Generated automatically on first use.
