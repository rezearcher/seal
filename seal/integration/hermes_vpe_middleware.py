"""
Hermes VPE Middleware — Optional VPE verification gate for Hermes Agent tool calls.

Integrates VPE (Verified Prompt Envelope) verification into the Hermes
tool call pipeline. When enabled, every tool call is checked against the
VPE envelope of the current prompt before execution.

Two modes:
  - ENFORCE: Reject tool calls that fail VPE verification
  - AUDIT: Log verification failures but allow execution (warn-only)

This is designed to be loaded as a Hermes plugin via the plugin system
(pre_tool_call hook), or used programmatically as a standalone wrapper.

Usage:
    from integration.hermes_vpe_middleware import VPEMiddleware

    middleware = VPEMiddleware(mode="audit")
    result = middleware.check_tool_call(
        tool_name="terminal",
        tool_args={"command": "curl http://...", "timeout": 30},
        prompt_envelope=signed_envelope,
    )
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

# Try to import seal — fall back gracefully if not installed
try:
    from seal import vpe_sign, vpe_verify
    from seal.vpe import VPEResult, generate_keypair, load_or_generate_keypair, VPE_VERSION
    from seal.epd import scan as epd_scan
    _SEAL_AVAILABLE = True
except ImportError:
    _SEAL_AVAILABLE = False
    VPEResult = None  # type: ignore

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


def _load_config() -> Dict[str, Any]:
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
    """

    __slots__ = ("allowed", "decision", "reason", "verified")

    def __init__(self, allowed: bool, decision: str, reason: str = "", verified: bool = True):
        self.allowed = allowed
        self.decision = decision
        self.reason = reason
        self.verified = verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "reason": self.reason,
            "verified": self.verified,
        }

    def __repr__(self) -> str:
        return f"<VPECheckResult {self.decision}: {self.reason}>"


class VPEMiddleware:
    """VPE verification middleware for Hermes tool calls.

    Wraps tool call dispatch with VPE envelope verification and optional
    EPD scanning.

    Usage:
        middleware = VPEMiddleware()
        middleware.ensure_keys()
        result = middleware.check_tool_call(
            tool_name="terminal",
            tool_args={"command": "rm -rf /"},
            prompt="the original prompt text",
        )
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
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
        self._skip_tools: List[str] = self.config.get("vpe_skip_tools", [])
        self._epd_enabled = self.config.get("vpe_epd_enabled", True)
        self._epd_min_confidence = float(self.config.get("vpe_epd_min_confidence", 0.85))

        # Keypair cache
        self._public_key: Optional[bytes] = None
        self._private_key: Optional[bytes] = None

        # Nonce replay cache (in-memory set)
        self._seen_nonces: set = set()

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
                from seal.vpe import load_keypair
                sk, pk = load_keypair(self._key_dir)
            else:
                from seal.vpe import load_or_generate_keypair
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

    def _scan_prompt(self, prompt: str) -> Dict[str, Any]:
        """Run EPD scan on a prompt.

        Returns scan result dict.
        """
        if not _SEAL_AVAILABLE or not self._epd_enabled:
            return {"clean": True, "flags": [], "llm_used": False}

        try:
            from seal.epd import EPDConfig
            import dataclasses
            config = EPDConfig(block_threshold=self._epd_min_confidence)
            result = epd_scan(prompt, config=config)
            return dataclasses.asdict(result)
        except Exception as exc:
            logger.warning("VPE: EPD scan failed: %s", exc)
            return {"clean": True, "flags": [], "llm_used": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        prompt: str = "",
        prompt_envelope: Optional[Dict[str, Any]] = None,
    ) -> VPECheckResult:
        """Check if a tool call should be allowed.

        The check proceeds through these stages:
        1. Short-circuit: if VPE is disabled, allow
        2. Skip tools: if tool is in skip list, allow
        3. EPD scan: if enabled, scan the prompt for injection
        4. VPE verify: if envelope provided, verify it

        Args:
            tool_name: Name of the tool being called.
            tool_args: Arguments to the tool.
            prompt: The original prompt text (for EPD scanning).
            prompt_envelope: An optional VPE envelope to verify.

        Returns:
            VPECheckResult with the decision.
        """
        # Stage 1: Disabled
        if not self._enabled:
            return VPECheckResult(True, "allow", "VPE disabled", verified=False)

        # Stage 2: Skip tools
        if tool_name in self._skip_tools:
            return VPECheckResult(True, "allow", f"tool '{tool_name}' is in skip list")

        # Stage 3: EPD scan
        if prompt and self._epd_enabled:
            epd_result = self._scan_prompt(prompt)
            if not epd_result.get("clean", True):
                flags = epd_result.get("flags", [])
                reason = f"EPD injection scan flagged: {[f['pattern_name'] for f in flags]}"
                if self._mode == "enforce":
                    return VPECheckResult(False, "deny", reason)
                else:
                    logger.warning("VPE (audit): %s", reason)
                    # Continue to VPE verification even in audit mode
                    return VPECheckResult(False, "audit_logged", reason)

        # Stage 4: VPE verify
        if prompt_envelope is not None:
            if not _SEAL_AVAILABLE:
                return VPECheckResult(
                    False,
                    "deny" if self._mode == "enforce" else "audit_logged",
                    "VPE verification requested but seal module unavailable",
                    verified=False,
                )

            try:
                result = vpe_verify(
                    prompt_envelope,
                    public_key=self._public_key,
                    seen_nonces=self._seen_nonces,
                    actual_args={"_tool_name": tool_name, **(tool_args or {})},
                )
                if not result.valid:
                    reason = f"VPE verification failed: {result.reason}"
                    if self._mode == "enforce":
                        return VPECheckResult(False, "deny", reason)
                    else:
                        logger.warning("VPE (audit): %s", reason)
                        return VPECheckResult(False, "audit_logged", reason)
            except Exception as exc:
                reason = f"VPE verify exception: {exc}"
                if self._mode == "enforce":
                    return VPECheckResult(False, "deny", reason)
                else:
                    logger.warning("VPE (audit): %s", reason)
                    return VPECheckResult(False, "audit_logged", reason)

        return VPECheckResult(True, "allow", "all checks passed")


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
_middleware: Optional[VPEMiddleware] = None


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
) -> Optional[Dict[str, Any]]:
    """Pre-tool-call hook handler for Hermes plugin system.

    Called before every tool invocation. Return a dict with 'veto': True
    to block the call, or None to allow it.

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

    if not result.allowed and result.decision == "deny":
        logger.warning(
            "VPE blocked tool call '%s': %s",
            tool_name_str, result.reason,
        )
        return {"veto": True, "reason": f"[VPE BLOCKED] {result.reason}"}

    if result.decision == "audit_logged":
        logger.info(
            "VPE audit: tool '%s' would have been blocked: %s",
            tool_name_str, result.reason,
        )

    return None


# ---------------------------------------------------------------------------
# Standalone CLI / config helper
# ---------------------------------------------------------------------------


def setup_vpe(mode: str = "audit", key_dir: Optional[str] = None) -> VPEMiddleware:
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
