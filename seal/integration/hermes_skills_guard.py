"""
Hermes Skills Guard Integration — Replace/extend Hermes' existing security
guard patterns with VPE + EPD.

Hermes currently has:
1. **Secret redaction** (security.redact_secrets) — ML-based secret scanning
   in tool output before it enters model context
2. **TIRITH security** (tirith_enabled) — pre-exec binary scanner for
   terminal injection, homograph URLs, etc.
3. **security-guidance plugin** — code-level security pattern warnings
   on file writes (eval, pickle, yaml.load, etc.)

This module provides the bridge to upgrade these reactive guards with
VPE's cryptographic provenance verification and EPD's prompt injection
scanning.

Architecture:
    User Prompt → VPE Envelope (with scope) → EPD Scan → Tool Execution
                                                       ↓
                                              VPE Verify (tool call)
                                                       ↓
                                              TIRITH (terminal only)
                                                       ↓
                                              Secret Redaction (output)

The VPE + EPD layers run BEFORE existing guards, providing:
- Cryptographic proof of prompt origin (VPE)
- Injection detection at the prompt level (EPD)
- Scope enforcement (allowed_tools, max_cost, etc.)

Integration with Hermes config.yaml:
    security:
      vpe:
        enabled: false
        mode: audit
        epd_enabled: true
      tirith_enabled: true   # runs after VPE gate
      redact_secrets: true   # unchanged
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from seal.vpe import (
        vpe_sign,
        vpe_verify,
        VPEResult,
        generate_keypair,
        load_or_generate_keypair,
        VPE_VERSION,
    )
    from seal.epd import epd_scan, EPDResult, EPDFlag
    _SEAL_AVAILABLE = True
except ImportError:
    _SEAL_AVAILABLE = False
    VPEResult = None  # type: ignore
    EPDResult = None  # type: ignore


# ---------------------------------------------------------------------------
# Guard Chain
# ---------------------------------------------------------------------------


class VPEGuardChain:
    """Composite security guard chain: VPE → EPD → existing guards.

    Orchestrates the full security pipeline for a Hermes tool call:

    1. VPE Verify — verify cryptographic provenance of the prompt
    2. EPD Scan — scan for injection patterns
    3. Scope Check — verify tool/arg compliance with envelope scope
    4. Forward to existing guards (TIRITH, secret redaction)

    This replaces the role of Hermes' existing 120+ regex guard patterns
    for prompt-level security. The regex patterns remain for terminal-
    level content filtering (via TIRITH).
    """

    def __init__(
        self,
        public_key: Optional[bytes] = None,
        mode: str = "audit",
        epd_enabled: bool = True,
        epd_min_confidence: float = 0.85,
    ):
        """Initialize the VPE guard chain.

        Args:
            public_key: Ed25519 public key for VPE verification.
            mode: "audit" (log violations) or "enforce" (reject).
            epd_enabled: If True, run EPD scanning.
            epd_min_confidence: Minimum confidence for EPD flags.
        """
        self._public_key = public_key
        self._mode = mode
        self._epd_enabled = epd_enabled
        self._epd_min_confidence = epd_min_confidence
        self._seen_nonces: set = set()

    def set_public_key(self, public_key: bytes) -> None:
        """Set the Ed25519 public key for verification."""
        self._public_key = public_key

    # ------------------------------------------------------------------
    # Stage 1: VPE Verify
    # ------------------------------------------------------------------

    def check_vpe(self, envelope: Dict[str, Any]) -> VPEResult:
        """Verify a VPE envelope.

        Returns VPEResult with valid=True/False.
        """
        if not _SEAL_AVAILABLE:
            return VPEResult(True, "no seal module — VPE skip")

        if self._public_key is None:
            return VPEResult(True, "no public key configured — VPE skip")

        return vpe_verify(
            envelope,
            public_key=self._public_key,
            seen_nonces=self._seen_nonces,
        )

    # ------------------------------------------------------------------
    # Stage 2: EPD Scan
    # ------------------------------------------------------------------

    def check_epd(self, prompt: str) -> EPDResult:
        """Scan a prompt for injection patterns.

        Returns EPDResult.
        """
        if not _SEAL_AVAILABLE or not self._epd_enabled:
            empty = EPDResult(clean=True)
            return empty

        return epd_scan(
            prompt,
            min_confidence=self._epd_min_confidence,
        )

    # ------------------------------------------------------------------
    # Stage 3: Scope Check
    # ------------------------------------------------------------------

    def check_scope(
        self,
        envelope: Dict[str, Any],
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[str]:
        """Check tool call against VPE envelope scope.

        Args:
            envelope: The VPE envelope.
            tool_name: The requested tool.
            tool_args: The tool arguments.

        Returns:
            Error string if scope violated, None if OK.
        """
        if not _SEAL_AVAILABLE:
            return None

        scope = envelope.get("scope", {})
        if not scope:
            return None  # no scope = no restrictions

        # Check allowed_tools
        allowed_tools = scope.get("allowed_tools")
        if allowed_tools and tool_name not in allowed_tools:
            return f"Tool '{tool_name}' not in allowed_tools: {allowed_tools}"

        # Check allowed_domains (for URL-related tools)
        allowed_domains = scope.get("allowed_domains")
        if allowed_domains:
            url = tool_args.get("url", "") or tool_args.get("command", "")
            if url:
                import re
                if not any(domain in url for domain in allowed_domains):
                    return f"URL/command target not in allowed_domains: {allowed_domains}"

        # Check max_tokens (for LLM tools)
        max_tokens = scope.get("max_tokens")
        if max_tokens:
            requested = tool_args.get("max_tokens", 0) or 0
            if requested > max_tokens:
                return f"Requested {requested} tokens exceeds scope max_tokens {max_tokens}"

        return None

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def check_all(
        self,
        prompt: str = "",
        envelope: Optional[Dict[str, Any]] = None,
        tool_name: str = "",
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run the full VPE+EPD security pipeline.

        Args:
            prompt: The original prompt text.
            envelope: Optional VPE envelope.
            tool_name: The tool being called.
            tool_args: Tool call arguments.

        Returns:
            Dict with keys:
                - allowed (bool): whether call is permitted
                - reason (str): explanation if denied
                - stages (dict): per-stage results
        """
        stages: Dict[str, Any] = {}
        tool_args = tool_args or {}

        # Stage 1: VPE
        if envelope:
            vpe_result = self.check_vpe(envelope)
            stages["vpe"] = {"valid": vpe_result.valid, "reason": vpe_result.reason}
            if not vpe_result.valid:
                return self._decision("deny", f"VPE: {vpe_result.reason}", stages)
        else:
            stages["vpe"] = {"valid": True, "reason": "no envelope to verify"}
            # In enforce mode, missing envelope is a violation
            if self._mode == "enforce":
                return self._decision("deny", "VPE: no envelope provided (enforce mode)", stages)

        # Stage 2: EPD
        if prompt:
            epd_result = self.check_epd(prompt)
            stages["epd"] = epd_result.to_dict()
            if not epd_result.clean:
                flag_names = [f.pattern_name for f in epd_result.flags]
                reason = f"EPD: injection detected ({', '.join(flag_names)})"
                if self._mode == "enforce":
                    return self._decision("deny", reason, stages)
                return self._decision("audit_logged", reason, stages)
        else:
            stages["epd"] = {"clean": True, "reason": "no prompt to scan"}

        # Stage 3: Scope
        if envelope:
            scope_error = self.check_scope(envelope, tool_name, tool_args)
            if scope_error:
                stages["scope"] = {"valid": False, "reason": scope_error}
                if self._mode == "enforce":
                    return self._decision("deny", f"Scope: {scope_error}", stages)
                return self._decision("audit_logged", f"Scope: {scope_error}", stages)
            stages["scope"] = {"valid": True}
        else:
            stages["scope"] = {"valid": True, "reason": "no envelope"}

        return self._decision("allow", "all checks passed", stages)

    def _decision(self, verdict: str, reason: str, stages: Dict[str, Any]) -> Dict[str, Any]:
        """Build a decision dict."""
        return {
            "allowed": verdict == "allow",
            "decision": verdict,
            "reason": reason,
            "stages": stages,
        }


# ---------------------------------------------------------------------------
# Config snippet for replacing Hermes existing guard patterns
# ---------------------------------------------------------------------------

# Hermes currently has 120+ regex guard patterns for terminal command
# safety. VPE + EPD are not a replacement for terminal-level security
# scanning (TIRITH handles that). They are a replacement for the
# *prompt-level* guard patterns — the regex rules that try to detect
# "ignore previous instructions" and other prompt injection at the
# natural-language level.
#
# By enabling VPE + EPD, those 120+ prompt-level regex patterns can
# be retired because:
# 1. VPE provides cryptographic proof that a prompt came from a trusted
#    source — no injection detection needed for trusted prompts
# 2. EPD catches injection in untrusted prompts with a smaller, more
#    maintainable rule set (15 patterns vs 120+)
# 3. The regex rules that remain (in TIRITH) focus on terminal-level
#    injection (pipe-to-interpreter, homograph URLs, etc.)

_VS_EXISTING_PATTERNS = """
Replacement matrix — Hermes existing guard patterns → VPE + EPD:

| Existing Pattern Category      | Count | Replacement          | Notes                              |
|--------------------------------|-------|----------------------|------------------------------------|
| Ignore/forget instructions     | ~30   | EPD (3 patterns)    | Cryptographic trust supersedes     |
| Role-switching / DAN           | ~20   | EPD (3 patterns)    | Same approach, fewer rules         |
| Delimiter manipulation         | ~15   | EPD (2 patterns)    |                                    |
| Hidden instruction markers     | ~10   | EPD (2 patterns)    |                                    |
| Tool hallucination             | ~10   | EPD (1 pattern)     | Scope enforcement also covers this |
| System prompt extraction       | ~15   | EPD (2 patterns)    |                                    |
| Encoded payloads               | ~10   | EPD (1 pattern)     |                                    |
| Non-English jailbreaks         | ~10   | EPD (1 pattern)     |                                    |
| Terminal-level injection       | N/A   | TIRITH (unchanged)  | Not replaced — orthogonal          |
| File-write security patterns   | N/A   | security-guidance   | Not replaced — orthogonal          |
"""

# The actual migration is config-only: set `vpe_enabled: true` and
# `security.vpe.mode: enforce` in config.yaml, and the EPD + VPE
# guards take over from the prompt-level regex patterns.
