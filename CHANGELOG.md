# Changelog

All notable changes to Seal (VPE) are documented here.

## Unreleased

### Fixed

- **Division VPE signer no longer swallows canonicalization errors** (L-010, kanban
  `t_3035a8b3`). `DivisionVPESigner._record_audit` previously wrapped envelope hashing
  in a blanket `except Exception` that silently fell back to a nonce-derived hash.
  The handler is now narrowed to `(TypeError, ValueError, KeyError)`; on failure it
  emits a `logger.warning`, prefixes the fallback identifier with `degraded:` so it
  cannot be mistaken for a real SHA-256 envelope hash, and stamps the audit record
  `reason="hash_computation_failed"`. The degraded-hash fallback is **retained and
  flagged**, not removed — it still produces an identifier for audit-record lookup.
  Gap: the failure branch has no dedicated test (`seal/integration/division_vpe_signer.py:217-234`).

## 0.1.0 — 2026-06-07

### Added

- **VPE Core** — Ed25519 signing and verification with canonical JSON envelopes
- **HMAC-SHA256** — Alternative signing path for internal/low-security contexts
- **Multi-signature** — Aggregate multiple signers into a single envelope
- **Key generation** — Ed25519 key pair generation (`seal genkey`)
- **CLI** — `seal sign`, `seal verify`, `seal genkey`, `seal secrets`, `seal audit`
- **EPD Scanner** — Two-pass prompt injection detection (regex + LLM fallback)
- **Secrets Broker** — Encrypted credential store with placeholder resolution
- **Nonce & Counter** — Replay protection and prompt ordering
- **MCP Integrations** — Hermes middleware and Division memory signer
- **Rollback support** — Versioned state recovery for stores
