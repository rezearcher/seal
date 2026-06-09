# Changelog

All notable changes to Seal (VPE) are documented here.

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
