# Seal

**Verified Prompt Envelope Protocol & AI Agent Security**

Seal replaces linguistic injection detection with **cryptographic provenance verification** for AI agent prompts. Every prompt gets an Ed25519-signed envelope that proves who authorized it, what scope it has, and that it hasn't been tampered with.

---

## Why VPE?

| Problem | Current Practice | VPE Fix |
|---------|-----------------|---------|
| Prompt injection | Linguistic filtering (~91% catch) | Cryptographic provenance |
| Scope escalation | No enforcement at prompt level | Envelope carries signed scope |
| Replay attacks | No protection | Nonce + counter per envelope |
| Credential leakage | Keys in prompt context | Secrets Broker proxy |
| Audit | None / manual log review | Signed, tamper-evident audit trail |

## Components

Seal has three subsystems:

```
┌─────────────────────────────────────────────────────────────┐
│                         Seal                                 │
├─────────────┬──────────────────────┬────────────────────────┤
│  VPE Core   │  EPD Scanner         │  Secrets Broker        │
│             │                      │                        │
│ Ed25519 /   │ Regex patterns +     │ Encrypted store +      │
│ HMAC-SHA256 │ LLM fallback for     │ {SECRET:label} proxy   │
│ signing &   │ injection detection  │ for tool calls         │
│ verification│                      │                        │
└─────────────┴──────────────────────┴────────────────────────┘
```

| Component | Description | Module |
|-----------|-------------|--------|
| **VPE Core** | Ed25519 sign/verify, key generation, canonical JSON serialization | `seal.core`, `seal.vpe` |
| **EPD Scanner** | Two-pass: regex (91%+) then LLM classification for ambiguous cases | `seal.epd` |
| **Secrets Broker** | Encrypted credential store, placeholder resolution, audit log | `seal.broker`, `seal.credential_store` |
| **CLI** | `genkey`, `sign`, `verify`, `secrets`, `audit`, `status` | `seal.cli` |
| **Integrations** | Hermes MCP middleware, Division memory signing | `seal/integration/` |

## Project Status

- **Phase 1 — VPE Spec & Reference Implementation** ✓
- **Phase 2 — EPD Scanner** ✓
- **Phase 3 — Secrets Broker** ✓
- **Phase 4 — Hermes/Division Integration** ✓
- **Phase 5 — Performance & Production Hardening** (in progress)
- **Phase 6 — OWASP Submission & MCP Spec Extension** (in progress)

## Key Concepts

### VPE Envelope

A VPE envelope is a signed JSON object that wraps a prompt with cryptographic metadata:

```json
{
  "vpe_version": "1.0",
  "prompt": "search the database for customer X",
  "scope": {
    "allowed_tools": ["search"],
    "max_tokens": 4000,
    "max_cost": 0.05,
    "allowed_domains": ["*.internal.corp.com"]
  },
  "issuer": "user:rez",
  "audience": "agent:hermes-default",
  "ttl_seconds": 300,
  "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "counter": 42,
  "signature": "ed25519_sig_hex..."
}
```

### Verification Flow

1. **Schema Validation** — All required fields present and typed correctly
2. **Signature Check** — Ed25519 verification against issuer's public key
3. **Audience Check** — Envelope intended for this agent
4. **TTL Check** — Not expired
5. **Nonce Check** — Not a replay
6. **Counter Check** — Monotonically increasing
7. **Scope Enforcement** — Tool, token, cost, domain limits
8. **EPD Scan** (Optional) — Injection pattern detection
