# VPE Protocol Specification v1.0

> **Verified Prompt Envelope (VPE)** — Cryptographic provenance for AI agent prompts.
> Version: 1.0 | Status: Draft Specification

The full specification can be found in the [VPE_SPEC_v1.md](https://github.com/nousresearch/seal/blob/main/VPE_SPEC_v1.md) document in the source repository. This page provides a structured summary.

## Introduction

AI agents execute prompts from multiple sources: user input, tool returns, attached documents, memory recall, and skill pipelines. Any of these can inject unauthorized instructions. Current defenses are purely linguistic — pattern matching, prose-level "untrusted data" markers, and heuristics.

**VPE provides cryptographic provenance verification at the prompt level.**

### Design Goals

| Goal | Description |
|------|-------------|
| **Integrity** | Tamper-evident: any modification invalidates the signature |
| **Authentication** | Binds prompt to a known issuer key |
| **Replay protection** | Nonce + counter prevent re-execution of captured envelopes |
| **Expiry** | TTL bounds the window of execution |
| **Least privilege** | Scope limits tools, tokens, cost, and domains per prompt |
| **Offline-first** | No SaaS dependency for verification |
| **Backward compatible** | Unsigned prompts still work (logged as "unverified") |

## Envelope Format

A VPE envelope is a single JSON object:

```json
{
  "vpe_version": "1.0",
  "prompt": "search the database...",
  "scope": {
    "allowed_tools": ["database_search", "read_file"],
    "max_tokens": 4000,
    "max_cost": 0.05,
    "allowed_domains": ["*.internal.corp.com"]
  },
  "issuer": "user:rez",
  "audience": "agent:hermes-default",
  "doc_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ttl_seconds": 300,
  "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "counter": 42,
  "signature": "ed25519_sig_hex..."
}
```

### Field Definitions

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `vpe_version` | string | REQUIRED | Protocol version (`"1.0"`) |
| `prompt` | string | REQUIRED | The actionable instruction text (max 1M chars) |
| `scope` | object | REQUIRED | Execution constraints (tools, tokens, cost, domains) |
| `issuer` | string | REQUIRED | Identity of the signing entity |
| `audience` | string | REQUIRED | Intended recipient agent |
| `doc_sha256` | string | OPTIONAL | SHA-256 binding to source document |
| `ttl_seconds` | integer | REQUIRED | Time-to-live in seconds |
| `nonce` | string | REQUIRED | Unique replay-prevention value |
| `counter` | integer | REQUIRED | Monotonically increasing sequence number |
| `signature` | string | REQUIRED | Ed25519 signature (hex-encoded) |

## Signing Algorithm

Ed25519 is used with a deterministic canonical JSON serialization:

1. Remove the `signature` key from the envelope
2. Serialize remaining fields with keys sorted alphabetically, no whitespace
3. Sign the UTF-8 bytes with the issuer's Ed25519 private key
4. Encode the 64-byte signature as lowercase hex

**Canonical field order for signing:**

```
vpe_version → prompt → scope (sorted keys) → issuer → audience
→ doc_sha256 → ttl_seconds → nonce → counter
```

## Verification Rules

Verification proceeds in this order:

1. **Schema Validation** — All REQUIRED fields present and correctly typed
2. **Signature Check** — Ed25519 verification; `UNKNOWN_ISSUER` or `INVALID_SIGNATURE`
3. **Audience Check** — Envelope intended for this agent; `WRONG_AUDIENCE`
4. **TTL/Expiry Check** — Not expired; `EXPIRED`
5. **Nonce Replay Check** — Nonce not previously used; `NONCE_REPLAY`
6. **Counter Monotonic Check** — Counter strictly increasing; `COUNTER_NON_MONOTONIC`
7. **Scope Enforcement** — Tool, token, cost, domain limits; various `*_NOT_ALLOWED` codes
8. **EPD Scan** (Optional) — Injection pattern detection; `EPD_FLAGGED`

## Error Codes

| Code | HTTP-like | Description |
|------|-----------|-------------|
| `OK` | 200 | Verification passed |
| `MALFORMED_ENVELOPE` | 400 | JSON parse failure or missing fields |
| `MALFORMED_SIGNATURE` | 400 | Invalid signature format |
| `UNKNOWN_ISSUER` | 401 | Issuer public key not found |
| `INVALID_SIGNATURE` | 403 | Ed25519 verification failed |
| `WRONG_AUDIENCE` | 403 | Intended for a different agent |
| `EXPIRED` | 410 | TTL has elapsed |
| `NONCE_REPLAY` | 409 | Nonce already used |
| `COUNTER_NON_MONOTONIC` | 409 | Counter not increasing |
| `TOOL_NOT_ALLOWED` | 403 | Tool not in allowed_tools |
| `TOKEN_LIMIT_EXCEEDED` | 403 | Exceeds max_tokens |
| `COST_LIMIT_EXCEEDED` | 402 | Exceeds max_cost |
| `DOMAIN_NOT_ALLOWED` | 403 | Domain not in allowed_domains |
| `EPD_FLAGGED` | 400 | Flagged by injection detector |
| `INTERNAL_ERROR` | 500 | Unexpected verifier failure |

## HMAC-SHA256 Alternative

For internal/low-security contexts, Seal provides an HMAC-SHA256 signing path:

| Dimension | Ed25519 | HMAC-SHA256 |
|-----------|---------|-------------|
| Speed | Asymmetric | 10-100x faster |
| Signature size | 64 bytes | 32 bytes |
| Key management | Key pair | Shared secret |
| Non-repudiation | Yes | No |
| Quantum resistance | None (Shor's) | Stronger |

## JSON Schema

See [Appendix A in the full spec](https://github.com/nousresearch/seal/blob/main/VPE_SPEC_v1.md#appendix-a-json-schema) for the canonical JSON Schema.
