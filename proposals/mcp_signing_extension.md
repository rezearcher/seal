# MCP Spec Extension: Optional Signing Layer

> **Status:** Draft proposal
> **Author:** Hermes Agent / Seal Project
> **Date:** 2026-06-06
> **Target:** Model Context Protocol (MCP) specification
> **Extension name:** `vpe-signing`

---

## Abstract

The **Model Context Protocol (MCP)** defines a standardized protocol for
communication between AI agents and external tools, resources, and
prompts. The current spec has no mechanism for:

- **Authentication** — proving that a prompt originates from a known entity
- **Authorization** — bounding what operations a prompt may perform
- **Replay protection** — preventing the same prompt from being executed
  multiple times
- **Audit trail** — verifying that a prompt's content has not been
  tampered with since issuance

This proposal adds an **optional signing layer** to the MCP specification
using the **Verified Prompt Envelope (VPE)** protocol — an Ed25519-based
signing scheme that wraps MCP messages with cryptographic provenance.

---

## Motivation

MCP is increasingly used in security-sensitive contexts:

- **CI/CD pipelines** — agents deploying infrastructure changes
- **Financial trading** — agents executing trades via MCP tools
- **Healthcare** — agents accessing patient records via MCP resources
- **Multi-agent systems** — agents delegating tasks to other agents

In all these scenarios, the agent needs assurance that the prompt it
received:

1. Actually came from the stated issuer (not an attacker)
2. Has not been modified in transit (tamper evidence)
3. Was intended for this specific agent (audience binding)
4. Is still within its validity window (freshness)
5. Cannot be replayed to perform the same action twice

---

## Design

### Extension Point

The signing layer extends MCP at the **message envelope** level. Every
MCP message (prompts, tool calls, resource requests) can carry an optional
`vpe` field in its metadata:

```json
{
  "method": "tools/call",
  "params": {
    "name": "database_query",
    "arguments": {
      "query": "SELECT * FROM users"
    },
    "_meta": {
      "vpe": {
        "version": "1.0",
        "envelope": { ... }
      }
    }
  }
}
```

### VPE Envelope (inside `_meta.vpe.envelope`)

The signed envelope contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vpe_version` | string | ✓ | Protocol version ("1.0") |
| `prompt` | string | ✓ | The signed instruction/prompt content |
| `scope` | object | ✗ | Capability restrictions (see below) |
| `issuer` | string | ✓ | Who authorized this (e.g. "user:alice") |
| `audience` | string | ✓ | Which agent should execute (e.g. "agent:hermes-production") |
| `doc_sha256` | string | ✗ | SHA-256 of source document the prompt binds to |
| `ttl_seconds` | number | ✗ | Seconds from `issued_at` until expiry |
| `issued_at` | number | ✓ | Unix timestamp of issuance |
| `nonce` | string | ✓ | Unique value for replay prevention |
| `counter` | number | ✗ | Monotonic counter for prompt ordering |
| `public_key` | string | ✗ | Signer's public key (hex) for self-contained verification |
| `signature` | string | ✓ | Ed25519 signature (hex) over all other fields |

### Scope Object

| Field | Type | Description |
|-------|------|-------------|
| `allowed_tools` | [string] | Tool names the prompt is authorized to call |
| `max_tokens` | number | Maximum tokens the prompt may consume |
| `max_cost` | number | Maximum cost (in USD or credits) |
| `allowed_domains` | [string] | URL domain allowlist for web/network tools |

### Signature

The signature is computed over the **canonical JSON** representation of
all fields EXCEPT `signature` itself:

```
to_sign = json.dumps(envelope_without_signature, separators=(",", ":"), sort_keys=True)
signature = ed25519.sign(private_key, to_sign).hex()
```

Canonical JSON (sorted keys, no whitespace) is mandatory — both signer
and verifier must produce identical bytes.

---

## Verification Flow

### Server-Side (Agent Receiving a Signed MCP Message)

```
Receive MCP message with _meta.vpe.envelope
  │
  ├─ Is VPE present? ── No ──→ Process normally (unsigned)
  │                             (log as unverified)
  │
  ├─ Has VPE? ── Yes ──→ Verify:
  │     ├─ 1. Parse envelope JSON
  │     ├─ 2. Check required fields present
  │     ├─ 3. Check vpe_version == supported version
  │     ├─ 4. Check TTL: (now - issued_at) <= ttl_seconds
  │     ├─ 5. Extract public key (from envelope or local store)
  │     ├─ 6. Check issuer in trusted_issuers list
  │     ├─ 7. Verify Ed25519 signature
  │     ├─ 8. Check nonce not replayed (seen_nonces set)
  │     ├─ 9. Check counter monotonic (per issuer+audience)
  │     ├─ 10. Check scope: tool/method in allowed list
  │     │
  │     └─ All pass? ── Yes ──→ Process (verified)
  │                     No  ──→ Reject with error:
  │                              { "error": "vpe_verification_failed",
  │                                "reason": "signature mismatch" }
```

### Client-Side (Issuer Signing a Message)

```
Compose MCP message
  │
  ├─ Serialize prompt/instruction
  ├─ Choose scope (optional, but recommended)
  ├─ Set issuer + audience
  ├─ Generate nonce (crypto-random 16+ bytes, hex)
  ├─ Increment counter
  ├─ Serialize to canonical JSON (sorted keys, no extra whitespace)
  ├─ Sign with Ed25519 private key
  ├─ Embed `_meta.vpe.envelope` in the MCP message
  └─ Send signed message
```

---

## Error Handling

### Verification Errors

| Error Code | HTTP Status | Description |
|-----------|-------------|-------------|
| `vpe_missing_required` | 400 | Missing required field in envelope |
| `vpe_version_mismatch` | 400 | Unsupported vpe_version |
| `vpe_expired` | 401 | Envelope TTL has expired |
| `vpe_signature_invalid` | 403 | Ed25519 signature does not match |
| `vpe_nonce_replay` | 409 | Nonce has already been used |
| `vpe_counter_non_monotonic` | 409 | Counter <= last seen value |
| `vpe_scope_violation` | 403 | Requested operation exceeds scope |
| `vpe_audience_mismatch` | 403 | Audience does not match this agent |
| `vpe_issuer_unknown` | 403 | Issuer not in trusted issuers list |
| `vpe_internal_error` | 500 | Verification pipeline failure |

When a VPE verification fails, the server returns the error code and a
human-readable `reason` field. The caller may choose to retry with a
freshly signed message (e.g., TTL expiry) or fall back to unsigned
processing.

### Graceful Degradation

Implementations SHOULD support three modes:

1. **Pass-through** — ignore VPE fields entirely (no change to existing
   MCP behavior)
2. **Audit** — verify if present, log failures, process anyway
   (recommended for migration)
3. **Enforce** — verify if present; fail with error on verification
   failure; reject unsigned messages if policy requires

---

## Key Exchange

### In-Band (Self-Contained)

The envelope can carry the signer's public key in the `public_key` field.
This allows verification without a separate key exchange, but requires
the verifier to trust the first-seen key (TOFU — Trust On First Use).

### Out-of-Band (Recommended for Production)

Public keys are distributed via a separate secure channel:

- Fixed in agent/server configuration
- Published via Web Key Directory (WKD)
- Distributed as part of a secrets manager (Vault, AWS Secrets Manager)
- Verified via Key Transparency / Certificate Transparency

A `kid` (Key ID) field may be added to the envelope to reference a
pre-shared key without transmitting it in-band.

### Key Rotation

- Agents should accept envelopes signed with the **current** or the
  **previous** key during rotation windows
- Grace period: at minimum 2× the maximum TTL
- Revocation: remove the key from the trusted set; previously signed
  envelopes using that key will fail verification

---

## MCP spec changes

### JSON Schema Extension

Add to the MCP message schema:

```json
{
  "VPEEnvelope": {
    "type": "object",
    "required": ["vpe_version", "prompt", "issuer", "audience", "nonce", "signature"],
    "properties": {
      "vpe_version": { "type": "string", "pattern": "^\\d+\\.\\d+$" },
      "prompt": { "type": "string" },
      "scope": {
        "type": "object",
        "properties": {
          "allowed_tools": { "type": "array", "items": { "type": "string" } },
          "max_tokens": { "type": "integer", "minimum": 0 },
          "max_cost": { "type": "number", "minimum": 0 },
          "allowed_domains": { "type": "array", "items": { "type": "string", "format": "hostname" } }
        }
      },
      "issuer": { "type": "string" },
      "audience": { "type": "string" },
      "doc_sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
      "ttl_seconds": { "type": "integer", "minimum": 0 },
      "issued_at": { "type": "integer", "minimum": 0 },
      "nonce": { "type": "string", "minLength": 8 },
      "counter": { "type": "integer", "minimum": 0 },
      "public_key": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
      "signature": { "type": "string", "pattern": "^[a-f0-9]{128}$" }
    }
  }
}
```

### Message Metadata Additions

The `_meta` field on MCP messages gains an optional `vpe` sub-field:

```json
{
  "_meta": {
    "vpe": {
      "version": "1.0",
      "envelope": { ... }
    }
  }
}
```

### Capability Negotiation

MCP servers SHOULD advertise VPE support via capabilities:

```json
{
  "capabilities": {
    "experimental": {
      "vpe": {
        "version": "1.0",
        "mode": "enforce",
        "public_keys": ["<hex>"]
      }
    }
  }
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Attacker replays a captured signed prompt | Nonce (replay detection) + counter (ordering) |
| Attacker modifies prompt content | Ed25519 signature (tamper evidence) |
| Attacker forges a prompt without the private key | Ed25519 existential unforgeability |
| Attacker uses an expired prompt | TTL expiry check |
| Attacker redirects prompt to a different agent | Audience check |
| Attacker escalates from authorized tool to unauthorized tool | Scope enforcement |
| Attacker compromises the signing key | Key rotation + revocation |
| Attacker reorders prompts to change semantics | Monotonic counter |
| Attacker replays across agent restarts | Persistent nonce store (optional) |

### Limitations

- **Not a content filter** — VPE authenticates, it does not sanitize.
  Combined with EPD (Embedded Prompt Detection) for content analysis.
- **Key management is hard** — lost or compromised keys bypass all VPE
  security. Production deployments MUST use HSM-backed keys.
- **Does not protect against in-model attacks** — if the model itself
  is compromised, VPE cannot help.
- **Adds latency** — signing and verification add ~1ms each with native
  Ed25519 implementations.

---

## Reference Implementation

A complete reference implementation is available as part of the **Seal**
project:

- **VPE Core** (sign + verify): `seal/vpe.py` — Ed25519 signing and
  verification with full check pipeline
- **Hermes MCP middleware**: `seal/integration/hermes_vpe_middleware.py` —
  plugin that wraps MCP tool calls with VPE verification
- **Division memory signing**: `seal/integration/division_vpe_signer.py` —
  signs MCP memory_remember episodes for audit trail
- **EPD scanner**: `seal/epd.py` — two-pass injection detection
  (regex + LLM) for unsigned prompts
- **Secrets Broker**: `seal/secrets_broker.py` — credential proxy that
  integrates with VPE scope

Path: ~/projects/seal/

---

## Appendix: Example Exchange

### Client Signs a Tool Call

```json
{
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/etc/config.json"
    },
    "_meta": {
      "vpe": {
        "version": "1.0",
        "envelope": {
          "vpe_version": "1.0",
          "prompt": "read the configuration file",
          "scope": {
            "allowed_tools": ["read_file", "search_files"],
            "allowed_domains": ["*.internal.corp.com"]
          },
          "issuer": "user:alice",
          "audience": "agent:hermes-production",
          "doc_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "ttl_seconds": 300,
          "issued_at": 1717664400,
          "nonce": "a1b2c3d4e5f6g7h8",
          "counter": 42,
          "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
      }
    }
  }
}
```

### Server Verification Response (Failure)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "vpe_scope_violation",
    "data": {
      "reason": "Tool 'write_file' not in allowed_tools: ['read_file', 'search_files']",
      "vpe_verification": {
        "passed": false,
        "stages": {
          "signature": true,
          "expiry": true,
          "nonce": true,
          "scope": false
        }
      }
    }
  }
}
```

---

## References

1. MCP Specification: https://spec.modelcontextprotocol.io/
2. Verified Prompt Envelope Protocol: ~/projects/seal/ARCHITECTURE.md
3. Ed25519 (RFC 8032): https://datatracker.ietf.org/doc/html/rfc8032
4. Seal Reference Implementation: ~/projects/seal/
5. OWASP VPE Proposal: ~/projects/seal/proposals/owasp_agentic_security_vpe.md
