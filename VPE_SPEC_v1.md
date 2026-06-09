# VPE Protocol Specification v1.0

> **Verified Prompt Envelope (VPE)** — Cryptographic provenance for AI agent prompts
> **Version:** 1.0
> **Status:** Draft Specification
> **Author:** Seal Project
> **Last Updated:** 2026-06-06

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [VPE Envelope Format](#3-vpe-envelope-format)
4. [Field Definitions](#4-field-definitions)
5. [Ed25519 Signing Algorithm](#5-ed25519-signing-algorithm)
6. [Verification Rules](#6-verification-rules)
7. [Error Codes and Handling](#7-error-codes-and-handling)
8. [Examples](#8-examples)
9. [Security Considerations](#9-security-considerations)
10. [Compatibility and Fallback](#10-compatibility-and-fallback)
11. [Appendix A: JSON Schema](#appendix-a-json-schema)
12. [Appendix B: Test Vectors](#appendix-b-test-vectors)

---

## 1. Introduction

### 1.1 Problem Statement

AI agents execute prompts from multiple sources: user input, tool returns, attached documents, memory recall, and skill pipelines. Any of these can inject unauthorized instructions. Current defenses are purely linguistic — pattern matching, prose-level "untrusted data" markers, and heuristics — which are bypassed by semantic obfuscation, multi-step injection chains, and indirect prompt manipulation through tool outputs.

No existing product, paper, or standard provides **cryptographic provenance verification** at the prompt level.

### 1.2 VPE Overview

The Verified Prompt Envelope (VPE) protocol cryptographically binds a prompt instruction to its issuer's identity, execution scope, and usage constraints. Each prompt is wrapped in a signed JSON envelope with Ed25519 signature. The receiving agent verifies the signature, checks expiration and replay protections, and enforces the declared scope before executing the prompt.

### 1.3 Design Goals

| Goal | Description |
|------|-------------|
| **Integrity** | Tamper-evident: any modification invalidates the signature |
| **Authentication** | Binds prompt to a known issuer key |
| **Replay protection** | Nonce + counter prevent re-execution of captured envelopes |
| **Expiry** | TTL bounds the window of execution |
| **Least privilege** | Scope limits tools, tokens, cost, and domains per prompt |
| **Offline-first** | No SaaS dependency for verification |
| **Backward compatible** | Unsigned prompts still work (logged as "unverified") |

---

## 2. Conventions and Terminology

### 2.1 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

### 2.2 Terminology

| Term | Definition |
|------|------------|
| **Envelope** | The complete signed JSON object containing a prompt and all metadata |
| **Issuer** | Entity that signs the envelope (user, service, workflow step) |
| **Audience** | Agent or agent profile intended to execute the prompt |
| **Scope** | Declared constraints on execution (tools, tokens, cost, domains) |
| **Nonce** | Random value ensuring uniqueness of each envelope |
| **Counter** | Monotonically increasing integer for ordered prompt sequencing |
| **EPD** | Embedded Prompt Detection — pre-LLM scanner within the verification gate |
| **Verifier** | The agent or middleware that validates an envelope before execution |

### 2.3 Encoding

- All string values are UTF-8 encoded JSON strings unless noted otherwise.
- Binary values (signatures, hashes) are encoded as lowercase hexadecimal strings.
- Timestamps are Unix epoch seconds (integer).

---

## 3. VPE Envelope Format

### 3.1 Top-Level Structure

A VPE envelope is a single JSON object with the following top-level keys:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `vpe_version` | string | REQUIRED | Protocol version identifier |
| `prompt` | string | REQUIRED | The actionable instruction text |
| `scope` | object | REQUIRED | Execution constraints |
| `issuer` | string | REQUIRED | Identity of the signing entity |
| `audience` | string | REQUIRED | Intended recipient agent |
| `doc_sha256` | string | OPTIONAL | SHA-256 binding to source document |
| `ttl_seconds` | integer | REQUIRED | Time-to-live in seconds from issuance |
| `nonce` | string | REQUIRED | Unique replay-prevention value |
| `counter` | integer | REQUIRED | Monotonically increasing sequence number |
| `signature` | string | REQUIRED | Ed25519 signature (hex-encoded) |

### 3.2 JSON Example

```json
{
  "vpe_version": "1.0",
  "prompt": "search the database for customer records matching account_id 4592",
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
  "signature": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
}
```

---

## 4. Field Definitions

### 4.1 `vpe_version` (string, REQUIRED)

The protocol version identifier. For this specification, the value MUST be `"1.0"`.

Format: `MAJOR.MINOR` where MAJOR indicates breaking changes and MINOR indicates backward-compatible additions.

- Implementations MUST reject envelopes with a `vpe_version` MAJOR they do not support.
- Implementations MAY accept envelopes with a higher MINOR version if unknown fields are tolerated.

### 4.2 `prompt` (string, REQUIRED)

The actionable instruction the agent SHOULD execute. This is the core payload of the envelope.

Constraints:
- MUST be a valid UTF-8 string.
- MUST NOT exceed 1,000,000 (1M) characters.
- SHOULD be human-readable and self-contained.
- MAY be empty (semantically: a no-op heartbeat or probe).

### 4.3 `scope` (object, REQUIRED)

The scope object declares execution constraints as a least-privilege capability set. The receiving agent MUST NOT exceed the bounds declared in `scope`.

| Sub-field | Type | Required | Description |
|-----------|------|----------|-------------|
| `allowed_tools` | array of strings | REQUIRED | Tool names the agent may use (empty array = no tools, `["*"]` = all tools) |
| `max_tokens` | integer | REQUIRED | Maximum output tokens the agent may generate |
| `max_cost` | number | REQUIRED | Maximum monetary cost the agent may incur (in USD) |
| `allowed_domains` | array of strings | REQUIRED | Domain patterns for network access (empty = no network, `["*"]` = all domains) |

#### 4.3.1 `allowed_tools`

An array of tool name strings. Wildcard patterns:
- `["*"]` — all tools allowed.
- `["database_*", "file_read"]` — glob-prefix matching (implementation-defined; RECOMMENDED: `fnmatch`-style).
- `[]` — no tools allowed (observation-only prompt).

The verifier MUST reject execution if the requested tool is not in `allowed_tools`.

#### 4.3.2 `max_tokens`

Maximum number of output tokens the agent may generate in response to this prompt. The verifier SHOULD enforce this as a hard cap on generation.

- `0` — no generation allowed.
- Values below `1` SHOULD be treated as `0`.

#### 4.3.3 `max_cost`

Maximum monetary cost in USD the agent may incur executing this prompt, including API calls, compute, and third-party services. The verifier SHOULD track cumulative cost and halt execution if exceeded.

- `0.0` — no cost allowed (zero-cost execution only).
- Negative values MUST be rejected as invalid.

#### 4.3.4 `allowed_domains`

An array of domain glob patterns for network-accessible tools (HTTP, API calls, web scraping, etc.).

- `["*"]` — all domains allowed.
- `["*.internal.corp.com"]` — only subdomains of `internal.corp.com`.
- `["api.stripe.com", "api.github.com"]` — specific domains only.
- `[]` — no network access (air-gapped execution).

Matching SHOULD use case-insensitive suffix/glob matching. The verifier MUST reject requests to domains not matching any pattern.

### 4.4 `issuer` (string, REQUIRED)

The identity of the entity that signed the envelope. Format is implementation-defined but SHOULD follow a colon-delimited scheme:

- `"user:rez"` — a human user identified by username
- `"service:ci-pipeline"` — an automated service
- `"workflow:order-processing/v3"` — a workflow step
- `"key:abc123def456"` — a raw key identifier

The verifier uses `issuer` to look up the corresponding Ed25519 public key for signature verification.

### 4.5 `audience` (string, REQUIRED)

The intended recipient agent or agent profile. The verifier MUST check that its own identity matches `audience`.

Format:
- `"agent:hermes-default"` — agent profile name
- `"agent:*"` — any agent (wildcard, use with caution)
- `"agent:division"` — specific agent name

If `audience` does not match the verifier's identity (and the wildcard `"agent:*"` is not used), the envelope MUST be rejected.

### 4.6 `doc_sha256` (string, OPTIONAL)

SHA-256 hash of the source document that originated the prompt, hex-encoded (64 hex characters). This binds the prompt to a specific document, preventing the same signed envelope from being applied to different source material.

- When present, the verifier SHOULD compute the SHA-256 of the source document (if available) and verify it matches.
- When absent, no document binding is enforced.
- MUST be exactly 64 lowercase hex characters when present.

### 4.7 `ttl_seconds` (integer, REQUIRED)

Time-to-live in seconds, measured from the moment of issuance. The verifier calculates expiry as:

```
expiry_time = issuance_time_known + ttl_seconds
```

If `issuance_time_known` is not available (e.g., no trusted clock at issuance), the verifier SHOULD use the envelope's first-seen timestamp as a lower bound.

- MUST be a positive integer.
- Values less than `1` SHOULD be rejected.
- RECOMMENDED range: `60` (1 minute) to `86400` (24 hours).
- After expiry, the verifier MUST reject the envelope with error `EXPIRED`.

### 4.8 `nonce` (string, REQUIRED)

A cryptographically random value that ensures the uniqueness of each envelope. The verifier MUST track seen nonces for the duration of their TTL and reject replayed envelopes.

Requirements:
- MUST be generated using a cryptographically secure random number generator (CSPRNG).
- RECOMMENDED length: at least 16 bytes (32 hex chars), encoded as lowercase hex.
- RECOMMENDED format: UUIDv4 (e.g., `"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`).
- The nonce plus `issuer` forms the composite uniqueness key for replay detection.

### 4.9 `counter` (integer, REQUIRED)

A monotonically increasing integer that provides ordered sequencing of prompts from a single issuer. The verifier MUST track the last-seen counter per issuer and reject non-monotonic values.

- MUST be a non-negative integer.
- MUST be strictly greater than the last accepted counter from the same `issuer`.
- The first envelope from an issuer SHOULD start at `0` or `1`.
- The counter plus `issuer` forms the composite key for monotonicity tracking.
- If a higher counter is accepted, the verifier MUST NOT subsequently accept a lower counter even if the nonce differs.

### 4.10 `signature` (string, REQUIRED)

The Ed25519 signature over the canonical signing payload (see [Section 5](#5-ed25519-signing-algorithm)), hex-encoded.

- MUST be exactly 128 lowercase hex characters (64 bytes raw).
- MUST be the last field in the serialized envelope (not required by protocol, but strongly RECOMMENDED for readability).

---

## 5. Ed25519 Signing Algorithm

### 5.1 Key Generation

Ed25519 key pairs MUST be generated using a cryptographically secure random number generator.

- Private key: 32 random bytes.
- Public key: 32 bytes (derived from private key via Curve25519 scalar multiplication).
- RECOMMENDED libraries: `cryptography` (Python), `libsodium`/`NaCl` (C/Rust), `ed25519-donna` (embedded).

### 5.2 Canonical Signing Payload

**Only fields other than `signature` are signed.** The signature field is excluded from the signing payload because it is added after signing.

The canonical payload is constructed by serializing the envelope *without* the `signature` field, keys sorted alphabetically, no whitespace, no trailing newline.

**Payload construction procedure:**

1. Remove the `signature` key from the envelope.
2. Serialize the remaining object to JSON with:
   - Keys sorted in alphabetical order.
   - No whitespace (compact serialization).
   - No trailing newline.
3. Encode the resulting JSON string as UTF-8 bytes.
4. Sign the bytes with the issuer's Ed25519 private key.

**Sorted key order for signing:**

```
allowed_domains  (inside scope)
allowed_tools    (inside scope)
audience
counter
doc_sha256       (included if present, omitted if absent)
issuer
max_cost         (inside scope)
max_tokens       (inside scope)
nonce
prompt
scope
ttl_seconds
vpe_version
```

### 5.3 Signature Algorithm

- Algorithm: Ed25519 (EdDSA with Curve25519)
- Hash: SHA-512 (internal to Ed25519)
- Signature output: 64 bytes
- Encoding: lowercase hex (128 characters)

### 5.4 Signing Procedure

```
Input:  envelope (dict), private_key (32 bytes)
Output: signed_envelope (dict with signature field populated)

1. Validate envelope fields (no signature yet).
2. Construct canonical payload from envelope (Section 5.2).
3. Sign payload bytes with Ed25519 private key → 64-byte raw signature.
4. Encode signature as lowercase hex string.
5. Set envelope["signature"] = hex_encoded_signature.
6. Return envelope.
```

### 5.5 Verification Procedure

```
Input:  signed_envelope (dict), expected_public_key (32 bytes)
Output: {valid: bool, reason: str}

1. Check that all REQUIRED fields are present and valid types.
   If missing/malformed → {valid: false, reason: "MALFORMED_ENVELOPE"}
2. Extract signature field (hex string).
3. Decode signature from hex to 64 bytes. If decode fails → MALFORMED_SIGNATURE.
4. Remove signature field from envelope.
5. Construct canonical payload (Section 5.2).
6. Verify Ed25519 signature(payload, signature_bytes, public_key).
   If verification fails → {valid: false, reason: "INVALID_SIGNATURE"}
7. Re-attach signature to envelope (for downstream processing).
8. Run verification rules (Section 6).
9. If all checks pass → {valid: true, reason: "OK"}
```

---

## 6. Verification Rules

Verification proceeds in the order listed below. If any check fails, the verifier MUST reject the envelope immediately and SHOULD log the failure with the corresponding error code.

### 6.1 Schema Validation

Verify that all REQUIRED fields are present and match their expected types (Section 4). Reject with `MALFORMED_ENVELOPE` and a descriptive sub-reason if any field is missing, null, or of the wrong type.

### 6.2 Signature Check

Perform Ed25519 signature verification as described in Section 5.5.

- Look up the public key corresponding to `issuer`.
- If `issuer` is unknown → reject with `UNKNOWN_ISSUER`.
- If signature verification fails → reject with `INVALID_SIGNATURE`.

### 6.3 Audience Check

Compare `audience` against the verifier's own identity.

- If `audience == "agent:*"` → allowed (wildcard).
- If `audience` matches the verifier's identity → allowed.
- Otherwise → reject with `WRONG_AUDIENCE`.

### 6.4 TTL / Expiry Check

```
if current_time > issued_at_time + ttl_seconds:
    reject with EXPIRED
```

If `issued_at_time` is not known:
- Use the verifier's first-seen timestamp as `issued_at_time`.
- This is a conservative estimate: the envelope cannot be older than when it was first observed.

### 6.5 Nonce Replay Check

Check the composite key `(issuer, nonce)` against the verifier's replay-detection store.

- If `(issuer, nonce)` has been seen before and is still within TTL → reject with `NONCE_REPLAY`.
- Otherwise → record `(issuer, nonce)` in the replay-detection store.
- The replay-detection store SHOULD expire entries after their TTL window passes.

Implementation note: a Bloom filter or bounded LRU cache with TTL-aware eviction is RECOMMENDED for efficiently tracking nonces at scale.

### 6.6 Counter Monotonic Check

Check the composite key `(issuer, counter)` against the verifier's monotonicity store.

- Let `last_counter` be the highest counter previously accepted from this `issuer`.
- If `counter <= last_counter` → reject with `COUNTER_NON_MONOTONIC`.
- Otherwise → update `last_counter = counter`.

The counter check detects skipped or reordered prompts. It is independent of the nonce check: a new nonce with an old counter is still rejected.

### 6.7 Scope Enforcement

Before each tool call or generation, the verifier MUST check:

1. **Tool scope:** Is the requested tool in `scope.allowed_tools`? If no → reject with `TOOL_NOT_ALLOWED`.
2. **Token scope:** Will the generation exceed `scope.max_tokens`? If yes → reject with `TOKEN_LIMIT_EXCEEDED`.
3. **Cost scope:** Will the operation exceed `scope.max_cost`? If yes → reject with `COST_LIMIT_EXCEEDED`.
4. **Domain scope:** Does the target domain match `scope.allowed_domains`? If no → reject with `DOMAIN_NOT_ALLOWED`.

Scope enforcement is dynamic — it applies throughout execution, not just at initial verification.

### 6.8 EPD Scan (Optional)

If Embedded Prompt Detection (EPD) is active, the verifier SHOULD run EPD on the `prompt` field before allowing execution. If EPD flags the prompt as potentially injected:

- The verifier MAY reject with `EPD_FLAGGED`.
- The verifier MAY allow execution with a warning logged (tolerant mode).
- The verifier MAY escalate to an LLM classification pass.

This check is OPTIONAL in v1.0 — agents without EPD skip it silently.

---

## 7. Error Codes and Handling

### 7.1 Error Code Table

| Code | HTTP-like Status | Description | Recovery |
|------|-----------------|-------------|----------|
| `OK` | 200 | Verification passed | Execute prompt |
| `MALFORMED_ENVELOPE` | 400 | JSON parse failure, missing fields, or type errors | Reject; issuer should re-sign corrected envelope |
| `MALFORMED_SIGNATURE` | 400 | Signature field is not valid hex or wrong length | Reject; issuer should re-sign |
| `UNKNOWN_ISSUER` | 401 | Issuer public key not found | Reject; register issuer's public key |
| `INVALID_SIGNATURE` | 403 | Ed25519 verification failed | Reject; envelope was tampered with or signed by wrong key |
| `WRONG_AUDIENCE` | 403 | Envelope intended for a different agent | Reject; re-issue with correct audience |
| `EXPIRED` | 410 | TTL has elapsed | Reject; issuer should re-issue with fresh TTL |
| `NONCE_REPLAY` | 409 | Nonce already used within TTL | Reject; issuer must generate new nonce |
| `COUNTER_NON_MONOTONIC` | 409 | Counter not strictly increasing | Reject; check ordering, re-issue with correct counter |
| `TOOL_NOT_ALLOWED` | 403 | Tool not in `allowed_tools` | Reject; widen scope or use different tool |
| `TOKEN_LIMIT_EXCEEDED` | 403 | Generation exceeds `max_tokens` | Reject; increase scope or shorten response |
| `COST_LIMIT_EXCEEDED` | 402 | Cumulative cost exceeds `max_cost` | Reject; increase scope or reduce cost |
| `DOMAIN_NOT_ALLOWED` | 403 | Target domain not in `allowed_domains` | Reject; widen scope or use different domain |
| `EPD_FLAGGED` | 400 | Prompt flagged by injection detector | Reject; revise prompt or override via signing authority |
| `INTERNAL_ERROR` | 500 | Unexpected verifier failure | Retry; log for operator review |

### 7.2 Error Response Format

Verifiers MUST return errors in the following structured format:

```json
{
  "valid": false,
  "error": {
    "code": "INVALID_SIGNATURE",
    "message": "Ed25519 signature verification failed for envelope issued by user:rez",
    "details": {
      "issuer": "user:rez",
      "audience": "agent:hermes-default",
      "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "counter": 42,
      "reason": "Signature does not match canonical payload under public key abc...def"
    }
  }
}
```

---

## 8. Examples

### 8.1 Valid Envelope

```json
{
  "vpe_version": "1.0",
  "prompt": "list all files in /home/rez/projects",
  "scope": {
    "allowed_tools": ["read_file", "list_directory"],
    "max_tokens": 1000,
    "max_cost": 0.01,
    "allowed_domains": []
  },
  "issuer": "user:alice",
  "audience": "agent:hermes-default",
  "doc_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ttl_seconds": 300,
  "nonce": "c0a1b2c3-d4e5-6789-abcd-ef0123456789",
  "counter": 1,
  "signature": "<valid_ed25519_signature_hex>"
}
```

**Expected verification result:** `{valid: true, reason: "OK"}`

**Execution allowed:** yes, within scope (read-only file tools, no network).

### 8.2 Expired Envelope

```json
{
  "vpe_version": "1.0",
  "prompt": "execute order for 100 shares of AAPL",
  "scope": {
    "allowed_tools": ["place_order", "read_market_data"],
    "max_tokens": 500,
    "max_cost": 0.10,
    "allowed_domains": ["api.tastytrade.com"]
  },
  "issuer": "user:bob",
  "audience": "agent:trading-bot",
  "ttl_seconds": 60,
  "nonce": "deadbeef-cafe-babe-face-8642997924581",
  "counter": 7,
  "signature": "<valid_but_expired_signature>"
}
```

**Expected verification result:** `{valid: false, error: {code: "EXPIRED", ...}}`

**Reason:** More than 60 seconds have elapsed since issuance. The signature is valid but the envelope is stale. Bob must re-issue with a fresh TTL window and new nonce.

### 8.3 Tampered Envelope

Original valid envelope intercepted and modified in transit. Attacker changes `prompt` field after seeing the signed envelope:

```json
{
  "vpe_version": "1.0",
  "prompt": "delete all files in /home/rez/projects",
  "scope": {
    "allowed_tools": ["read_file", "list_directory"],
    "max_tokens": 1000,
    "max_cost": 0.01,
    "allowed_domains": []
  },
  "issuer": "user:alice",
  "audience": "agent:hermes-default",
  "doc_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ttl_seconds": 300,
  "nonce": "c0a1b2c3-d4e5-6789-abcd-ef0123456789",
  "counter": 1,
  "signature": "<signature_from_original_envelope>"
}
```

**Expected verification result:** `{valid: false, error: {code: "INVALID_SIGNATURE", ...}}`

**Reason:** The `prompt` field was changed from "list all files" to "delete all files". The signature was computed over the original `prompt`, so verification fails. The tamper is detected regardless of whether the attacker changed one character or the entire field.

### 8.4 Replayed Envelope

An attacker captures a valid envelope and attempts to re-submit it:

```json
{
  "vpe_version": "1.0",
  "prompt": "transfer 0.01 BTC to address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "scope": {
    "allowed_tools": ["send_crypto"],
    "max_tokens": 100,
    "max_cost": 0.50,
    "allowed_domains": ["api.blockchain.com"]
  },
  "issuer": "user:carol",
  "audience": "agent:crypto-bot",
  "ttl_seconds": 3600,
  "nonce": "11111111-2222-3333-4444-555555555555",
  "counter": 15,
  "signature": "<valid_signature>"
}
```

**First submission:** `{valid: true, reason: "OK"}` — transaction executes.

**Second submission (same envelope, same nonce):** `{valid: false, error: {code: "NONCE_REPLAY", ...}}`

**Reason:** The `nonce` value `11111111-2222-3333-4444-555555555555` has already been recorded for issuer `user:carol`. Even though the signature is valid and the TTL hasn't expired, the replay is detected.

### 8.5 Envelope with Incorrect Audience

```json
{
  "vpe_version": "1.0",
  "prompt": "access production database",
  "scope": {
    "allowed_tools": ["database_query"],
    "max_tokens": 2000,
    "max_cost": 0.05,
    "allowed_domains": ["db.internal.prod.com"]
  },
  "issuer": "user:admin",
  "audience": "agent:meridian-engine",
  "ttl_seconds": 120,
  "nonce": "fedcba09-8765-4321-0123-456789abcdef",
  "counter": 99,
  "signature": "<valid_signature>"
}
```

**When received by `agent:hermes-default`:** `{valid: false, error: {code: "WRONG_AUDIENCE", ...}}`

**Reason:** The audience `agent:meridian-engine` does not match the verifier's identity `agent:hermes-default`. Only `meridian-engine` should execute this prompt.

### 8.6 Envelope Exceeding Scope at Runtime

Valid envelope with strict scope, where the agent's execution would exceed declared limits:

```json
{
  "vpe_version": "1.0",
  "prompt": "scrape all pages of example.com and analyze",
  "scope": {
    "allowed_tools": ["web_fetch", "llm_generate"],
    "max_tokens": 500,
    "max_cost": 0.02,
    "allowed_domains": ["example.com"]
  },
  "issuer": "user:dave",
  "audience": "agent:hermes-default",
  "ttl_seconds": 600,
  "nonce": "aaaabbbb-cccc-dddd-eeee-ffff00001111",
  "counter": 3,
  "signature": "<valid_signature>"
}
```

**Verification passes** (signature valid, TTL OK, nonce fresh).

**But during execution:**
- Web fetch to `evil.com` → `DOMAIN_NOT_ALLOWED`.
- Attempting to generate 5000 tokens → `TOKEN_LIMIT_EXCEEDED`.
- Cumulative cost exceeds `$0.02` → `COST_LIMIT_EXCEEDED`.

---

## 9. Security Considerations

### 9.1 Key Management

- **Private keys** MUST be stored securely and never exposed in prompt histories, log files, or training data.
- **Public keys** MUST be distributed through authenticated channels (the Seal Secrets Broker or equivalent).
- **Key rotation** is RECOMMENDED: issuers SHOULD rotate keys periodically and verifiers SHOULD support multiple active keys per issuer.
- **Compromised key revocation:** implement a revocation list or key versioning mechanism.

### 9.2 Replay Protection Bounds

- The nonce replay store MUST have bounded memory usage. A Bloom filter with TTL-aware eviction is RECOMMENDED.
- After TTL expiry, the nonce MAY be dropped from the replay store, but the counter monotonicity check still prevents replay of significantly older envelopes.
- The nonce MUST be generated with a CSPRNG. UUIDv4 is RECOMMENDED for simplicity, but raw random bytes are preferred for true uniqueness.

### 9.3 Clock Synchronization

- TTL verification depends on clock accuracy. Verifiers SHOULD use NTP-synchronized clocks.
- A clock skew tolerance of ±30 seconds is RECOMMENDED to account for mild desynchronization.
- If the verifier's clock is unreliable, `ttl_seconds` should be used as a relative bound from first-seen time, not absolute time.

### 9.4 Scope Bounds

- An issuer SHOULD set the tightest possible scope for each prompt.
- Wildcard scopes (`"allowed_tools": ["*"]`, `"allowed_domains": ["*"]`) SHOULD only be used in trusted environments.
- `max_cost` and `max_tokens` provide cost-control safety nets even against validly-signed prompts that turn out to be expensive.

### 9.5 Side-Channel Considerations

- Signature verification timing SHOULD use constant-time comparison to prevent timing side-channel attacks on the public key.
- Error messages SHOULD NOT reveal whether the `issuer` exists (unknown_issuer vs invalid_signature), to prevent attacker enumeration of registered issuers.

### 9.6 Canonicalization Attacks

- JSON parsing differences can produce different canonical payloads. Implementations MUST:
  - Reject JSON with duplicate keys (last-write-wins is not safe for signing).
  - Use the same JSON serialization library for both signing and verification.
  - Normalize numeric precision (`42` vs `42.0` vs `4.2e1`) before signing.

---

## 10. Compatibility and Fallback

### 10.1 Unsigned Prompts

VPE is OPTIONAL. Agents MAY accept unsigned (plain-text) prompts for backward compatibility. Unsigned prompts MUST be logged as `"unverified"` and SHOULD be subject to EPD scanning in lieu of cryptographic verification.

### 10.2 Version Negotiation

Implementations receiving an envelope with `vpe_version` `"1.1"` (hypothetical future version):
- MUST accept it if only backward-compatible (MINOR) changes were made.
- MUST reject it if incompatible (MAJOR) changes were made.
- Implementation-defined behavior: MAY attempt to downgrade or gracefully handle unknown fields.

### 10.3 Extensibility

Future versions of VPE MAY:
- Add new fields (non-breaking within MAJOR version).
- Support additional signing algorithms (e.g., ECDSA, post-quantum).
- Introduce chained envelopes (multi-hop provenance).
- Add encryption of the `prompt` field in addition to signing.

---

## Appendix A: JSON Schema

The canonical JSON Schema for VPE v1.0 envelopes:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://seal.vpe/v1.0/envelope",
  "title": "VPE Envelope v1.0",
  "description": "A Verified Prompt Envelope (VPE) with Ed25519 cryptographic provenance",
  "type": "object",
  "required": [
    "vpe_version", "prompt", "scope", "issuer", "audience",
    "ttl_seconds", "nonce", "counter", "signature"
  ],
  "properties": {
    "vpe_version": {
      "type": "string",
      "pattern": "^[0-9]+\\.[0-9]+$",
      "description": "Protocol version (MAJOR.MINOR)"
    },
    "prompt": {
      "type": "string",
      "maxLength": 1000000,
      "description": "The actionable instruction"
    },
    "scope": {
      "type": "object",
      "required": ["allowed_tools", "max_tokens", "max_cost", "allowed_domains"],
      "properties": {
        "allowed_tools": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Tool names allowed for execution ([\"*\"] = all)"
        },
        "max_tokens": {
          "type": "integer",
          "minimum": 0,
          "description": "Maximum output tokens"
        },
        "max_cost": {
          "type": "number",
          "minimum": 0,
          "description": "Maximum cost in USD"
        },
        "allowed_domains": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Domain glob patterns for network access ([\"*\"] = all)"
        }
      },
      "additionalProperties": false
    },
    "issuer": {
      "type": "string",
      "minLength": 1,
      "description": "Identity of the signing entity"
    },
    "audience": {
      "type": "string",
      "minLength": 1,
      "description": "Intended recipient agent"
    },
    "doc_sha256": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$",
      "description": "SHA-256 of source document (optional)"
    },
    "ttl_seconds": {
      "type": "integer",
      "minimum": 1,
      "description": "Time-to-live in seconds"
    },
    "nonce": {
      "type": "string",
      "minLength": 16,
      "description": "Unique replay-prevention value"
    },
    "counter": {
      "type": "integer",
      "minimum": 0,
      "description": "Monotonically increasing sequence number"
    },
    "signature": {
      "type": "string",
      "pattern": "^[a-f0-9]{128}$",
      "description": "Ed25519 signature (64 bytes, hex-encoded)"
    }
  },
  "additionalProperties": false
}
```

## Appendix B: Test Vectors

> Test vectors will be generated from the reference implementation (P1.2). Below is the canonical structure.

### B.1 Key Pair

```
Private key (hex):   <32 bytes hex>
Public key (hex):    <32 bytes hex>
```

### B.2 Canonical Signing Payload

```
Input envelope (without signature):
{"vpe_version":"1.0","prompt":"test prompt","scope":{"allowed_tools":[],"max_tokens":100,"max_cost":0.0,"allowed_domains":[]},"issuer":"test:user","audience":"agent:test","ttl_seconds":60,"nonce":"00000000-0000-0000-0000-000000000001","counter":0}

Canonical payload bytes (hex):
<UTF-8 encoding of above JSON>

Signature (hex):
<64 bytes hex>
```

### B.3 Verification Example

```
Public key:       <hex>
Canonical bytes:  <hex>
Expected sig:     <hex>

Verify(payload, sig, pubkey) → {valid: true}
```

---

## References

- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — EdDSA (Ed25519)
- [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) — Key words for use in RFCs
- [JSON Schema](https://json-schema.org/) — JSON Schema draft-07
- [Seal Architecture](ARCHITECTURE.md) — System architecture and design decisions
- [OWASP LLM Top 10](https://genai.owasp.org/) — Prompt injection as #1 risk
