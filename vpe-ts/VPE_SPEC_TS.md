# VPE TypeScript Port Specification

## Overview
Port the VPE (Verified Prompt Envelope) protocol to TypeScript/Node.js.
The existing Python reference is at ~/projects/seal/seal/core.py

## Files to create
- `src/index.ts` — main module with all exports
- `package.json` — already created, update name to `seal-vpe`
- `tsconfig.json` — TypeScript config
- `jest.config.js` — test config
- `test/core.test.ts` — tests matching the Python test suite

## API Surface (exactly matching Python reference)

### generateKeyPair()
Returns `{ privateKey: Buffer, publicKey: Buffer }` — 32 bytes each.
Use `tweetnacl` (pure JS Ed25519) or `crypto` module.

### canonicalJson(envelope: Record<string, any>): Buffer
Deterministic JSON serialization for signing.
Rules:
1. Field order: `_ENVELOPE_FIELDS = ["vpe_version", "prompt", "scope", "issuer", "audience", "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain"]`
2. Skip "signature" field
3. Omit cert_chain when null/undefined
4. Include counter: null when null
5. Scope keys sorted alphabetically
6. Per-field defaults: vpe_version="1.0", scope={}, issuer="", audience="", doc_sha256="", iat=null, ttl_seconds=300, nonce="", counter=null, cert_chain=null
7. Compact separators: "," and ":"
8. Encode as UTF-8 bytes

### vpeSign(
  prompt: string,
  scope?: Record<string, any>,
  issuer?: string,
  audience?: string,
  docSha256?: string,
  ttlSeconds?: number,
  nonce?: string,
  counter?: number | null,
  privateKey: Buffer,
  compact?: boolean
): string

Creates a signed VPE envelope JSON string.
- Auto-generates nonce (32 hex chars) if not provided
- Auto-computes doc_sha256 = SHA256(prompt).hex() if not provided
- Sets iat = Math.floor(Date.now()/1000)
- Signs canonical JSON with Ed25519
- If compact=true, strips default/empty fields from output using _STRIPPABLE_FIELD_DEFAULTS

### vpeVerify(
  envelopeStr: string,
  publicKey?: Buffer,
  trustAnchor?: Buffer,
  notBefore?: number,
  notAfter?: number,
  nonceStore?: { add(nonce: string): boolean }
): { valid: boolean, reason: string }

Verifies a VPE envelope.
Checks in order:
1. JSON parse
2. vpe_version = "1.0"
3. signature field present
4. scope is object
5. nonce is string, non-empty
6. counter is int or null
7. ttl_seconds is int
8. Nonce replay (if nonceStore and ttl>0)
9. Resolve public key (from cert_chain + trustAnchor, or direct publicKey)
10. Ed25519 signature verification
11. TTL expiry
12. not_before / not_after constraints

Returns { valid: boolean, reason: string }

### vpeSignHmac(prompt, scope?, issuer?, audience?, docSha256?, ttlSeconds?, nonce?, counter?, sharedSecret: Buffer, compact?): string
Same envelope format but HMAC-SHA256 instead of Ed25519.

### vpeVerifyHmac(envelopeStr, sharedSecret: Buffer, notBefore?, notAfter?): { valid, reason }
HMAC verification. Same checks as vpeVerify but uses HMAC.

## Strippable field defaults (for compact mode)
```
vpe_version: "1.0"
scope: {}
issuer: ""
audience: ""
doc_sha256: ""
iat: null
counter: null
cert_chain: null
ttl_seconds: 300 or 0
```

## Tests to implement
Write Jest tests that mirror the Python test_core.py:
- Canonical JSON tests (field order, scope sort, cert_chain handling, defaults)
- Key generation (32 bytes, different keys each call)
- Signing (returns JSON string, contains all fields, Ed25519 sig is 128 hex chars)
- Verification (valid envelope, wrong keys reject)
- Tamper detection (prompt, scope, issuer, audience, nonce, counter, ttl, signature)
- Replay prevention (same nonce rejected with NonceStore)
- HMAC sign/verify roundtrip
- Cross-language test: generate deterministic key, sign a fixed payload, verify
