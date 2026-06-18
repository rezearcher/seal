# VPE Go Port Specification

## Overview
Port the VPE (Verified Prompt Envelope) protocol to Go.
The existing Python reference is at ~/projects/seal/seal/core.py

## Files to create
- `vpe/vpe.go` — main module
- `vpe/vpe_test.go` — tests matching Python test suite
- `vpe/canonical.go` — canonical JSON serialization
- `vpe/hmac.go` — HMAC signing/verification

## Package structure
Package name: `vpe`
Import path: `github.com/seal/vpe-go/vpe`

## API Surface (exactly matching Python reference)

### GenerateKeyPair() (PrivateKey, PublicKey, error)
Returns 32-byte Ed25519 key pair.
Use `crypto/ed25519` from stdlib (Go 1.13+).

### VpeSign(
  prompt string,
  scope map[string]interface{},
  issuer string,
  audience string,
  docSha256 string,
  ttlSeconds int,
  nonce string,
  counter *int,
  privateKey []byte,
  compact bool,
) (string, error)

Defaults when empty/zero:
- scope: {} (empty map)
- issuer: ""
- audience: ""
- docSha256: SHA256(prompt) hex
- ttlSeconds: 300
- nonce: 32 hex chars (auto-generated)
- counter: nil (excluded from JSON, shows as null in canonical)

### VpeVerify(
  envelopeStr string,
  publicKey []byte,
  trustAnchor []byte,
  notBefore int64,
  notAfter int64,
  nonceStore NonceStore,
) VpeResult

VpeResult = struct { Valid bool; Reason string }

NonceStore interface:
```go
type NonceStore interface {
    Add(nonce string) bool  // returns false if nonce already seen
}
```

### VpeSignHmac(...sharedSecret []byte, compact bool) (string, error)
Same envelope, HMAC-SHA256 signature.

### VpeVerifyHmac(envelopeStr string, sharedSecret []byte, notBefore, notAfter int64) VpeResult

## Canonical JSON (_canonicalJson)
Rules:
1. Field order: ["vpe_version", "prompt", "scope", "issuer", "audience", "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain"]
2. Exclude "signature"
3. Omit cert_chain when nil
4. Scope keys sorted alphabetically
5. Per-field defaults: vpe_version="1.0", scope={}, issuer="", audience="", doc_sha256="", iat=nil, ttl_seconds=300, nonce="", counter=nil, cert_chain=nil
6. Compact separators: no spaces
7. Encode as UTF-8 bytes

## _ENVELOPE_FIELDS
```go
var EnvelopeFields = []string{
    "vpe_version", "prompt", "scope", "issuer", "audience",
    "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain",
}
```

## Strippable defaults (for compact mode)
vpe_version="1.0", scope={}, issuer="", audience="", doc_sha256="", iat=nil, counter=nil, cert_chain=nil, ttl_seconds=300 or 0

## Tests
Write Go tests matching the Python test_core.py:
- Canonical JSON determinism, field order, scope sort, cert_chain handling
- Key generation
- Signing round-trip
- Verification with correct/wrong keys
- Tamper detection (every field)
- HMAC round-trip
