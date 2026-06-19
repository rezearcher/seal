# VPE Rust Port Specification

## Overview
Port the VPE (Verified Prompt Envelope) protocol to Rust.
The existing Python reference is at ~/projects/seal/seal/core.py

## Files to create
- `src/lib.rs` — main module with all exports
- `src/canonical.rs` — canonical JSON serialization
- `tests/core_test.rs` — integration tests matching Python test suite

## Cargo.toml dependencies
```toml
[dependencies]
ed25519-dalek = { version = "2", features = ["std"] }
sha2 = "0.10"
rand = "0.8"
hmac = "0.12"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
```

## API Surface (exactly matching Python reference)

### pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>)
Returns (private_key, public_key) — 32 bytes each.

### pub fn canonical_json(envelope: &HashMap<String, Value>) -> Vec<u8>
Rules:
1. Field order: ["vpe_version", "prompt", "scope", "issuer", "audience", "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain"]
2. Exclude "signature"
3. Omit cert_chain when Null
4. Scope keys sorted alphabetically
5. Per-field defaults: vpe_version="1.0", scope={}, issuer="", audience="", doc_sha256="", iat=Null, ttl_seconds=300, nonce="", counter=Null, cert_chain=Null
6. Compact separators: no spaces
7. UTF-8 bytes

### pub fn vpe_sign(
  prompt: &str,
  scope: Option<Value>,
  issuer: Option<&str>,
  audience: Option<&str>,
  doc_sha256: Option<&str>,
  ttl_seconds: Option<i64>,
  nonce: Option<&str>,
  counter: Option<i64>,
  private_key: &[u8],
  compact: bool,
) -> Result<String, Box<dyn Error>>

### pub fn vpe_verify(
  envelope_str: &str,
  public_key: Option<&[u8]>,
  trust_anchor: Option<&[u8]>,
  not_before: Option<i64>,
  not_after: Option<i64>,
  nonce_store: Option<&mut dyn NonceStore>,
) -> VpeResult

VpeResult = struct { pub valid: bool, pub reason: String }

pub trait NonceStore {
    fn add(&mut self, nonce: &str) -> bool;
}

### pub fn vpe_sign_hmac(... shared_secret: &[u8], compact: bool) -> Result<String, ...>

### pub fn vpe_verify_hmac(envelope_str: &str, shared_secret: &[u8], not_before: Option<i64>, not_after: Option<i64>) -> VpeResult

## _ENVELOPE_FIELDS
```
const ENVELOPE_FIELDS: &[&str] = &[
    "vpe_version", "prompt", "scope", "issuer", "audience",
    "doc_sha256", "iat", "ttl_seconds", "nonce", "counter", "cert_chain",
];
```

## Canonical defaults
vpe_version: "1.0"
scope: serde_json::Value::Object(Map::new())
issuer: ""
audience: ""
doc_sha256: ""
iat: Value::Null
ttl_seconds: 300 (as Number)
nonce: ""
counter: Value::Null
cert_chain: Value::Null

`ttl_seconds` in canonical: always 300 when missing (default). In the actual JSON output, it's 300. The default for ttl_seconds in the canonical function is 300 (i64).

## Strippable defaults (for compact mode)
Same as Python: remove fields when they match default values.

## Tests
Write tests in tests/core_test.rs that mirror Python test_core.py:
- Canonical JSON: determinism, field order, scope sort, cert_chain handling, defaults
- Key generation: 32 bytes each, different each call
- Signing: returns JSON string, all fields present, 128 hex char signature
- Verification: valid round-trip, wrong keys reject
- Tamper detection: every field mutation causes failure
- HMAC sign/verify round-trip
