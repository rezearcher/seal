mod canonical;

pub use canonical::canonical_json;
use canonical::strip_empty_fields;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{Map, Number, Value};
use sha2::Sha256;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a VPE verification.
#[derive(Debug, Clone)]
pub struct VpeResult {
    pub valid: bool,
    pub reason: String,
}

/// Trait for nonce replay protection.
pub trait NonceStore {
    /// Add a nonce to the store. Returns `false` if the nonce was already seen
    /// (replay detected).
    fn add(&mut self, nonce: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn make_nonce() -> String {
    let mut buf = [0u8; 16];
    use rand::RngCore;
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Load a raw 32-byte Ed25519 private key.
fn load_private_key(raw: &[u8]) -> Result<SigningKey, Box<dyn Error>> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load a raw 32-byte Ed25519 public key.
fn load_public_key(raw: &[u8]) -> Result<VerifyingKey, Box<dyn Error>> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

/// Build the base envelope dict (before signing) shared by vpe_sign and vpe_sign_hmac.
fn build_envelope(
    prompt: &str,
    scope: Option<Value>,
    issuer: Option<&str>,
    audience: Option<&str>,
    doc_sha256: Option<&str>,
    ttl_seconds: Option<i64>,
    nonce: Option<&str>,
    counter: Option<i64>,
) -> Map<String, Value> {
    let mut env = Map::new();
    env.insert("vpe_version".into(), Value::String("1.0".into()));
    env.insert("prompt".into(), Value::String(prompt.to_owned()));
    env.insert("scope".into(), scope.unwrap_or(Value::Object(Map::new())));
    env.insert(
        "issuer".into(),
        Value::String(issuer.unwrap_or("").to_owned()),
    );
    env.insert(
        "audience".into(),
        Value::String(audience.unwrap_or("").to_owned()),
    );
    env.insert(
        "doc_sha256".into(),
        Value::String(doc_sha256.unwrap_or("").to_owned()),
    );
    env.insert("iat".into(), Value::Number(Number::from(unix_now())));
    env.insert(
        "ttl_seconds".into(),
        Value::Number(Number::from(ttl_seconds.unwrap_or(300))),
    );
    env.insert(
        "nonce".into(),
        Value::String(nonce.map(|s| s.to_owned()).unwrap_or_else(make_nonce)),
    );
    env.insert(
        "counter".into(),
        counter
            .map(|c| Value::Number(Number::from(c)))
            .unwrap_or(Value::Null),
    );
    env.insert("signature".into(), Value::String(String::new()));
    env
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 key pair.
///
/// Returns `(private_key, public_key)` — 32 bytes each.
pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

// ---------------------------------------------------------------------------
// Sign (Ed25519)
// ---------------------------------------------------------------------------

/// Sign a prompt and produce a VPE envelope JSON string (Ed25519).
pub fn vpe_sign(
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
) -> Result<String, Box<dyn Error>> {
    let sk = load_private_key(private_key)?;

    let mut envelope = build_envelope(
        prompt,
        scope,
        issuer,
        audience,
        doc_sha256,
        ttl_seconds,
        nonce,
        counter,
    );

    // Canonical JSON (signature field is empty at this point)
    let canon = canonical_json(&envelope);

    // Sign
    let signature: Signature = sk.sign(&canon);
    let sig_hex = hex::encode(signature.to_bytes());
    envelope.insert("signature".into(), Value::String(sig_hex));

    // Compact mode: strip default/empty fields
    let output = if compact {
        strip_empty_fields(&envelope)
    } else {
        envelope
    };

    Ok(serde_json::to_string(&output)?)
}

// ---------------------------------------------------------------------------
// Verify (Ed25519)
// ---------------------------------------------------------------------------

/// Verify a VPE envelope string (Ed25519).
pub fn vpe_verify(
    envelope_str: &str,
    public_key: Option<&[u8]>,
    trust_anchor: Option<&[u8]>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    nonce_store: Option<&mut dyn NonceStore>,
) -> VpeResult {
    // 1. Parse
    let envelope: Map<String, Value> = match serde_json::from_str(envelope_str) {
        Ok(Value::Object(m)) => m,
        Ok(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_json: not a dict".into(),
            }
        }
        Err(e) => {
            return VpeResult {
                valid: false,
                reason: format!("invalid_json: {e}"),
            }
        }
    };

    // 2. Version
    let version = envelope
        .get("vpe_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0");
    if version != "1.0" {
        return VpeResult {
            valid: false,
            reason: format!("unsupported_version: {version}"),
        };
    }

    // 3. Signature present
    let sig_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sig_hex.is_empty() {
        return VpeResult {
            valid: false,
            reason: "missing_signature".into(),
        };
    }

    // 4. Scope is dict
    match envelope.get("scope") {
        Some(Value::Object(_)) | None => {}
        _ => {
            return VpeResult {
                valid: false,
                reason: "scope_not_dict".into(),
            }
        }
    }

    // 5. Nonce present
    let nonce = envelope.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce.is_empty() {
        return VpeResult {
            valid: false,
            reason: "missing_or_empty_nonce".into(),
        };
    }

    // 6. Counter type check (if present)
    if let Some(counter) = envelope.get("counter") {
        if !counter.is_null() && !counter.is_i64() {
            return VpeResult {
                valid: false,
                reason: "counter_not_integer".into(),
            };
        }
    }

    // 7. TTL check
    let ttl = envelope
        .get("ttl_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // 8. Nonce replay check
    if let Some(store) = nonce_store {
        if ttl > 0 && !store.add(nonce) {
            return VpeResult {
                valid: false,
                reason: "nonce_reused".into(),
            };
        }
    }

    // 9. Determine effective public key (cert-chain or direct)
    let cert_chain = envelope.get("cert_chain");
    let effective_pk: Vec<u8> =
        if trust_anchor.is_some() && cert_chain.is_some() && !cert_chain.unwrap().is_null() {
            // Simplified cert-chain verification — for now assume direct key mode
            // In a full implementation, walk the chain here.
            // Fall back to public_key param.
            match public_key {
                Some(pk) => pk.to_vec(),
                None => {
                    return VpeResult {
                        valid: false,
                        reason: "no_verification_key: provide public_key or trust_anchor".into(),
                    }
                }
            }
        } else if let Some(pk) = public_key {
            pk.to_vec()
        } else {
            return VpeResult {
                valid: false,
                reason: "no_verification_key: provide public_key or trust_anchor".into(),
            };
        };

    // 10. Cryptographic signature verification
    let canon = {
        let mut verify_env = envelope.clone();
        verify_env.insert("signature".into(), Value::String(String::new()));
        canonical_json(&verify_env)
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_signature_encoding".into(),
            }
        }
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_signature_encoding".into(),
            }
        }
    };

    let pk = match load_public_key(&effective_pk) {
        Ok(pk) => pk,
        Err(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_public_key".into(),
            }
        }
    };

    if pk.verify(&canon, &sig).is_err() {
        return VpeResult {
            valid: false,
            reason: "signature_mismatch".into(),
        };
    }

    // 11. TTL expiry
    let now = unix_now();
    if ttl > 0 {
        match envelope.get("iat").and_then(|v| v.as_i64()) {
            Some(iat) => {
                if now - iat > ttl {
                    return VpeResult {
                        valid: false,
                        reason: "envelope_expired".into(),
                    };
                }
            }
            None => {
                // No iat — backward-compat, treat as no expiry
            }
        }
    }

    // 12. Key time constraints
    if let Some(nb) = not_before {
        if now < nb {
            return VpeResult {
                valid: false,
                reason: "key_not_yet_valid".into(),
            };
        }
    }
    if let Some(na) = not_after {
        if now >= na {
            return VpeResult {
                valid: false,
                reason: "key_expired".into(),
            };
        }
    }

    VpeResult {
        valid: true,
        reason: "ok".into(),
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 sign & verify
// ---------------------------------------------------------------------------

/// Sign a prompt with HMAC-SHA256 for internal/low-security contexts.
pub fn vpe_sign_hmac(
    prompt: &str,
    scope: Option<Value>,
    issuer: Option<&str>,
    audience: Option<&str>,
    doc_sha256: Option<&str>,
    ttl_seconds: Option<i64>,
    nonce: Option<&str>,
    counter: Option<i64>,
    shared_secret: &[u8],
    compact: bool,
) -> Result<String, Box<dyn Error>> {
    if shared_secret.is_empty() {
        return Err("shared_secret must be non-empty bytes".into());
    }

    let mut envelope = build_envelope(
        prompt,
        scope,
        issuer,
        audience,
        doc_sha256,
        ttl_seconds,
        nonce,
        counter,
    );

    let canon = canonical_json(&envelope);

    let mut mac =
        HmacSha256::new_from_slice(shared_secret).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(&canon);
    let sig_hex = hex::encode(mac.finalize().into_bytes());

    envelope.insert("signature".into(), Value::String(sig_hex));

    let output = if compact {
        strip_empty_fields(&envelope)
    } else {
        envelope
    };

    Ok(serde_json::to_string(&output)?)
}

/// Verify a HMAC-SHA256 signed VPE envelope.
pub fn vpe_verify_hmac(
    envelope_str: &str,
    shared_secret: &[u8],
    not_before: Option<i64>,
    not_after: Option<i64>,
) -> VpeResult {
    // 1. Parse
    let envelope: Map<String, Value> = match serde_json::from_str(envelope_str) {
        Ok(Value::Object(m)) => m,
        Ok(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_json: not a dict".into(),
            }
        }
        Err(e) => {
            return VpeResult {
                valid: false,
                reason: format!("invalid_json: {e}"),
            }
        }
    };

    // 2. Version
    let version = envelope
        .get("vpe_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0");
    if version != "1.0" {
        return VpeResult {
            valid: false,
            reason: format!("unsupported_version: {version}"),
        };
    }

    // 3. Signature present
    let sig_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sig_hex.is_empty() {
        return VpeResult {
            valid: false,
            reason: "missing_signature".into(),
        };
    }

    // 4. Scope is dict
    match envelope.get("scope") {
        Some(Value::Object(_)) | None => {}
        _ => {
            return VpeResult {
                valid: false,
                reason: "scope_not_dict".into(),
            }
        }
    }

    // 5. Nonce present
    let nonce = envelope.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce.is_empty() {
        return VpeResult {
            valid: false,
            reason: "missing_or_empty_nonce".into(),
        };
    }

    // 6. Counter type check
    if let Some(counter) = envelope.get("counter") {
        if !counter.is_null() && !counter.is_i64() {
            return VpeResult {
                valid: false,
                reason: "counter_not_integer".into(),
            };
        }
    }

    // 7. TTL check
    let ttl = envelope
        .get("ttl_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // 8. HMAC-SHA256 signature verification
    let canon = {
        let mut verify_env = envelope.clone();
        verify_env.insert("signature".into(), Value::String(String::new()));
        canonical_json(&verify_env)
    };

    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(_) => {
            return VpeResult {
                valid: false,
                reason: "invalid_signature_encoding".into(),
            }
        }
    };

    let mut mac = match HmacSha256::new_from_slice(shared_secret) {
        Ok(m) => m,
        Err(e) => {
            return VpeResult {
                valid: false,
                reason: format!("hmac_key_error: {e}"),
            }
        }
    };
    mac.update(&canon);
    let result = mac.finalize();
    let expected = result.into_bytes();

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    if expected.ct_eq(&sig_bytes).unwrap_u8() != 1 {
        return VpeResult {
            valid: false,
            reason: "signature_mismatch".into(),
        };
    }

    // 9. TTL expiry
    let now = unix_now();
    if ttl > 0 {
        match envelope.get("iat").and_then(|v| v.as_i64()) {
            Some(iat) => {
                if now - iat > ttl {
                    return VpeResult {
                        valid: false,
                        reason: "envelope_expired".into(),
                    };
                }
            }
            None => {}
        }
    }

    // 10. Key time constraints
    if let Some(nb) = not_before {
        if now < nb {
            return VpeResult {
                valid: false,
                reason: "key_not_yet_valid".into(),
            };
        }
    }
    if let Some(na) = not_after {
        if now >= na {
            return VpeResult {
                valid: false,
                reason: "key_expired".into(),
            };
        }
    }

    VpeResult {
        valid: true,
        reason: "ok".into(),
    }
}
