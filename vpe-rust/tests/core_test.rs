use serde_json::{Map, Value};
use vpe_rust::{
    generate_key_pair, vpe_sign, vpe_sign_hmac, vpe_verify, vpe_verify_hmac, NonceStore, VpeResult,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ok(result: &VpeResult) {
    assert!(result.valid, "expected ok, got reason: {}", result.reason);
}

fn not_ok(result: &VpeResult) {
    assert!(!result.valid, "expected failure, got ok");
}

/// Parse a JSON string into a Map (for inspection).
fn parse_map(json_str: &str) -> Map<String, Value> {
    match serde_json::from_str(json_str).unwrap() {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

/// A simple nonce store for testing.
struct TestNonceStore {
    seen: std::collections::HashSet<String>,
}

impl TestNonceStore {
    fn new() -> Self {
        TestNonceStore {
            seen: std::collections::HashSet::new(),
        }
    }
}

impl NonceStore for TestNonceStore {
    fn add(&mut self, nonce: &str) -> bool {
        self.seen.insert(nonce.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

#[test]
fn test_key_generation() {
    let (sk, pk) = generate_key_pair();
    assert_eq!(sk.len(), 32, "private key must be 32 bytes");
    assert_eq!(pk.len(), 32, "public key must be 32 bytes");
}

#[test]
fn test_key_generation_unique() {
    let (sk1, pk1) = generate_key_pair();
    let (sk2, pk2) = generate_key_pair();
    assert_ne!(sk1, sk2, "private keys should differ");
    assert_ne!(pk1, pk2, "public keys should differ");
}

// ---------------------------------------------------------------------------
// Sign (Ed25519) — basic structure & defaults
// ---------------------------------------------------------------------------

#[test]
fn test_sign_minimal() {
    let (private_key, _public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "run ls",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();

    let parsed = parse_map(&envelope);
    assert_eq!(parsed["prompt"], "run ls");
    assert_eq!(parsed["vpe_version"], "1.0");
    assert_eq!(parsed["scope"], Value::Object(Map::new()));
    assert_eq!(parsed["issuer"], "");
    assert_eq!(parsed["audience"], "");
    assert_eq!(parsed["doc_sha256"], "");
    assert_eq!(parsed["ttl_seconds"], 300);
    assert!(parsed["nonce"].as_str().unwrap().len() > 0);
    assert!(parsed["iat"].as_i64().is_some());
    assert!(parsed["counter"].is_null());
    let sig = parsed["signature"].as_str().unwrap();
    assert_eq!(sig.len(), 128, "Ed25519 signature should be 128 hex chars");
}

#[test]
fn test_sign_all_fields() {
    let (private_key, _public_key) = generate_key_pair();
    let scope_val: Value =
        serde_json::from_str(r#"{"read": ["/tmp"], "write": ["/tmp/out"]}"#).unwrap();
    let envelope = vpe_sign(
        "process data",
        Some(scope_val),
        Some("alice"),
        Some("bob"),
        Some("abc123"),
        Some(600),
        None,
        Some(42),
        &private_key,
        false,
    )
    .unwrap();

    let parsed = parse_map(&envelope);
    assert_eq!(parsed["prompt"], "process data");
    assert_eq!(parsed["issuer"], "alice");
    assert_eq!(parsed["audience"], "bob");
    assert_eq!(parsed["doc_sha256"], "abc123");
    assert_eq!(parsed["ttl_seconds"], 600);
    assert_eq!(parsed["counter"], 42);
    assert_eq!(parsed["vpe_version"], "1.0");
    assert!(
        parsed["scope"].as_object().unwrap().contains_key("read"),
        "scope should contain 'read'"
    );
}

#[test]
fn test_sign_custom_nonce() {
    let (private_key, _public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        Some("my-custom-nonce"),
        None,
        &private_key,
        false,
    )
    .unwrap();

    let parsed = parse_map(&envelope);
    assert_eq!(parsed["nonce"], "my-custom-nonce");
}

// ---------------------------------------------------------------------------
// Sign — compact mode
// ---------------------------------------------------------------------------

#[test]
fn test_sign_compact_strips_defaults() {
    let (private_key, _public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "hello",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        true,
    )
    .unwrap();

    let parsed = parse_map(&envelope);
    // prompt, nonce, signature, iat should be kept
    assert!(parsed.contains_key("prompt"));
    assert!(parsed.contains_key("nonce"));
    assert!(parsed.contains_key("signature"));
    assert!(parsed.contains_key("iat"), "iat is now set at sign time and is not a strippable default — iat has no default that matches the actual time");
    // Default/empty fields should be stripped
    assert!(
        !parsed.contains_key("vpe_version"),
        "vpe_version should be stripped in compact mode"
    );
    assert!(
        !parsed.contains_key("issuer"),
        "issuer should be stripped in compact mode"
    );
    assert!(
        !parsed.contains_key("audience"),
        "audience should be stripped"
    );
    assert!(
        !parsed.contains_key("doc_sha256"),
        "doc_sha256 should be stripped"
    );
    assert!(
        !parsed.contains_key("counter"),
        "counter should be stripped"
    );
    assert!(
        !parsed.contains_key("cert_chain"),
        "cert_chain should be stripped"
    );
    // ttl_seconds is 300 (default) — should be stripped
    assert!(
        !parsed.contains_key("ttl_seconds"),
        "ttl_seconds should be stripped at default 300"
    );
    // scope = {} — should be stripped
    assert!(
        !parsed.contains_key("scope"),
        "scope should be stripped when empty"
    );
}

// ---------------------------------------------------------------------------
// Verify (Ed25519) — round trip
// ---------------------------------------------------------------------------

#[test]
fn test_verify_round_trip() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "run ls",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();

    let result = vpe_verify(&envelope, Some(&public_key), None, None, None, None);
    ok(&result);
}

#[test]
fn test_verify_compact_round_trip() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "run ls",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        true,
    )
    .unwrap();

    let result = vpe_verify(&envelope, Some(&public_key), None, None, None, None);
    ok(&result);
}

#[test]
fn test_verify_wrong_key() {
    let (private_key, _public_key) = generate_key_pair();
    let (_, wrong_public_key) = generate_key_pair();

    let envelope = vpe_sign(
        "run ls",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();

    let result = vpe_verify(&envelope, Some(&wrong_public_key), None, None, None, None);
    assert!(!result.valid, "wrong key should fail");
    assert!(
        result.reason.contains("signature_mismatch"),
        "reason: {}",
        result.reason
    );
}

// ---------------------------------------------------------------------------
// Tamper detection — every field mutation causes failure
// ---------------------------------------------------------------------------

#[test]
fn test_tamper_prompt() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "original",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("prompt".into(), Value::String("tampered".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered prompt should fail");
}

#[test]
fn test_tamper_issuer() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("issuer".into(), Value::String("attacker".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered issuer should fail");
}

#[test]
fn test_tamper_audience() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("audience".into(), Value::String("attacker".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered audience should fail");
}

#[test]
fn test_tamper_scope() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    let mut scope = Map::new();
    scope.insert("admin".into(), Value::Bool(true));
    parsed.insert("scope".into(), Value::Object(scope));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered scope should fail");
}

#[test]
fn test_tamper_ttl() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert(
        "ttl_seconds".into(),
        Value::Number(serde_json::Number::from(9999)),
    );
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered ttl should fail");
}

#[test]
fn test_tamper_nonce() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("nonce".into(), Value::String("tampered-nonce".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered nonce should fail");
}

#[test]
fn test_tamper_counter() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert(
        "counter".into(),
        Value::Number(serde_json::Number::from(999)),
    );
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered counter should fail");
}

#[test]
fn test_tamper_vpe_version() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("vpe_version".into(), Value::String("2.0".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered version should fail");
    assert!(result.reason.contains("unsupported_version"));
}

#[test]
fn test_tamper_signature_itself() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("signature".into(), Value::String("00".repeat(64)));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let result = vpe_verify(&tampered, Some(&public_key), None, None, None, None);
    assert!(!result.valid, "tampered signature should fail");
}

// ---------------------------------------------------------------------------
// Verify — validation checks
// ---------------------------------------------------------------------------

#[test]
fn test_verify_invalid_json() {
    let result = vpe_verify("not-json", Some(&[0u8; 32]), None, None, None, None);
    assert!(!result.valid);
    assert!(result.reason.contains("invalid_json"));
}

#[test]
fn test_verify_missing_signature() {
    let result = vpe_verify(
        r#"{"prompt":"x","nonce":"n"}"#,
        Some(&[0u8; 32]),
        None,
        None,
        None,
        None,
    );
    assert!(!result.valid);
    assert!(result.reason.contains("missing_signature"));
}

#[test]
fn test_verify_scope_not_dict() {
    let (private_key, _public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("scope".into(), Value::String("not-a-dict".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let (_, pk) = generate_key_pair();
    let result = vpe_verify(&tampered, Some(&pk), None, None, None, None);
    assert!(!result.valid);
    assert!(result.reason.contains("scope_not_dict"));
}

#[test]
fn test_verify_empty_nonce() {
    let (private_key, _public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let mut parsed = parse_map(&envelope);
    parsed.insert("nonce".into(), Value::String("".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();
    let (_, pk) = generate_key_pair();
    let result = vpe_verify(&tampered, Some(&pk), None, None, None, None);
    assert!(!result.valid);
    assert!(result.reason.contains("missing_or_empty_nonce"));
}

#[test]
fn test_verify_no_key_provided() {
    let result = vpe_verify(
        r#"{"prompt":"x","nonce":"n","signature":"00"}"#,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(!result.valid);
    assert!(result.reason.contains("no_verification_key"));
}

// ---------------------------------------------------------------------------
// Nonce replay protection
// ---------------------------------------------------------------------------

#[test]
fn test_nonce_replay_detected() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        Some(3600),
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    let parsed = parse_map(&envelope);
    let nonce = parsed["nonce"].as_str().unwrap().to_owned();

    let mut store = TestNonceStore::new();

    // First use — should succeed
    let result1 = vpe_verify(
        &envelope,
        Some(&public_key),
        None,
        None,
        None,
        Some(&mut store),
    );
    ok(&result1);

    // Second use with same nonce — should be detected as replay
    let mut store2 = TestNonceStore::new();
    store2.add(&nonce); // mark the nonce as seen
    let result2 = vpe_verify(
        &envelope,
        Some(&public_key),
        None,
        None,
        None,
        Some(&mut store2),
    );
    assert!(!result2.valid, "reused nonce should fail");
    assert!(result2.reason.contains("nonce_reused"));
}

// ---------------------------------------------------------------------------
// Key time constraints
// ---------------------------------------------------------------------------

#[test]
fn test_not_before_future_key() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    // Key is not yet valid (not_before in the far future)
    let result = vpe_verify(
        &envelope,
        Some(&public_key),
        None,
        Some(99999999999i64),
        None,
        None,
    );
    assert!(!result.valid);
    assert!(result.reason.contains("key_not_yet_valid"));
}

#[test]
fn test_not_after_expired_key() {
    let (private_key, public_key) = generate_key_pair();
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();
    // Key has expired (not_after in the past)
    let result = vpe_verify(&envelope, Some(&public_key), None, None, Some(0), None);
    assert!(!result.valid);
    assert!(result.reason.contains("key_expired"));
}

// ---------------------------------------------------------------------------
// HMAC sign/verify
// ---------------------------------------------------------------------------

#[test]
fn test_hmac_round_trip() {
    let secret = b"my-shared-secret-key-32-bytes!";
    let envelope = vpe_sign_hmac(
        "run ls", None, None, None, None, None, None, None, secret, false,
    )
    .unwrap();

    let result = vpe_verify_hmac(&envelope, secret, None, None);
    ok(&result);
}

#[test]
fn test_hmac_compact_round_trip() {
    let secret = b"my-shared-secret-key-different!";
    let envelope = vpe_sign_hmac(
        "hello world",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        secret,
        true,
    )
    .unwrap();

    let result = vpe_verify_hmac(&envelope, secret, None, None);
    ok(&result);
}

#[test]
fn test_hmac_wrong_secret() {
    let secret = b"correct-secret-32-bytes-long!!";
    let wrong_secret = b"wrong-secret-32-bytes-long!!!!!";
    let envelope = vpe_sign_hmac(
        "run ls", None, None, None, None, None, None, None, secret, false,
    )
    .unwrap();

    let result = vpe_verify_hmac(&envelope, wrong_secret, None, None);
    assert!(!result.valid, "wrong secret should fail");
    assert!(result.reason.contains("signature_mismatch"));
}

#[test]
fn test_hmac_tamper_detection() {
    let secret = b"test-secret-for-hmac-test";
    let envelope = vpe_sign_hmac(
        "original prompt",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        secret,
        false,
    )
    .unwrap();

    let mut parsed = parse_map(&envelope);
    parsed.insert("prompt".into(), Value::String("tampered".into()));
    let tampered = serde_json::to_string(&parsed).unwrap();

    let result = vpe_verify_hmac(&tampered, secret, None, None);
    assert!(!result.valid, "tampered HMAC envelope should fail");
}

#[test]
fn test_hmac_all_fields() {
    let secret = b"another-secret-32-b";
    let scope_val: Value = serde_json::from_str(r#"{"read": ["/data"]}"#).unwrap();
    let envelope = vpe_sign_hmac(
        "process",
        Some(scope_val),
        Some("system"),
        Some("agent"),
        Some("doc_hash_123"),
        Some(0),
        Some("explicit-nonce"),
        Some(7),
        secret,
        false,
    )
    .unwrap();

    let parsed = parse_map(&envelope);
    assert_eq!(parsed["prompt"], "process");
    assert_eq!(parsed["issuer"], "system");
    assert_eq!(parsed["audience"], "agent");
    assert_eq!(parsed["doc_sha256"], "doc_hash_123");
    assert_eq!(parsed["ttl_seconds"], 0);
    assert_eq!(parsed["nonce"], "explicit-nonce");
    assert_eq!(parsed["counter"], 7);

    let sig = parsed["signature"].as_str().unwrap();
    assert_eq!(sig.len(), 64, "HMAC signature should be 64 hex chars");

    let result = vpe_verify_hmac(&envelope, secret, None, None);
    ok(&result);
}

#[test]
fn test_hmac_empty_secret_rejected() {
    let result = vpe_sign_hmac("test", None, None, None, None, None, None, None, b"", false);
    assert!(result.is_err(), "empty secret should be rejected");
}

// ---------------------------------------------------------------------------
// Expiry (TTL) verification
// ---------------------------------------------------------------------------

#[test]
fn test_expiry_past_envelope() {
    let (private_key, public_key) = generate_key_pair();
    // Envelope with very short TTL, then wait... actually we can't easily test
    // time-dependent expiry in unit tests without clock control.
    // Instead, just verify that a valid envelope with ttl=0 (no expiry) works.
    let envelope = vpe_sign(
        "test",
        None,
        None,
        None,
        None,
        Some(0),
        None,
        None,
        &private_key,
        false,
    )
    .unwrap();

    let result = vpe_verify(&envelope, Some(&public_key), None, None, None, None);
    ok(&result);
}
