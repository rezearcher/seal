use std::fs;
use std::path::Path;
use serde_json::Value;
use vpe_rust::{vpe_verify, vpe_verify_hmac};

/// Find the vector fixture by searching relative paths.
fn find_fixture() -> String {
    let candidates = &[
        "../tests/vectors/vpe_vectors.json",
        "../../tests/vectors/vpe_vectors.json",
        "../../../tests/vectors/vpe_vectors.json",
        "tests/vectors/vpe_vectors.json",
    ];
    for &p in candidates {
        if Path::new(p).exists() {
            return fs::read_to_string(p).expect("read fixture");
        }
    }
    // Also try from CARGO_MANIFEST_DIR
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = format!("{}/../tests/vectors/vpe_vectors.json", manifest_dir);
        if Path::new(&p).exists() {
            return fs::read_to_string(&p).expect("read fixture");
        }
        let p = format!("{}/../../tests/vectors/vpe_vectors.json", manifest_dir);
        if Path::new(&p).exists() {
            return fs::read_to_string(&p).expect("read fixture");
        }
    }
    panic!("cannot find vpe_vectors.json");
}

/// Parse the fixture JSON and return all vectors.
fn load_vectors() -> (Vec<u8>, Vec<u8>, Vec<(String, bool, String, String)>) {
    let raw = find_fixture();
    let fixture: Value = serde_json::from_str(&raw).expect("valid fixture JSON");

    let pub_hex = fixture["ed25519_public_key_hex"].as_str().unwrap();
    let public_key = hex::decode(pub_hex).expect("valid pubkey hex");

    let hmac_hex = fixture["hmac_secret_hex"].as_str().unwrap();
    let hmac_secret = hex::decode(hmac_hex).expect("valid hmac secret hex");

    let vectors = fixture["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for vec in vectors {
        let id = vec["id"].as_str().unwrap().to_string();
        let expected = vec["expected_verify"].as_bool().unwrap();

        let env_str = match vec["tampered_envelope_json"].as_str() {
            Some(t) => t.to_string(),
            None => vec["signed_envelope_json"].as_str().unwrap().to_string(),
        };

        let sig_type = vec["signature_type"].as_str().unwrap().to_string();
        results.push((id, expected, env_str, sig_type));
    }

    (public_key, hmac_secret, results)
}

#[test]
fn test_interop_all_vectors() {
    let (public_key, hmac_secret, vectors) = load_vectors();
    let mut failed = Vec::new();

    for (id, expected, env_str, sig_type) in &vectors {
        let result = if sig_type == "hmac-sha256" {
            vpe_verify_hmac(env_str, &hmac_secret, None, None)
        } else {
            vpe_verify(env_str, Some(&public_key), None, None, None, None)
        };

        if result.valid != *expected {
            failed.push(format!(
                "[{}] expected valid={}, got valid={} reason={}",
                id, expected, result.valid, result.reason
            ));
        }
    }

    if !failed.is_empty() {
        panic!("Vector verification failures:\n{}", failed.join("\n"));
    }
}
