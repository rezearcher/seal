use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

/// Ordered field list matching Python's _ENVELOPE_FIELDS.
/// Every field except `signature` appears in this order in canonical JSON.
pub const ENVELOPE_FIELDS: &[&str] = &[
    "vpe_version",
    "prompt",
    "scope",
    "issuer",
    "audience",
    "doc_sha256",
    "iat",
    "ttl_seconds",
    "nonce",
    "counter",
    "cert_chain",
];

/// Per-field defaults for canonical JSON reconstruction.
/// Matches Python's _CANONICAL_DEFAULTS dict.
pub fn get_canonical_default(field: &str) -> Value {
    match field {
        "vpe_version" => Value::String("1.0".to_owned()),
        "scope" => Value::Object(Map::new()),
        "issuer" => Value::String(String::new()),
        "audience" => Value::String(String::new()),
        "doc_sha256" => Value::String(String::new()),
        "iat" => Value::Null,
        "ttl_seconds" => Value::Number(Number::from(300)),
        "nonce" => Value::String(String::new()),
        "counter" => Value::Null,
        "cert_chain" => Value::Null,
        _ => Value::Null,
    }
}

/// Fields that can be stripped from the wire format when at their default value
/// (compact mode). Matches Python's _STRIPPABLE_FIELD_DEFAULTS.
pub fn is_strippable_default(field: &str, value: &Value) -> bool {
    match field {
        "vpe_version" => value == "1.0",
        "scope" => value == &Value::Object(Map::new()),
        "issuer" => value == "",
        "audience" => value == "",
        "doc_sha256" => value == "",
        "iat" => value.is_null(),
        "counter" => value.is_null(),
        "cert_chain" => value.is_null(),
        _ => false,
    }
}

/// True if ttl_seconds is at its default (300) or 0 (no expiry).
pub fn is_strippable_ttl(value: &Value) -> bool {
    if let Some(n) = value.as_i64() {
        n == 300 || n == 0
    } else {
        false
    }
}

/// Sort scope keys alphabetically (determinism for signing).
fn sort_scope_keys(value: &Value) -> Value {
    match value {
        Value::Object(scope_map) => {
            let sorted: BTreeMap<&String, &Value> = scope_map.iter().collect();
            let mut new_map = Map::new();
            for (k, v) in sorted {
                new_map.insert(k.clone(), v.clone());
            }
            Value::Object(new_map)
        }
        other => other.clone(),
    }
}

/// Canonical JSON encoding of VPE fields (minus signature) for signing.
///
/// Uses field order from `ENVELOPE_FIELDS`, sorts `scope` keys
/// lexicographically, applies per-field defaults for missing keys, and
/// produces a deterministic byte string.
///
/// Missing cert_chain is omitted from output (None).
/// All other fields are always included, even if their value is null.
///
/// Matches Python's _canonical_json() exactly.
pub fn canonical_json(envelope: &Map<String, Value>) -> Vec<u8> {
    let mut ordered = Map::new();

    for field in ENVELOPE_FIELDS {
        if *field == "signature" {
            continue;
        }

        if *field == "cert_chain" {
            // Omit cert_chain when null/absent (matches Python's conditional)
            match envelope.get(*field) {
                Some(Value::Null) | None => continue,
                Some(v) => {
                    ordered.insert(field.to_string(), v.clone());
                }
            }
            continue;
        }

        let resolved = if *field == "scope" {
            match envelope.get(*field) {
                Some(v) => sort_scope_keys(v),
                None => get_canonical_default(*field),
            }
        } else {
            envelope
                .get(*field)
                .cloned()
                .unwrap_or_else(|| get_canonical_default(*field))
        };

        ordered.insert(field.to_string(), resolved);
    }

    // Compact separators (no spaces) — matches Python's separators=(",", ":")
    serde_json::to_vec(&ordered).expect("canonical_json: serialization should never fail")
}

/// Return a copy of envelope with optional default/empty fields removed
/// (compact mode). Matches Python's _strip_empty_fields().
pub fn strip_empty_fields(envelope: &Map<String, Value>) -> Map<String, Value> {
    let mut result = Map::new();
    for (key, value) in envelope.iter() {
        if key == "ttl_seconds" {
            if is_strippable_ttl(value) {
                continue;
            }
        } else if is_strippable_default(key, value) {
            continue;
        }
        result.insert(key.clone(), value.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_determinism() {
        let mut env = Map::new();
        env.insert("vpe_version".into(), Value::String("1.0".into()));
        env.insert("prompt".into(), Value::String("test".into()));
        env.insert("scope".into(), Value::Object(Map::new()));
        env.insert("issuer".into(), Value::String("me".into()));
        env.insert("audience".into(), Value::String("".into()));
        env.insert("doc_sha256".into(), Value::String("".into()));
        env.insert("iat".into(), Value::Number(Number::from(1000)));
        env.insert("ttl_seconds".into(), Value::Number(Number::from(300)));
        env.insert("nonce".into(), Value::String("abc".into()));
        env.insert("counter".into(), Value::Null);
        env.insert("signature".into(), Value::String("deadbeef".into()));

        let bytes1 = canonical_json(&env);
        let bytes2 = canonical_json(&env);
        assert_eq!(bytes1, bytes2, "canonical JSON must be deterministic");
    }

    #[test]
    fn test_canonical_field_order() {
        let mut env = Map::new();
        env.insert("prompt".into(), Value::String("p".into()));
        env.insert("vpe_version".into(), Value::String("1.0".into()));
        env.insert("nonce".into(), Value::String("n".into()));
        env.insert("ttl_seconds".into(), Value::Number(Number::from(300)));
        let bytes = canonical_json(&env);
        let json_str = String::from_utf8(bytes).unwrap();
        // First field should be "vpe_version", not "prompt"
        assert!(
            json_str.starts_with("{\"vpe_version\""),
            "Expected vpe_version first, got: {json_str}"
        );
    }

    #[test]
    fn test_canonical_scope_sort() {
        let mut scope = Map::new();
        scope.insert("z".into(), Value::Number(Number::from(1)));
        scope.insert("a".into(), Value::Number(Number::from(2)));
        scope.insert("m".into(), Value::Number(Number::from(3)));

        let mut env = Map::new();
        env.insert("vpe_version".into(), Value::String("1.0".into()));
        env.insert("prompt".into(), Value::String("p".into()));
        env.insert("scope".into(), Value::Object(scope));
        env.insert("nonce".into(), Value::String("n".into()));

        let bytes = canonical_json(&env);
        let json_str = String::from_utf8(bytes).unwrap();
        // scope keys should be sorted: a, m, z
        assert!(
            json_str.contains("\"scope\":{\"a\":2,\"m\":3,\"z\":1}"),
            "scope keys not sorted: {json_str}"
        );
    }

    #[test]
    fn test_canonical_cert_chain_omitted_when_null() {
        let mut env = Map::new();
        env.insert("vpe_version".into(), Value::String("1.0".into()));
        env.insert("prompt".into(), Value::String("p".into()));
        env.insert("nonce".into(), Value::String("n".into()));
        env.insert("cert_chain".into(), Value::Null);

        let bytes = canonical_json(&env);
        let json_str = String::from_utf8(bytes).unwrap();
        assert!(
            !json_str.contains("cert_chain"),
            "cert_chain should be omitted when null: {json_str}"
        );

        // When cert_chain is present, it should be included
        let mut env2 = Map::new();
        env2.insert("vpe_version".into(), Value::String("1.0".into()));
        env2.insert("prompt".into(), Value::String("p".into()));
        env2.insert("nonce".into(), Value::String("n".into()));
        env2.insert(
            "cert_chain".into(),
            Value::Array(vec![Value::String("cert1".into())]),
        );
        let bytes2 = canonical_json(&env2);
        let json_str2 = String::from_utf8(bytes2).unwrap();
        assert!(
            json_str2.contains("cert_chain"),
            "cert_chain should be present when non-null: {json_str2}"
        );
    }

    #[test]
    fn test_canonical_defaults() {
        // Minimal envelope — just prompt, vpe_version, nonce
        let mut env = Map::new();
        env.insert("prompt".into(), Value::String("hello".into()));
        env.insert("nonce".into(), Value::String("n1".into()));

        let bytes = canonical_json(&env);
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        let obj = parsed.as_object().unwrap();

        assert_eq!(obj["vpe_version"], "1.0");
        assert_eq!(obj["prompt"], "hello");
        assert_eq!(obj["scope"], Value::Object(Map::new()));
        assert_eq!(obj["issuer"], "");
        assert_eq!(obj["audience"], "");
        assert_eq!(obj["doc_sha256"], "");
        assert_eq!(obj["ttl_seconds"], 300);
        assert_eq!(obj["nonce"], "n1");
        // iat and counter are null — they are included as null in canonical
        assert_eq!(obj["iat"], Value::Null);
        assert_eq!(obj["counter"], Value::Null);
        // cert_chain is omitted
        assert!(!obj.contains_key("cert_chain"));
    }

    #[test]
    fn test_canonical_no_spaces() {
        let mut env = Map::new();
        env.insert("prompt".into(), Value::String("test".into()));
        env.insert("nonce".into(), Value::String("n".into()));
        env.insert("scope".into(), Value::Object(Map::new()));

        let bytes = canonical_json(&env);
        let json_str = String::from_utf8(bytes).unwrap();
        // Should be compact — no spaces after : or ,
        assert!(
            !json_str.contains(": "),
            "Should not have space after colon"
        );
        assert!(
            !json_str.contains(", "),
            "Should not have space after comma"
        );
    }

    #[test]
    fn test_strip_empty_fields() {
        let mut env = Map::new();
        env.insert("vpe_version".into(), Value::String("1.0".into()));
        env.insert("prompt".into(), Value::String("test".into()));
        env.insert("scope".into(), Value::Object(Map::new()));
        env.insert("issuer".into(), Value::String("".into()));
        env.insert("nonce".into(), Value::String("abc".into()));
        env.insert("ttl_seconds".into(), Value::Number(Number::from(300)));
        env.insert("iat".into(), Value::Null);
        env.insert("signature".into(), Value::String("sig123".into()));

        let stripped = strip_empty_fields(&env);
        // These fields should be stripped (at default values)
        assert!(!stripped.contains_key("vpe_version"));
        assert!(!stripped.contains_key("scope"));
        assert!(!stripped.contains_key("issuer"));
        assert!(!stripped.contains_key("ttl_seconds"));
        assert!(!stripped.contains_key("iat"));
        // These should be kept
        assert!(stripped.contains_key("prompt"));
        assert!(stripped.contains_key("nonce"));
        assert!(stripped.contains_key("signature"));
    }

    #[test]
    fn test_canonical_iat_and_counter_included_as_null() {
        // iat and counter should be included as null in canonical JSON
        // even when not present in the envelope
        let mut env = Map::new();
        env.insert("prompt".into(), Value::String("x".into()));
        env.insert("nonce".into(), Value::String("y".into()));

        let bytes = canonical_json(&env);
        let json_str = String::from_utf8(bytes).unwrap();
        assert!(
            json_str.contains("\"iat\":null"),
            "iat should be null: {json_str}"
        );
        assert!(
            json_str.contains("\"counter\":null"),
            "counter should be null: {json_str}"
        );
    }
}
