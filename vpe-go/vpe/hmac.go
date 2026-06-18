package vpe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// VpeSignHmac signs a prompt with HMAC-SHA256 for internal/low-security contexts.
func VpeSignHmac(
	prompt string,
	scope map[string]interface{},
	issuer string,
	audience string,
	docSha256 string,
	ttlSeconds int,
	nonce string,
	counter *int,
	sharedSecret []byte,
	compact bool,
) (string, error) {
	if len(sharedSecret) == 0 {
		return "", fmt.Errorf("shared_secret must be non-empty bytes")
	}
	if scope == nil {
		scope = map[string]interface{}{}
	}
	if nonce == "" {
		nonce = makeNonce()
	}
	if ttlSeconds == 0 {
		ttlSeconds = defaultTTL
	}

	envelope := map[string]interface{}{
		"vpe_version": VpeVersion,
		"prompt":      prompt,
		"scope":       scope,
		"issuer":      issuer,
		"audience":    audience,
		"doc_sha256":  docSha256,
		"iat":         time.Now().Unix(),
		"ttl_seconds": ttlSeconds,
		"nonce":       nonce,
		"counter":     counter,
		"signature":   "",
	}

	canon, err := canonicalJSON(envelope)
	if err != nil {
		return "", fmt.Errorf("canonical json: %w", err)
	}

	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(canon)
	sig := hexEncode(mac.Sum(nil))
	envelope["signature"] = sig

	if compact {
		envelope = stripEmptyFields(envelope)
	}

	result, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	return string(result), nil
}

// VpeVerifyHmac verifies a HMAC-SHA256 signed VPE envelope.
func VpeVerifyHmac(
	envelopeStr string,
	sharedSecret []byte,
	notBefore int64,
	notAfter int64,
) VpeResult {
	// 1. Parse
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(envelopeStr), &envelope); err != nil {
		return VpeResult{Valid: false, Reason: fmt.Sprintf("invalid_json: %v", err)}
	}
	if envelope == nil {
		return VpeResult{Valid: false, Reason: "invalid_json: not a dict"}
	}

	// 2. Version
	version, _ := envelope["vpe_version"].(string)
	if version == "" {
		version = VpeVersion
	}
	if version != VpeVersion {
		return VpeResult{Valid: false, Reason: fmt.Sprintf("unsupported_version: %s", version)}
	}

	// 3. Signature present
	sigHex, _ := envelope["signature"].(string)
	if sigHex == "" {
		return VpeResult{Valid: false, Reason: "missing_signature"}
	}

	// 4. Scope is dict
	if _, ok := envelope["scope"]; ok {
		switch envelope["scope"].(type) {
		case map[string]interface{}:
			// ok
		default:
			return VpeResult{Valid: false, Reason: "scope_not_dict"}
		}
	}

	// 5. Nonce present
	nonce, _ := envelope["nonce"].(string)
	if nonce == "" {
		return VpeResult{Valid: false, Reason: "missing_or_empty_nonce"}
	}

	// 6. Counter type check
	if counter, ok := envelope["counter"]; ok && counter != nil {
		switch counter.(type) {
		case float64, int, int64:
			// ok
		default:
			return VpeResult{Valid: false, Reason: "counter_not_integer"}
		}
	}

	// 7. TTL type check
	ttlVal, ok := envelope["ttl_seconds"]
	if !ok {
		ttlVal = float64(0)
	}
	ttl, ok := toInt(ttlVal)
	if !ok {
		return VpeResult{Valid: false, Reason: "ttl_not_integer"}
	}

	// 8. HMAC-SHA256 signature verification
	verifyEnv := deepCopyMap(envelope)
	verifyEnv["signature"] = ""
	canon, err := canonicalJSON(verifyEnv)
	if err != nil {
		return VpeResult{Valid: false, Reason: fmt.Sprintf("canonical_json_error: %v", err)}
	}

	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(canon)
	expected := hexEncode(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHex), []byte(expected)) {
		return VpeResult{Valid: false, Reason: "signature_mismatch"}
	}

	// 9. TTL expiry
	now := time.Now().Unix()
	if ttl > 0 {
		iatVal, iatOk := envelope["iat"]
		if iatOk && iatVal != nil {
			iat, iatOk2 := toInt(iatVal)
			if !iatOk2 {
				return VpeResult{Valid: false, Reason: "iat_not_integer"}
			}
			if now-iat > int64(ttl) {
				return VpeResult{Valid: false, Reason: "envelope_expired"}
			}
		}
	}

	// 10. Key time constraints
	if notBefore > 0 && now < notBefore {
		return VpeResult{Valid: false, Reason: "key_not_yet_valid"}
	}
	if notAfter > 0 && now >= notAfter {
		return VpeResult{Valid: false, Reason: "key_expired"}
	}

	return VpeResult{Valid: true, Reason: "ok"}
}

// hexEncode is a helper to encode bytes to hex string.
func hexEncode(data []byte) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, len(data)*2)
	for i, v := range data {
		b[i*2] = hexChars[v>>4]
		b[i*2+1] = hexChars[v&0x0f]
	}
	return string(b)
}
