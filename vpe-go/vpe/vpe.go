package vpe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VpeResult is the result of an envelope verification.
type VpeResult struct {
	Valid  bool
	Reason string
}

// NonceStore is an interface for replay-prevention storage.
type NonceStore interface {
	Add(nonce string) bool
}

// GenerateKeyPair generates a new Ed25519 key pair.
// Returns (privateKey, publicKey, error).
func GenerateKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}
	return privateKey, publicKey, nil
}

func makeNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// VpeSign signs a prompt and produces a VPE envelope JSON string.
func VpeSign(
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
) (string, error) {
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
		"vpe_version":  VpeVersion,
		"prompt":       prompt,
		"scope":        scope,
		"issuer":       issuer,
		"audience":     audience,
		"doc_sha256":   docSha256,
		"iat":          time.Now().Unix(),
		"ttl_seconds":  ttlSeconds,
		"nonce":        nonce,
		"counter":      counter,
		"cert_chain":   nil,
		"signature":    "",
	}

	canon, err := canonicalJSON(envelope)
	if err != nil {
		return "", fmt.Errorf("canonical json: %w", err)
	}

	sig := ed25519.Sign(privateKey, canon)
	envelope["signature"] = hex.EncodeToString(sig)

	if compact {
		envelope = stripEmptyFields(envelope)
	}

	result, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	return string(result), nil
}

// VpeVerify verifies a VPE envelope string.
func VpeVerify(
	envelopeStr string,
	publicKey []byte,
	trustAnchor []byte,
	notBefore int64,
	notAfter int64,
	nonceStore NonceStore,
) VpeResult {
	// 1. Parse JSON
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(envelopeStr), &envelope); err != nil {
		return VpeResult{Valid: false, Reason: fmt.Sprintf("invalid_json: %v", err)}
	}
	if envelope == nil {
		return VpeResult{Valid: false, Reason: "invalid_json: not a dict"}
	}

	// 2. Version check
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
	scope, _ := envelope["scope"].(map[string]interface{})
	if scope == nil {
		// Check if it's present but not a dict
		if _, ok := envelope["scope"]; ok {
			// Could be a different type - check specifically
			switch envelope["scope"].(type) {
			case map[string]interface{}:
				// ok
			default:
				return VpeResult{Valid: false, Reason: "scope_not_dict"}
			}
		}
	}

	// 5. Nonce present
	nonce, _ := envelope["nonce"].(string)
	if nonce == "" {
		return VpeResult{Valid: false, Reason: "missing_or_empty_nonce"}
	}

	// 6. Counter type check (if present)
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

	// 8. Nonce replay check
	if nonceStore != nil && ttl > 0 {
		if !nonceStore.Add(nonce) {
			return VpeResult{Valid: false, Reason: "nonce_reused"}
		}
	}

	// 9. Determine effective public key
	var effectivePK []byte
	certChain, _ := envelope["cert_chain"].([]interface{})

	if trustAnchor != nil && certChain != nil && len(certChain) > 0 {
		// Verify cert chain
		chainResult := verifyCertChain(certChain, trustAnchor)
		if !chainResult.Valid {
			return VpeResult{Valid: false, Reason: fmt.Sprintf("cert_chain_failed: %s", chainResult.Reason)}
		}
		effectivePK = chainResult.LeafPublicKey
	} else if publicKey != nil {
		effectivePK = publicKey
	} else {
		return VpeResult{Valid: false, Reason: "no_verification_key: provide public_key or trust_anchor"}
	}

	// 10. Cryptographic signature verification
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return VpeResult{Valid: false, Reason: "invalid_signature_encoding"}
	}

	verifyEnv := deepCopyMap(envelope)
	verifyEnv["signature"] = ""
	canon, err := canonicalJSON(verifyEnv)
	if err != nil {
		return VpeResult{Valid: false, Reason: fmt.Sprintf("canonical_json_error: %v", err)}
	}

	if !ed25519.Verify(ed25519.PublicKey(effectivePK), canon, sigBytes) {
		return VpeResult{Valid: false, Reason: "signature_mismatch"}
	}

	// 11. TTL expiry
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
		// If no iat, treat as no expiry (backward compat)
	}

	// 12. Key time constraints
	if notBefore > 0 && now < notBefore {
		return VpeResult{Valid: false, Reason: "key_not_yet_valid"}
	}
	if notAfter > 0 && now >= notAfter {
		return VpeResult{Valid: false, Reason: "key_expired"}
	}

	return VpeResult{Valid: true, Reason: "ok"}
}

func toInt(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint64:
		return int64(n), true
	}
	return 0, false
}

// verifyCertChainResult holds the result of certificate chain verification.
type verifyCertChainResult struct {
	Valid          bool
	Reason         string
	LeafPublicKey  []byte
}

// verifyCertChain walks a certificate chain root→leaf and verifies every link.
func verifyCertChain(chain []interface{}, trustAnchor []byte) verifyCertChainResult {
	if len(chain) == 0 {
		return verifyCertChainResult{Valid: false, Reason: "empty_cert_chain"}
	}

	// Root cert
	root, ok := chain[0].(map[string]interface{})
	if !ok {
		return verifyCertChainResult{Valid: false, Reason: "invalid_root_cert"}
	}

	rootSubjectPKHex, _ := root["subject_public_key"].(string)
	rootSubjectPK, err := hex.DecodeString(rootSubjectPKHex)
	if err != nil {
		return verifyCertChainResult{Valid: false, Reason: "invalid_root_public_key_hex"}
	}

	if string(rootSubjectPK) != string(trustAnchor) {
		return verifyCertChainResult{Valid: false, Reason: "root_public_key_mismatch_trust_anchor"}
	}

	parentPK := trustAnchor
	for i, certRaw := range chain {
		cert, ok := certRaw.(map[string]interface{})
		if !ok {
			return verifyCertChainResult{Valid: false, Reason: fmt.Sprintf("chain_link_%d_invalid", i)}
		}

		result := verifyCertificate(cert, parentPK)
		if !result.Valid {
			if i == 0 {
				return verifyCertChainResult{Valid: false, Reason: fmt.Sprintf("root_cert_failed: %s", result.Reason)}
			}
			return verifyCertChainResult{Valid: false, Reason: fmt.Sprintf("chain_link_%d_failed: %s", i, result.Reason)}
		}

		// Next parent is this cert's subject
		subjectPKHex, _ := cert["subject_public_key"].(string)
		subjectPK, err := hex.DecodeString(subjectPKHex)
		if err != nil {
			return verifyCertChainResult{Valid: false, Reason: fmt.Sprintf("chain_link_%d_invalid_public_key_hex", i)}
		}
		parentPK = subjectPK
	}

	return verifyCertChainResult{Valid: true, Reason: "ok", LeafPublicKey: parentPK}
}

// verifyCertificate verifies a single certificate's signature against a parent public key.
type certVerificationResult struct {
	Valid  bool
	Reason string
}

func verifyCertificate(cert map[string]interface{}, parentPublicKey []byte) certVerificationResult {
	sigHex, _ := cert["signature"].(string)
	if sigHex == "" {
		return certVerificationResult{Valid: false, Reason: "missing_cert_signature"}
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return certVerificationResult{Valid: false, Reason: "invalid_cert_signature_encoding"}
	}

	verifyCert := deepCopyMap(cert)
	verifyCert["signature"] = ""

	canon := orderedCertJSON(verifyCert)
	if !ed25519.Verify(ed25519.PublicKey(parentPublicKey), canon, sigBytes) {
		return certVerificationResult{Valid: false, Reason: "cert_signature_mismatch"}
	}

	return certVerificationResult{Valid: true, Reason: "ok"}
}

// orderedCertJSON produces the canonical JSON for a certificate.
func orderedCertJSON(cert map[string]interface{}) []byte {
	certFields := []string{
		"cert_version",
		"subject_id",
		"subject_public_key",
		"issuer_id",
		"issuer_public_key",
		"serial",
		"not_before",
		"not_after",
		"metadata",
	}

	var buf strings.Builder
	buf.WriteByte('{')
	for i, field := range certFields {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(field)
		buf.WriteString("\":")
		val, ok := cert[field]
		if !ok {
			val = ""
		}
		valBytes, _ := json.Marshal(val)
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return []byte(buf.String())
}
