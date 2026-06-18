package vpe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Canonical JSON tests
// ---------------------------------------------------------------------------

func TestCanonicalJSONDeterminism(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "do something",
		"scope":       map[string]interface{}{"read": "docs", "write": "code"},
		"issuer":      "alice",
		"audience":    "bob",
		"doc_sha256":  "abc123",
		"iat":         float64(1000),
		"ttl_seconds": float64(300),
		"nonce":       "deadbeef00112233",
		"counter":     nil,
		"signature":   "should_be_excluded",
	}

	b1, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}
	b2, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if string(b1) != string(b2) {
		t.Fatalf("canonical JSON not deterministic:\n%q\n%q", b1, b2)
	}
}

func TestCanonicalJSONFieldOrder(t *testing.T) {
	env := map[string]interface{}{
		"prompt":      "hello",
		"nonce":       "x",
		"vpe_version": "1.0",
		"scope":       map[string]interface{}{},
		"signature":   "x",
	}

	b, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}
	str := string(b)

	// vpe_version must be first
	if !strings.HasPrefix(str, `{"vpe_version":`) {
		t.Fatalf("expected vpe_version first, got: %s", str)
	}

	// Check order of key fields
	keys := []string{"vpe_version", "prompt", "scope", "nonce"}
	prevIdx := -1
	for _, k := range keys {
		idx := strings.Index(str, `"`+k+`"`)
		if idx <= prevIdx {
			t.Fatalf("field %s out of order in: %s", k, str)
		}
		prevIdx = idx
	}

	// signature must NOT be present
	if strings.Contains(str, "signature") {
		t.Fatalf("signature should not be in canonical JSON: %s", str)
	}
}

func TestCanonicalJSONScopeSorted(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "test",
		"scope": map[string]interface{}{
			"zebra": "z",
			"alpha": "a",
			"bravo": "b",
		},
		"nonce": "testnonce",
	}

	b, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	// Check alpha comes before bravo comes before zebra
	str := string(b)
	alphaIdx := strings.Index(str, `"alpha"`)
	bravoIdx := strings.Index(str, `"bravo"`)
	zebraIdx := strings.Index(str, `"zebra"`)

	if alphaIdx < 0 || bravoIdx < 0 || zebraIdx < 0 {
		t.Fatalf("missing scope keys in: %s", str)
	}
	if !(alphaIdx < bravoIdx && bravoIdx < zebraIdx) {
		t.Fatalf("scope keys not sorted: %s", str)
	}
}

func TestCanonicalJSONOmitCertChain(t *testing.T) {
	// cert_chain should be omitted when nil
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "test",
		"cert_chain":  nil,
		"nonce":       "x",
	}

	b, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if strings.Contains(string(b), "cert_chain") {
		t.Fatalf("expected cert_chain omitted when nil, got: %s", b)
	}
}

func TestCanonicalJSONIncludesCertChain(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "test",
		"cert_chain":  []interface{}{"cert1", "cert2"},
		"nonce":       "x",
	}

	b, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if !strings.Contains(string(b), "cert_chain") {
		t.Fatalf("expected cert_chain present, got: %s", b)
	}
}

func TestCanonicalJSONStrippedRoundTrip(t *testing.T) {
	// Full envelope
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "do something",
		"scope":       map[string]interface{}{},
		"issuer":      "",
		"audience":    "",
		"doc_sha256":  "",
		"iat":         float64(2000),
		"ttl_seconds": float64(300),
		"nonce":       "abc123",
		"counter":     nil,
		"cert_chain":  nil,
		"signature":   "sig",
	}

	fullJSON, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	// Stripped envelope (missing default fields)
	strippedEnv := map[string]interface{}{
		"prompt": "do something",
		"iat":    float64(2000),
		"nonce":  "abc123",
		"signature": "sig",
	}

	strippedJSON, err := canonicalJSON(strippedEnv)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if string(fullJSON) != string(strippedJSON) {
		t.Fatalf("canonical JSON mismatch between full and stripped:\nfull:     %s\nstripped: %s", fullJSON, strippedJSON)
	}
}

// ---------------------------------------------------------------------------
// Key generation tests
// ---------------------------------------------------------------------------

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}
}

// ---------------------------------------------------------------------------
// Sign and verify round-trip tests
// ---------------------------------------------------------------------------

func TestVpeSignVerifyRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("hello world", nil, "issuer", "audience",
		"", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	result := VpeVerify(envStr, pub, nil, 0, 0, nil)
	if !result.Valid {
		t.Fatalf("VpeVerify failed: %s", result.Reason)
	}
}

func TestVpeSignVerifyWithAllFields(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	counter := 42
	scope := map[string]interface{}{
		"read":  "/data",
		"write": "/tmp",
	}
	envStr, err := VpeSign(
		"do the thing",
		scope,
		"alice",
		"bob-agent",
		"sha256hash",
		600,
		"customnonce123",
		&counter,
		priv,
		false,
	)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	result := VpeVerify(envStr, pub, nil, 0, 0, nil)
	if !result.Valid {
		t.Fatalf("VpeVerify failed: %s", result.Reason)
	}

	// Verify fields survive round-trip
	var env map[string]interface{}
	json.Unmarshal([]byte(envStr), &env)
	if env["prompt"] != "do the thing" {
		t.Fatalf("prompt mismatch: %v", env["prompt"])
	}
	if env["issuer"] != "alice" {
		t.Fatalf("issuer mismatch: %v", env["issuer"])
	}
	if env["audience"] != "bob-agent" {
		t.Fatalf("audience mismatch: %v", env["audience"])
	}
	if env["doc_sha256"] != "sha256hash" {
		t.Fatalf("doc_sha256 mismatch: %v", env["doc_sha256"])
	}
	if env["nonce"] != "customnonce123" {
		t.Fatalf("nonce mismatch: %v", env["nonce"])
	}
	// Check counter
	counterJSON, _ := env["counter"].(float64)
	if int(counterJSON) != 42 {
		t.Fatalf("counter mismatch: %v", env["counter"])
	}
}

func TestVpeSignWrongKeyFails(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	_, wrongPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	result := VpeVerify(envStr, wrongPub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail with wrong key")
	}
	if !strings.Contains(result.Reason, "signature_mismatch") {
		t.Fatalf("expected signature_mismatch, got: %s", result.Reason)
	}
}

func TestVpeSignTamperPrompt(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("original prompt", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// Tamper: change "original prompt" to "tampered prompt"
	tampered := strings.Replace(envStr, "original prompt", "tampered prompt", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered prompt")
	}
}

func TestVpeSignTamperScope(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", map[string]interface{}{"role": "user"}, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// Tamper scope role value
	tampered := strings.Replace(envStr, "user", "admin", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered scope")
	}
}

func TestVpeSignTamperIssuer(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "original_issuer", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	tampered := strings.Replace(envStr, "original_issuer", "evil_issuer", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered issuer")
	}
}

func TestVpeSignTamperAudience(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "original_audience", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	tampered := strings.Replace(envStr, "original_audience", "evil_audience", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered audience")
	}
}

func TestVpeSignTamperDocSha256(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "original_hash", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	tampered := strings.Replace(envStr, "original_hash", "tampered_hash", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered doc_sha256")
	}
}

func TestVpeSignTamperNonce(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "original_nonce", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	tampered := strings.Replace(envStr, "original_nonce", "tampered_nonce", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered nonce")
	}
}

func TestVpeSignTamperTTL(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// Tamper ttl_seconds value
	tampered := strings.Replace(envStr, "300", "999999", 1)
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered ttl_seconds")
	}
}

func TestVpeSignTamperSignature(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// Modify the signature hex string (flip a bit)
	tampered := envStr[:len(envStr)-5] + "00000" + "}"
	result := VpeVerify(tampered, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered signature")
	}
}

func TestVpeVerifyMissingSignature(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "test",
		"nonce":       "abc",
	}
	b, _ := json.Marshal(env)

	result := VpeVerify(string(b), []byte("key"), nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on missing signature")
	}
	if !strings.Contains(result.Reason, "missing_signature") {
		t.Fatalf("expected missing_signature, got: %s", result.Reason)
	}
}

func TestVpeVerifyInvalidJSON(t *testing.T) {
	result := VpeVerify("not-json", []byte("key"), nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on invalid JSON")
	}
	if !strings.Contains(result.Reason, "invalid_json") {
		t.Fatalf("expected invalid_json, got: %s", result.Reason)
	}
}

func TestVpeVerifyUnsupportedVersion(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "0.5",
		"prompt":      "test",
		"nonce":       "abc",
		"signature":   "deadbeef",
	}
	b, _ := json.Marshal(env)

	result := VpeVerify(string(b), []byte("key"), nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on unsupported version")
	}
	if !strings.Contains(result.Reason, "unsupported_version") {
		t.Fatalf("expected unsupported_version, got: %s", result.Reason)
	}
}

func TestVpeVerifyNonceReplay(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	store := &memNonceStore{seen: make(map[string]bool)}
	envStr, err := VpeSign("test", nil, "", "", "", 300, "fixed-nonce-for-test", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// First use should pass
	result := VpeVerify(envStr, pub, nil, 0, 0, store)
	if !result.Valid {
		t.Fatalf("first verify should pass: %s", result.Reason)
	}

	// Second use with same nonce should fail
	result = VpeVerify(envStr, pub, nil, 0, 0, store)
	if result.Valid {
		t.Fatal("expected verification to fail on nonce replay")
	}
	if !strings.Contains(result.Reason, "nonce_reused") {
		t.Fatalf("expected nonce_reused, got: %s", result.Reason)
	}
}

func TestVpeVerifyExpired(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create an envelope with TTL=1 second, then wait
	envStr, err := VpeSign("test", nil, "", "", "", 1, "expired-nonce", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	result := VpeVerify(envStr, pub, nil, 0, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on expired envelope")
	}
	if !strings.Contains(result.Reason, "envelope_expired") {
		t.Fatalf("expected envelope_expired, got: %s", result.Reason)
	}
}

func TestVpeVerifyKeyNotYetValid(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// notBefore far in the future
	future := time.Now().Unix() + 86400
	result := VpeVerify(envStr, pub, nil, future, 0, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on key not yet valid")
	}
	if !strings.Contains(result.Reason, "key_not_yet_valid") {
		t.Fatalf("expected key_not_yet_valid, got: %s", result.Reason)
	}
}

func TestVpeVerifyKeyExpired(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	// notAfter in the past
	past := time.Now().Unix() - 1
	result := VpeVerify(envStr, pub, nil, 0, past, nil)
	if result.Valid {
		t.Fatal("expected verification to fail on key expired")
	}
	if !strings.Contains(result.Reason, "key_expired") {
		t.Fatalf("expected key_expired, got: %s", result.Reason)
	}
}

func TestVpeSignVerifiesCompactMode(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Sign with compact = true
	envStr, err := VpeSign("compact test", nil, "", "", "", 300, "compactnonce", nil, priv, true)
	if err != nil {
		t.Fatalf("VpeSign compact failed: %v", err)
	}

	// Compact mode should drop many default fields
	if strings.Contains(envStr, "vpe_version") {
		// vpe_version might be kept if non-default, but let's check esssential fields exist
	}

	var env map[string]interface{}
	json.Unmarshal([]byte(envStr), &env)

	// prompt, nonce, signature, iat must be present
	if _, ok := env["prompt"]; !ok {
		t.Fatal("compact envelope missing prompt")
	}
	if _, ok := env["nonce"]; !ok {
		t.Fatal("compact envelope missing nonce")
	}
	if _, ok := env["signature"]; !ok {
		t.Fatal("compact envelope missing signature")
	}
	if _, ok := env["iat"]; !ok {
		t.Fatal("compact envelope missing iat")
	}

	// Default fields like scope (empty), issuer, audience should be stripped
	val, ok := env["issuer"]
	if ok && val == "" {
		t.Fatal("compact envelope should have stripped empty issuer")
	}

	// Verify compact envelope still verifies
	result := VpeVerify(envStr, pub, nil, 0, 0, nil)
	if !result.Valid {
		t.Fatalf("compact envelope verification failed: %s", result.Reason)
	}
}

func TestVpeSignAutoGeneratesNonce(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	var env map[string]interface{}
	json.Unmarshal([]byte(envStr), &env)

	nonce, _ := env["nonce"].(string)
	if len(nonce) != 32 {
		t.Fatalf("expected auto-generated nonce of length 32, got %q (len=%d)", nonce, len(nonce))
	}
	// Verify it's hex
	_, err = hex.DecodeString(nonce)
	if err != nil {
		t.Fatalf("nonce is not valid hex: %v", err)
	}
}

func TestVpeSignDefaultsScope(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// nil scope should become empty map
	envStr, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	var env map[string]interface{}
	json.Unmarshal([]byte(envStr), &env)

	scope, ok := env["scope"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected scope to be a map, got %T", env["scope"])
	}
	if len(scope) != 0 {
		t.Fatalf("expected empty scope, got %v", scope)
	}
}

// ---------------------------------------------------------------------------
// HMAC tests
// ---------------------------------------------------------------------------

func TestVpeSignHmacVerifyRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	envStr, err := VpeSignHmac("hmac test", nil, "", "", "", 300, "", nil, secret, false)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	result := VpeVerifyHmac(envStr, secret, 0, 0)
	if !result.Valid {
		t.Fatalf("VpeVerifyHmac failed: %s", result.Reason)
	}
}

func TestVpeSignHmacWrongSecretFails(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	envStr, err := VpeSignHmac("hmac test", nil, "", "", "", 300, "", nil, secret, false)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	wrongSecret := make([]byte, 32)
	rand.Read(wrongSecret)

	result := VpeVerifyHmac(envStr, wrongSecret, 0, 0)
	if result.Valid {
		t.Fatal("expected HMAC verification to fail with wrong secret")
	}
	if !strings.Contains(result.Reason, "signature_mismatch") {
		t.Fatalf("expected signature_mismatch, got: %s", result.Reason)
	}
}

func TestVpeSignHmacTamperedPrompt(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	envStr, err := VpeSignHmac("original", nil, "", "", "", 300, "", nil, secret, false)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	tampered := strings.Replace(envStr, "original", "tampered", 1)
	result := VpeVerifyHmac(tampered, secret, 0, 0)
	if result.Valid {
		t.Fatal("expected verification to fail on tampered prompt")
	}
}

func TestVpeSignHmacCompact(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	envStr, err := VpeSignHmac("compact hmac", nil, "", "", "", 300, "hmac-compact-nonce", nil, secret, true)
	if err != nil {
		t.Fatalf("VpeSignHmac compact failed: %v", err)
	}

	result := VpeVerifyHmac(envStr, secret, 0, 0)
	if !result.Valid {
		t.Fatalf("compact HMAC verification failed: %s", result.Reason)
	}
}

func TestVpeSignHmacEmptySecret(t *testing.T) {
	_, err := VpeSignHmac("test", nil, "", "", "", 300, "", nil, []byte{}, false)
	if err == nil {
		t.Fatal("expected error with empty shared secret")
	}
}

func TestVpeSignHmacAllFields(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	counter := 7
	scope := map[string]interface{}{"read": "all"}
	envStr, err := VpeSignHmac(
		"full hmac", scope, "hmac-issuer", "hmac-audience",
		"hmac-doc", 500, "hmac-nonce-123", &counter, secret, false,
	)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	result := VpeVerifyHmac(envStr, secret, 0, 0)
	if !result.Valid {
		t.Fatalf("HMAC verification failed: %s", result.Reason)
	}
}

func TestVpeSignHmacExpired(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	envStr, err := VpeSignHmac("expiring", nil, "", "", "", 1, "hmac-expire-nonce", nil, secret, false)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	result := VpeVerifyHmac(envStr, secret, 0, 0)
	if result.Valid {
		t.Fatal("expected expired HMAC to fail")
	}
	if !strings.Contains(result.Reason, "envelope_expired") {
		t.Fatalf("expected envelope_expired, got: %s", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Helper: in-memory nonce store for tests
// ---------------------------------------------------------------------------

type memNonceStore struct {
	seen map[string]bool
}

func (s *memNonceStore) Add(nonce string) bool {
	if s.seen[nonce] {
		return false
	}
	s.seen[nonce] = true
	return true
}

// ---------------------------------------------------------------------------
// Cross-protocol: VpeSign envelope verified by VpeVerifyHmac should fail
// ---------------------------------------------------------------------------

func TestCrossProtocolFails(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	_ = pub // used for Ed25519 verify below
	secret := make([]byte, 32)
	rand.Read(secret)

	// Sign with Ed25519, verify with HMAC (should fail)
	envStr, err := VpeSign("cross-protocol", nil, "", "", "", 300, "cross-nonce", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	result := VpeVerifyHmac(envStr, secret, 0, 0)
	if result.Valid {
		t.Fatal("expected HMAC verify of Ed25519-signed envelope to fail")
	}
	if !strings.Contains(result.Reason, "signature_mismatch") {
		t.Fatalf("expected signature_mismatch, got: %s", result.Reason)
	}

	// Sign with HMAC, verify with Ed25519 (should fail)
	envStr2, err := VpeSignHmac("cross-protocol-2", nil, "", "", "", 300, "cross-nonce-2", nil, secret, false)
	if err != nil {
		t.Fatalf("VpeSignHmac failed: %v", err)
	}

	result2 := VpeVerify(envStr2, pub, nil, 0, 0, nil)
	if result2.Valid {
		t.Fatal("expected Ed25519 verify of HMAC-signed envelope to fail")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestCanonicalJSONEmptyScope(t *testing.T) {
	env := map[string]interface{}{
		"vpe_version": "1.0",
		"prompt":      "test",
		"scope":       map[string]interface{}{},
		"nonce":       "x",
	}

	b, err := canonicalJSON(env)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if !strings.Contains(string(b), `"scope":{}`) {
		t.Fatalf("expected empty scope in canonical JSON, got: %s", b)
	}
}

func TestVpeSignEmptyEnvelope(t *testing.T) {
	// Minimal signing with only required fields
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	envStr, err := VpeSign("", nil, "", "", "", 0, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	result := VpeVerify(envStr, pub, nil, 0, 0, nil)
	if !result.Valid {
		t.Fatalf("empty envelope verification failed: %s", result.Reason)
	}
}

func TestTwoSignaturesDifferent(t *testing.T) {
	// Same parameters should produce different nonces -> different envelopes -> different signatures
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	env1, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	env2, err := VpeSign("test", nil, "", "", "", 300, "", nil, priv, false)
	if err != nil {
		t.Fatalf("VpeSign failed: %v", err)
	}

	if env1 == env2 {
		t.Fatal("expected two signatures to be different due to auto-generated nonces")
	}
}
