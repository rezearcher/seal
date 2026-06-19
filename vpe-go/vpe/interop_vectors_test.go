package vpe

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Interop vector fixture structures.
type VectorParams struct {
	Prompt     string                 `json:"prompt"`
	Scope      map[string]interface{} `json:"scope"`
	Issuer     string                 `json:"issuer"`
	Audience   string                 `json:"audience"`
	DocSha256  string                 `json:"doc_sha256"`
	TtlSeconds int                    `json:"ttl_seconds"`
	Nonce      string                 `json:"nonce"`
	Counter    *int                   `json:"counter"`
	Compact    bool                   `json:"compact"`
}

type Vector struct {
	ID                  string                 `json:"id"`
	Description         string                 `json:"description"`
	SignatureType       string                 `json:"signature_type"`
	Params              VectorParams           `json:"params"`
	ExpectedCanonical   string                 `json:"expected_canonical_hex"`
	ExpectedSignature   string                 `json:"expected_signature_hex"`
	SignedEnvelopeJSON  string                 `json:"signed_envelope_json"`
	ExpectedVerify      bool                   `json:"expected_verify"`
	TamperedEnvelopeJSON *string               `json:"tampered_envelope_json"`
}

type Fixture struct {
	Version       int      `json:"version"`
	PubKeyHex     string   `json:"ed25519_public_key_hex"`
	HmacSecretHex string   `json:"hmac_secret_hex"`
	Vectors       []Vector `json:"vectors"`
}

func loadFixture(t *testing.T) Fixture {
	t.Helper()
	var fixturePath string
	// Try multiple relative paths from the test working directory
	candidates := []string{
		"../../tests/vectors/vpe_vectors.json",
		"../../../tests/vectors/vpe_vectors.json",
		"../tests/vectors/vpe_vectors.json",
	}
	// Also try absolute derived from test source
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "../../tests/vectors/vpe_vectors.json"),
			filepath.Join(cwd, "../../../tests/vectors/vpe_vectors.json"),
		)
	}

	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			fixturePath = p
			break
		}
	}
	if raw == nil {
		t.Fatalf("cannot find vpe_vectors.json (tried %v): %v", candidates, err)
	}

	var f Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture from %s: %v", fixturePath, err)
	}
	return f
}

func TestInteropVectorAll(t *testing.T) {
	f := loadFixture(t)
	pubKey, _ := hex.DecodeString(f.PubKeyHex)
	hmacSecret, _ := hex.DecodeString(f.HmacSecretHex)

	for _, vec := range f.Vectors {
		t.Run(vec.ID, func(t *testing.T) {
			envStr := vec.SignedEnvelopeJSON
			if vec.TamperedEnvelopeJSON != nil {
				envStr = *vec.TamperedEnvelopeJSON
			}

			var result VpeResult
			if vec.SignatureType == "hmac-sha256" {
				result = VpeVerifyHmac(envStr, hmacSecret, 0, 0)
			} else {
				result = VpeVerify(envStr, pubKey, nil, 0, 0, nil)
			}

			if result.Valid != vec.ExpectedVerify {
				t.Errorf("expected valid=%v, got valid=%v reason=%s",
					vec.ExpectedVerify, result.Valid, result.Reason)
			}
		})
	}
}
