// Package vpe implements the Verified Prompt Envelope (VPE) protocol.
package vpe

import (
	"encoding/json"
	"sort"
	"strings"
)

// EnvelopeFields is the ordered field list for canonical JSON serialization.
// Every field except "signature" appears exactly once, in this order.
var EnvelopeFields = []string{
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
}

// VpeVersion is the current protocol version.
const VpeVersion = "1.0"

// strippableDefaults are fields that can be removed from the wire format
// when they match their default value.
var strippableDefaults = map[string]interface{}{
	"vpe_version": VpeVersion,
	"scope":       map[string]interface{}{},
	"issuer":      "",
	"audience":    "",
	"doc_sha256":  "",
	"iat":         nil,
	"counter":     nil,
	"cert_chain":  nil,
}

const defaultTTL = 300

// canonicalDefaults are the per-field defaults used when reconstructing
// canonical JSON from a (possibly stripped) envelope.
var canonicalDefaults = map[string]interface{}{
	"vpe_version": VpeVersion,
	"scope":       map[string]interface{}{},
	"issuer":      "",
	"audience":    "",
	"doc_sha256":  "",
	"iat":         nil,
	"ttl_seconds": float64(defaultTTL),
	"nonce":       "",
	"counter":     nil,
	"cert_chain":  nil,
}

// isStrippableTTL returns true if ttl is at its default (300) or 0 (no expiry).
func isStrippableTTL(value interface{}) bool {
	switch v := value.(type) {
	case float64:
		return v == float64(defaultTTL) || v == 0
	case int:
		return v == defaultTTL || v == 0
	case int64:
		return v == int64(defaultTTL) || v == 0
	}
	return false
}

// stripEmptyFields returns a copy of envelope with optional default/empty fields removed.
func stripEmptyFields(envelope map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range envelope {
		if key == "ttl_seconds" {
			if isStrippableTTL(value) {
				continue
			}
		} else if defaults, ok := strippableDefaults[key]; ok {
			if valuesEqual(value, defaults) {
				continue
			}
		}
		result[key] = value
	}
	return result
}

// valuesEqual compares two interface{} values for equality, handling nil and maps.
func valuesEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	am, aOk := a.(map[string]interface{})
	bm, bOk := b.(map[string]interface{})
	if aOk && bOk {
		if len(am) != len(bm) {
			return false
		}
		for k, av := range am {
			bv, ok := bm[k]
			if !ok {
				return false
			}
			if av != bv {
				return false
			}
		}
		return true
	}
	return a == b
}

// canonicalJSON produces a deterministic JSON encoding of the envelope for signing.
// It follows the field order in EnvelopeFields, sorts scope keys lexicographically,
// applies per-field defaults for missing keys, and omits cert_chain when nil.
func canonicalJSON(envelope map[string]interface{}) ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('{')

	first := true
	for _, field := range EnvelopeFields {
		if field == "signature" {
			continue
		}

		var value interface{}
		if v, ok := envelope[field]; ok {
			value = v
		} else if def, ok := canonicalDefaults[field]; ok {
			value = def
		}

		// cert_chain is omitted when nil
		if field == "cert_chain" && value == nil {
			continue
		}

		if !first {
			buf.WriteByte(',')
		}
		first = false

		buf.WriteByte('"')
		buf.WriteString(field)
		buf.WriteString("\":")

		if field == "scope" {
			m, ok := value.(map[string]interface{})
			if !ok || m == nil {
				buf.WriteString("{}")
			} else {
				writeSortedMap(&buf, m)
			}
		} else {
			valBytes, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			buf.Write(valBytes)
		}
	}

	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// writeSortedMap writes a JSON object with sorted keys to the buffer.
func writeSortedMap(buf *strings.Builder, m map[string]interface{}) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(k)
		buf.WriteString("\":")
		valBytes, _ := json.Marshal(m[k])
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
}

// deepCopyMap returns a deep copy of a map[string]interface{}.
func deepCopyMap(original map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(original))
	for k, v := range original {
		if m, ok := v.(map[string]interface{}); ok {
			result[k] = deepCopyMap(m)
		} else if s, ok := v.([]interface{}); ok {
			newSlice := make([]interface{}, len(s))
			for i, item := range s {
				if m2, ok2 := item.(map[string]interface{}); ok2 {
					newSlice[i] = deepCopyMap(m2)
				} else {
					newSlice[i] = item
				}
			}
			result[k] = newSlice
		} else {
			result[k] = v
		}
	}
	return result
}
