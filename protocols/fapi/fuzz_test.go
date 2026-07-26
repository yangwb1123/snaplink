package fapi

import (
	"testing"
)

// FuzzExtractJWTAlg verifies that ExtractJWTAlg never panics on arbitrary input.
func FuzzExtractJWTAlg(f *testing.F) {
	seeds := []string{
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
		"eyJhbGciOiJFZERTQSJ9.payload.sig",
		"",
		"...",
		"invalid",
		"a.b.c",
		"eyJhbGciOiJub25lIn0.payload.",
		"!!!.payload.sig",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, compact string) {
		alg := ExtractJWTAlg(compact)
		// Must not panic. Result is either empty or a valid alg string.
		if alg != "" && len(alg) > 20 {
			t.Errorf("unexpectedly long alg: %q", alg)
		}
	})
}
