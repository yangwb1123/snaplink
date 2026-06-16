package handler

import "testing"

// TestAlgAllowed locks the server-level alg-allowlist membership check feeding
// the alg gate: only an exact match against the configured allowlist passes;
// an empty allowlist or empty alg never matches.
func TestAlgAllowed(t *testing.T) {
	allow := []string{"EdDSA", "ES256", "RS256"}
	cases := []struct {
		name  string
		alg   string
		allow []string
		want  bool
	}{
		{"allowed alg", "ES256", allow, true},
		{"first entry", "EdDSA", allow, true},
		{"last entry", "RS256", allow, true},
		{"disallowed alg", "HS256", allow, false},
		{"case-sensitive (no lowercase match)", "es256", allow, false},
		{"empty alg", "", allow, false},
		{"empty allowlist", "ES256", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := AlgAllowed(c.alg, c.allow); got != c.want {
				t.Fatalf("AlgAllowed(%q, %v) = %v, want %v", c.alg, c.allow, got, c.want)
			}
		})
	}
}
