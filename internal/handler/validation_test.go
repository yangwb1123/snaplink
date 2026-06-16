package handler

import (
	"encoding/base64"
	"errors"
	"testing"
)

// TestIsUnknownTokenErr guards the multi-issuer revoke fan-out's failure
// classification. A migration once stubbed this to `return err != nil`, which
// silently swallowed real infra failures (so partial_revoke_failure never
// fired). This locks the contract: only the conventional not-found shapes are
// benign; every other error is a genuine failure the caller MUST surface.
func TestIsUnknownTokenErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is benign", nil, true},
		{"not found", errors.New("session_issuer: token not found"), true},
		{"unknown", errors.New("unknown token"), true},
		{"no such", errors.New("no such token"), true},
		// The regression that motivated this test: an infra error must NOT be
		// classified as a benign unknown-token outcome.
		{"infra connection refused is a real failure", errors.New("redis: connection refused"), false},
		{"generic error is a real failure", errors.New("boom"), false},
		{"timeout is a real failure", errors.New("context deadline exceeded"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsUnknownTokenErr(c.err); got != c.want {
				t.Errorf("IsUnknownTokenErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestJWSHeaderAlg locks the strict three-segment parse used by the
// server-level alg-allowlist pre-filter: a compact JWS yields its alg; opaque
// or malformed input reports "no JWS alg" so it passes through to the
// session/opaque issuers untouched.
func TestJWSHeaderAlg(t *testing.T) {
	jws := func(headerJSON string) string {
		h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
		return h + ".eyJzdWIiOiJ4In0.sig"
	}
	cases := []struct {
		name    string
		token   string
		wantAlg string
		wantOK  bool
	}{
		{"eddsa header", jws(`{"alg":"EdDSA"}`), "EdDSA", true},
		{"es256 header", jws(`{"alg":"ES256"}`), "ES256", true},
		{"opaque token", "opaque-session-token", "", false},
		{"one dot", "aaa.bbb", "", false},
		{"empty alg", jws(`{"typ":"JWT"}`), "", false},
		{"empty token", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alg, ok := JWSHeaderAlg(c.token)
			if alg != c.wantAlg || ok != c.wantOK {
				t.Errorf("JWSHeaderAlg(%q) = (%q,%v), want (%q,%v)", c.token, alg, ok, c.wantAlg, c.wantOK)
			}
		})
	}
}
