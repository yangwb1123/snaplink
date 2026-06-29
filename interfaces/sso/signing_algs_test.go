package sso

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// fakeJWTIssuer is a minimal in-test TokenIssuer that accepts any
// 3-segment token and returns fixed claims — enough to prove the
// Server-level alg gate fires BEFORE the issuer runs. No mocks of
// storage are involved (AGENTS.md §8); this is a test-local SPI stub.
type fakeJWTIssuer struct{ validated bool }

func (f *fakeJWTIssuer) Issue(context.Context, *Subject, []string) (*Token, error) {
	return nil, errors.New("unused")
}
func (f *fakeJWTIssuer) Validate(_ context.Context, _ string) (*TokenClaims, error) {
	f.validated = true
	return &TokenClaims{Subject: "ok"}, nil
}
func (f *fakeJWTIssuer) Revoke(context.Context, string) error { return nil }

func mkJWS(t *testing.T, alg string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"at+jwt"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"ok"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return hdr + "." + body + "." + sig
}

func TestJWSHeaderAlg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		token   string
		wantAlg string
		wantOK  bool
	}{
		{mkJWS(t, "ES256"), "ES256", true},
		{mkJWS(t, "EdDSA"), "EdDSA", true},
		{mkJWS(t, "RS256"), "RS256", true},
		{mkJWS(t, "PS256"), "PS256", true},
		{"opaque-session-token", "", false},
		{"two.segments", "", false},
		{"a.b.c.d", "", false},
	}
	for _, c := range cases {
		alg, ok := jwsHeaderAlg(c.token)
		if ok != c.wantOK || alg != c.wantAlg {
			t.Errorf("jwsHeaderAlg(%q) = (%q,%v), want (%q,%v)", c.token, alg, ok, c.wantAlg, c.wantOK)
		}
	}
}

func TestSupportedSigningAlgsGate(t *testing.T) {
	t.Parallel()
	// ES256 allowed, EdDSA not.
	fake := &fakeJWTIssuer{}
	s := NewServer(
		WithTokenIssuer("jwt", fake),
		WithSupportedSigningAlgs("ES256"),
	)

	// Disallowed alg must be rejected BEFORE the issuer's Validate runs.
	if _, _, err := s.validateAnyToken(context.Background(), mkJWS(t, "EdDSA")); err == nil {
		t.Error("EdDSA token accepted despite ES256-only allowlist")
	}
	if fake.validated {
		t.Error("issuer.Validate ran for a disallowed alg (gate did not pre-filter)")
	}

	// Allowed alg passes the gate and reaches the issuer.
	fake.validated = false
	if _, _, err := s.validateAnyToken(context.Background(), mkJWS(t, "ES256")); err != nil {
		t.Errorf("ES256 token rejected: %v", err)
	}
	if !fake.validated {
		t.Error("issuer.Validate did not run for an allowed alg")
	}

	// Opaque (non-JWS) tokens are not gated — they reach the issuer.
	fake.validated = false
	if _, _, err := s.validateAnyToken(context.Background(), "opaque-token"); err != nil {
		t.Errorf("opaque token rejected by alg gate: %v", err)
	}
	if !fake.validated {
		t.Error("opaque token was incorrectly gated")
	}
}

// TestSupportedSigningAlgsGate_RSA proves the gate admits the RSA algs
// when allowlisted (RS256/PS256) and pre-filters them when not.
func TestSupportedSigningAlgsGate_RSA(t *testing.T) {
	t.Parallel()
	fake := &fakeJWTIssuer{}
	s := NewServer(
		WithTokenIssuer("jwt", fake),
		WithSupportedSigningAlgs("RS256", "PS256"),
	)
	for _, alg := range []string{"RS256", "PS256"} {
		fake.validated = false
		if _, _, err := s.validateAnyToken(context.Background(), mkJWS(t, alg)); err != nil {
			t.Errorf("%s token rejected despite allowlist: %v", alg, err)
		}
		if !fake.validated {
			t.Errorf("%s: issuer.Validate did not run for an allowed alg", alg)
		}
	}
	// ES256 not in the allowlist → gated out before the issuer.
	fake.validated = false
	if _, _, err := s.validateAnyToken(context.Background(), mkJWS(t, "ES256")); err == nil {
		t.Error("ES256 accepted despite RS256/PS256-only allowlist")
	}
	if fake.validated {
		t.Error("issuer.Validate ran for a disallowed alg")
	}
}
