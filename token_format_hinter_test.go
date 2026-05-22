package sso_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// countingValidator wraps a TokenIssuer and counts Validate calls.
// Used to prove that the multi-issuer dispatcher skips issuers
// whose TokenFormatHinter rejects the inbound shape.
type countingValidator struct {
	inner sso.TokenIssuer
	calls int
}

func (c *countingValidator) Issue(ctx context.Context, sub *sso.Subject, scopes []string) (*sso.Token, error) {
	return c.inner.Issue(ctx, sub, scopes)
}
func (c *countingValidator) Validate(ctx context.Context, tok string) (*sso.TokenClaims, error) {
	c.calls++
	return c.inner.Validate(ctx, tok)
}
func (c *countingValidator) Revoke(ctx context.Context, tok string) error {
	return c.inner.Revoke(ctx, tok)
}

// AcceptsTokenFormat delegates to the wrapped issuer if it
// implements the hinter, so the dispatcher's skip path is exercised
// end-to-end and not bypassed by the wrapper losing the interface.
func (c *countingValidator) AcceptsTokenFormat(tok string) bool {
	if h, ok := c.inner.(sso.TokenFormatHinter); ok {
		return h.AcceptsTokenFormat(tok)
	}
	return true
}

func TestTokenFormatHinter_SkipsNonJWTOnEd25519Issuer(t *testing.T) {
	jwt := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	jwtCounter := &countingValidator{inner: jwt}

	session := defaultimpl.NewSessionTokenIssuer()
	sessionCounter := &countingValidator{inner: session}

	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", jwtCounter),
		sso.WithTokenIssuer("session", sessionCounter),
		sso.WithDefaultTokenStrategy("session"),
	)
	// Mint an opaque session token.
	tok, err := session.Issue(context.Background(), &sso.Subject{ID: "u-fmt"}, []string{"read"})
	if err != nil {
		t.Fatalf("session issue: %v", err)
	}
	claims, err := srv.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Subject != "u-fmt" {
		t.Errorf("subject = %q want u-fmt", claims.Subject)
	}

	// The JWT issuer MUST NOT have been called on an opaque token —
	// AcceptsTokenFormat returned false (no two-dot shape), so the
	// dispatcher skipped it entirely.
	if jwtCounter.calls != 0 {
		t.Errorf("Ed25519 issuer Validate called %d times on opaque token; expected 0 (skipped by TokenFormatHinter)", jwtCounter.calls)
	}
	if sessionCounter.calls == 0 {
		t.Errorf("session issuer should have been tried")
	}
}

func TestTokenFormatHinter_EdgeCases(t *testing.T) {
	jwt := defaultimpl.NewEd25519JWTIssuer()
	cases := []struct {
		token string
		want  bool
	}{
		{"", false},               // empty
		{"single-segment", false}, // 0 dots
		{"two.segments", false},   // 1 dot
		{"a.b.c", true},           // 2 dots = JWT shape
		{"a.b.c.d", false},        // 3 dots = not JWT
	}
	for _, tc := range cases {
		got := jwt.AcceptsTokenFormat(tc.token)
		if got != tc.want {
			t.Errorf("AcceptsTokenFormat(%q) = %v want %v", tc.token, got, tc.want)
		}
	}
}

// errIssuer always returns an error from Validate — used to confirm
// that a non-hinter issuer is still tried (legacy behavior preserved).
type errIssuer struct{}

func (errIssuer) Issue(context.Context, *sso.Subject, []string) (*sso.Token, error) {
	return nil, errors.New("unimplemented")
}
func (errIssuer) Validate(context.Context, string) (*sso.TokenClaims, error) {
	return nil, errors.New("always wrong")
}
func (errIssuer) Revoke(context.Context, string) error { return nil }

func TestTokenFormatHinter_NonHinterIssuerStillTried(t *testing.T) {
	// An issuer that doesn't implement TokenFormatHinter MUST be
	// attempted regardless of token shape — preserves legacy
	// behavior so existing custom issuers keep working.
	wrapped := &countingValidator{inner: errIssuer{}}
	srv := sso.NewServer(sso.WithTokenIssuer("legacy", wrapped))
	_, _ = srv.ValidateToken(context.Background(), "opaque-token")
	if wrapped.calls != 1 {
		t.Errorf("legacy issuer Validate called %d times; expected 1", wrapped.calls)
	}
}
