package sso_test

// accessors_revocation_test.go proves RevokeToken (interfaces/sso/
// accessors_feature_gates.go) audits a partial cross-issuer revoke failure the
// same way every other revocation call site does. Before this fix, RevokeToken
// — the ONLY caller being the break-glass impersonation cascade
// (interfaces/admin/break_glass_impersonate.go's cascadeRevokeImpersonationTokens)
// — discarded RevokeAcrossIssuers' (revoked, failed) result entirely, so an
// issuer that owned a leaked/expired break-glass bearer but failed to revoke
// it left zero operator-visible trace, unlike /token/revoke-all (see
// test/audit_partial_revoke_test.go, the pattern this test mirrors).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// revocationFlakyIssuer wraps a real TokenIssuer but injects a synthetic
// infra failure on Revoke, mirroring test/audit_partial_revoke_test.go's
// flakyRevokeIssuer (kept package-local since that one lives in the separate
// ssotest module under test/).
type revocationFlakyIssuer struct {
	inner sso.TokenIssuer
}

func (f *revocationFlakyIssuer) Issue(ctx context.Context, sub *sso.Subject, scopes []string) (*sso.Token, error) {
	return f.inner.Issue(ctx, sub, scopes)
}
func (f *revocationFlakyIssuer) Validate(ctx context.Context, tok string) (*sso.TokenClaims, error) {
	return f.inner.Validate(ctx, tok)
}
func (f *revocationFlakyIssuer) Revoke(context.Context, string) error {
	return errors.New("redis: connection refused")
}
func (f *revocationFlakyIssuer) AcceptsTokenFormat(tok string) bool {
	if h, ok := f.inner.(sso.TokenFormatHinter); ok {
		return h.AcceptsTokenFormat(tok)
	}
	return true
}

// TestRevokeToken_AuditsPartialFailure proves the fix: an issuer that owns
// the token but fails to revoke it now surfaces a partial_revoke_failure
// audit event via RevokeToken, exactly like /token/revoke-all.
func TestRevokeToken_AuditsPartialFailure(t *testing.T) {
	jwt := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	flaky := &revocationFlakyIssuer{inner: jwt}
	sink := audit.NewMemorySink(64)
	rec := audit.New(sink)
	s := sso.NewServer(
		sso.WithTokenIssuer("jwt", flaky),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
	)

	tok, err := jwt.Issue(context.Background(), &sso.Subject{ID: "bg-target"}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	s.RevokeToken(context.Background(), tok.AccessToken)

	events, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var found *audit.Event
	for _, e := range events {
		if e.Type == audit.EventPartialRevokeFailure {
			found = e
			break
		}
	}
	if found == nil {
		t.Fatalf("partial_revoke_failure event NOT emitted by RevokeToken; events=%+v", events)
	}
	if found.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome = %q, want failure", found.Outcome)
	}
	if got := found.Metadata["failed"]; got != "jwt" {
		t.Errorf("metadata.failed = %q, want %q", got, "jwt")
	}
}

// TestRevokeToken_NoAuditOnCleanRevoke proves the no-op contract still holds:
// when every issuer revokes cleanly, RevokeToken emits nothing (matching
// auditPartialRevokeFailure's "would be noise" rule).
func TestRevokeToken_NoAuditOnCleanRevoke(t *testing.T) {
	jwt := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	sink := audit.NewMemorySink(64)
	rec := audit.New(sink)
	s := sso.NewServer(
		sso.WithTokenIssuer("jwt", jwt),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
	)

	tok, err := jwt.Issue(context.Background(), &sso.Subject{ID: "bg-target"}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	s.RevokeToken(context.Background(), tok.AccessToken)

	events, _ := sink.Query(context.Background(), audit.Query{})
	for _, e := range events {
		if e.Type == audit.EventPartialRevokeFailure {
			t.Errorf("partial_revoke_failure emitted on clean revoke: %+v", e)
		}
	}
}
