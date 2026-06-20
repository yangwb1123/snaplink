package ssotest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

// flakyRevokeIssuer wraps a TokenIssuer but injects a synthetic
// non-"not found" error on Revoke — simulating an infra failure
// (Redis blip, DB timeout) the dispatcher MUST audit.
type flakyRevokeIssuer struct {
	inner sso.TokenIssuer
}

func (f *flakyRevokeIssuer) Issue(ctx context.Context, sub *sso.Subject, scopes []string) (*sso.Token, error) {
	return f.inner.Issue(ctx, sub, scopes)
}
func (f *flakyRevokeIssuer) Validate(ctx context.Context, tok string) (*sso.TokenClaims, error) {
	return f.inner.Validate(ctx, tok)
}
func (f *flakyRevokeIssuer) Revoke(context.Context, string) error {
	return errors.New("redis: connection refused")
}

// passThroughHinter mirrors TokenFormatHinter delegation so the wrapped
// JWT issuer's shape gate is respected by the dispatcher.
func (f *flakyRevokeIssuer) AcceptsTokenFormat(tok string) bool {
	if h, ok := f.inner.(sso.TokenFormatHinter); ok {
		return h.AcceptsTokenFormat(tok)
	}
	return true
}

func TestPartialRevokeFailure_AuditEmitted(t *testing.T) {
	// The "jwt" issuer owns the token but its Revoke errors with an
	// infra failure (synthetic Redis blip). The session issuer is
	// shape-skipped via TokenFormatHinter. The dispatcher must
	// surface the broken revoke via a partial_revoke_failure audit
	// event so operators know the bearer can still work at JWT
	// validation until natural expiry.
	session := defaultimpl.NewSessionTokenIssuer()
	jwt := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	flaky := &flakyRevokeIssuer{inner: jwt}
	sink := audit.NewMemorySink(64)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithTokenIssuer("session", session),
		sso.WithTokenIssuer("jwt", flaky),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(rec),
	)
	// Mint a JWT-shaped token via the underlying issuer so the
	// dispatcher actually routes Revoke to the flaky wrapper.
	tok, err := jwt.Issue(context.Background(), &sso.Subject{ID: "u-pr"}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/token/revoke-all", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

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
		t.Fatalf("partial_revoke_failure event NOT emitted; events=%+v", events)
	}
	if found.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome = %q, want failure", found.Outcome)
	}
	if got := found.Metadata["failed"]; !strings.Contains(got, "jwt") {
		t.Errorf("metadata.failed = %q, want to contain \"jwt\"", got)
	}
}

func TestPartialRevokeFailure_NotEmittedOnFullSuccess(t *testing.T) {
	// When every issuer revokes cleanly (or returns "not found"),
	// no audit event is emitted — that'd be noise.
	session := defaultimpl.NewSessionTokenIssuer()
	jwt := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	sink := audit.NewMemorySink(64)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithTokenIssuer("session", session),
		sso.WithTokenIssuer("jwt", jwt),
		sso.WithDefaultTokenStrategy("session"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(rec),
	)
	tok, _ := session.Issue(context.Background(), &sso.Subject{ID: "u-pr"}, nil)

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/token/revoke-all", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{})
	for _, e := range events {
		if e.Type == audit.EventPartialRevokeFailure {
			t.Errorf("partial_revoke_failure emitted on clean revoke: %+v", e)
		}
	}
}
