package grpcadmin

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
)

// TestTokenAdminService_NilDepsPreconditionFails proves ListSessions and
// IssueTempToken respond Unimplemented (documented "optional dependency
// absent" behavior) rather than panicking, and that Revoke on a session_id
// still needs a SessionManager even though it doesn't hard-require one at
// construction time.
func TestTokenAdminService_NilDepsPreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewTokenAdminService(TokenAdminConfig{})
	ctx := context.Background()

	_, err := svc.ListSessions(ctx, &adminv1.ListSessionsRequest{})
	requireCode(t, err, codes.Unimplemented)
	_, err = svc.IssueTempToken(ctx, &adminv1.IssueTempTokenRequest{UserId: "u1"})
	requireCode(t, err, codes.Unimplemented)
	_, err = svc.Revoke(ctx, &adminv1.RevokeRequest{SessionId: "s1"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestTokenAdminService_InvalidArgument covers the guard clauses. The
// tempStore is wired here so IssueTempToken's own guard clause is reached at
// all (a nil tempStore short-circuits to Unimplemented before the argument
// check, per TestTokenAdminService_NilDepsPreconditionFails above).
func TestTokenAdminService_InvalidArgument(t *testing.T) {
	t.Parallel()
	svc := NewTokenAdminService(TokenAdminConfig{TempStore: authenticators.NewMemoryTempTokenStore()})
	ctx := context.Background()

	_, err := svc.Revoke(ctx, &adminv1.RevokeRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.IssueTempToken(ctx, &adminv1.IssueTempTokenRequest{})
	requireCode(t, err, codes.InvalidArgument)
}

// TestTokenAdminService_ListAndRevokeSessions drives ListSessions + Revoke
// (by session_id) against a real MemorySessionManager.
func TestTokenAdminService_ListAndRevokeSessions(t *testing.T) {
	t.Parallel()
	sessions := defaultimpl.NewMemorySessionManager()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	svc := NewTokenAdminService(TokenAdminConfig{Sessions: sessions, Recorder: rec})
	ctx := context.Background()

	s1, err := sessions.Create(ctx, "alice")
	requireOK(t, err, "sessions.Create alice")
	_, err = sessions.Create(ctx, "bob")
	requireOK(t, err, "sessions.Create bob")

	all, err := svc.ListSessions(ctx, &adminv1.ListSessionsRequest{})
	requireOK(t, err, "ListSessions all")
	if len(all.Sessions) != 2 {
		t.Errorf("ListSessions all len = %d", len(all.Sessions))
	}

	filtered, err := svc.ListSessions(ctx, &adminv1.ListSessionsRequest{UserId: "alice"})
	requireOK(t, err, "ListSessions filtered")
	if len(filtered.Sessions) != 1 || filtered.Sessions[0].Id != s1.ID {
		t.Errorf("ListSessions filtered = %+v", filtered.Sessions)
	}

	resp, err := svc.Revoke(ctx, &adminv1.RevokeRequest{SessionId: s1.ID})
	requireOK(t, err, "Revoke by session_id")
	if len(resp.Revoked) != 1 || resp.Revoked[0] != sso.RevokedSession {
		t.Errorf("Revoke response = %+v", resp.Revoked)
	}
	remaining, _ := svc.ListSessions(ctx, &adminv1.ListSessionsRequest{})
	if len(remaining.Sessions) != 1 {
		t.Errorf("expected 1 remaining session after revoke, got %d", len(remaining.Sessions))
	}

	events, err := sink.Query(ctx, audit.Query{Type: audit.EventAdminTokenRevoked})
	requireOK(t, err, "sink.Query")
	if len(events) != 1 {
		t.Errorf("expected 1 revoke audit event, got %d", len(events))
	}
}

// TestTokenAdminService_RevokeTokenLocalFallback proves the local-only
// issuer fan-out: with no revokeAcrossIssuers wired, Revoke tries every
// configured sso.TokenIssuer and succeeds when one of them recognizes the
// token, using a real Ed25519JWTIssuer (no mocks) rather than a stub.
func TestTokenAdminService_RevokeTokenLocalFallback(t *testing.T) {
	t.Parallel()
	issuer := defaultimpl.NewEd25519JWTIssuer()
	tok, err := issuer.Issue(context.Background(), &sso.Subject{ID: "u1", ClientID: "web"}, []string{"openid"})
	requireOK(t, err, "Issue")

	svc := NewTokenAdminService(TokenAdminConfig{Issuers: map[string]sso.TokenIssuer{"default": issuer}})
	ctx := context.Background()

	resp, err := svc.Revoke(ctx, &adminv1.RevokeRequest{Token: tok.AccessToken})
	requireOK(t, err, "Revoke recognized token")
	if len(resp.Revoked) != 1 || resp.Revoked[0] != sso.RevokedToken {
		t.Errorf("Revoke response = %+v", resp.Revoked)
	}

	_, err = svc.Revoke(ctx, &adminv1.RevokeRequest{Token: "not-a-real-token"})
	requireCode(t, err, codes.NotFound)
}

// TestTokenAdminService_RevokeAcrossIssuersPreferred proves that when the
// cross-replica-publishing seam is wired, Revoke uses it INSTEAD of the
// local issuer fan-out — the production wiring
// (sso.Server.RevokeAcrossIssuers) is too heavyweight to stand up in a unit
// test, so this closure exercises the exact call contract
// (func(ctx, token) (revoked, failed []string)) the field expects.
func TestTokenAdminService_RevokeAcrossIssuersPreferred(t *testing.T) {
	t.Parallel()
	var calledWith string
	fanout := func(_ context.Context, token string) (revoked, failed []string) {
		calledWith = token
		if token == "known" {
			return []string{"replica-a", "replica-b"}, nil
		}
		return nil, []string{"replica-a"}
	}
	svc := NewTokenAdminService(TokenAdminConfig{RevokeAcrossIssuers: fanout})
	ctx := context.Background()

	resp, err := svc.Revoke(ctx, &adminv1.RevokeRequest{Token: "known"})
	requireOK(t, err, "Revoke known token")
	if calledWith != "known" || len(resp.Revoked) != 1 || resp.Revoked[0] != sso.RevokedToken {
		t.Errorf("Revoke response = %+v calledWith=%q", resp.Revoked, calledWith)
	}

	_, err = svc.Revoke(ctx, &adminv1.RevokeRequest{Token: "unknown"})
	requireCode(t, err, codes.NotFound)
}

// TestTokenAdminService_IssueTempToken drives IssueTempToken against a real
// MemoryTempTokenStore and proves the issued token actually consumes back
// to the right subject with the aud/scope claims folded in.
func TestTokenAdminService_IssueTempToken(t *testing.T) {
	t.Parallel()
	store := authenticators.NewMemoryTempTokenStore()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	svc := NewTokenAdminService(TokenAdminConfig{TempStore: store, Recorder: rec})
	ctx := context.Background()

	resp, err := svc.IssueTempToken(ctx, &adminv1.IssueTempTokenRequest{
		UserId: "carol", ClientId: "web-app", Scopes: []string{"openid", "profile"},
	})
	requireOK(t, err, "IssueTempToken")
	if resp.Token == "" || resp.ExpiresAtUnix == 0 {
		t.Fatalf("IssueTempToken response = %+v", resp)
	}

	subject, err := store.Consume(ctx, resp.Token)
	requireOK(t, err, "Consume")
	if subject.ID != "carol" {
		t.Errorf("subject.ID = %q, want carol", subject.ID)
	}
	if subject.Claims["aud"] != "web-app" {
		t.Errorf("subject.Claims[aud] = %q", subject.Claims["aud"])
	}
	if subject.Claims["scope"] != "openid profile" {
		t.Errorf("subject.Claims[scope] = %q", subject.Claims["scope"])
	}

	// Single-use: a second Consume of the same token must fail.
	_, err = store.Consume(ctx, resp.Token)
	if err == nil {
		t.Error("expected the temp token to be single-use")
	}

	events, err := sink.Query(ctx, audit.Query{Type: audit.EventAdminTempTokenIssued})
	requireOK(t, err, "sink.Query")
	if len(events) != 1 {
		t.Errorf("expected 1 temp-token-issued audit event, got %d", len(events))
	}
}
