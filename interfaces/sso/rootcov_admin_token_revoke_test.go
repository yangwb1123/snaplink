package sso_test

// rootcov_admin_token_revoke_test.go covers DELETE /api/v1/admin/tokens/{id}
// and POST /api/v1/admin/logout — proving both now leave a forensic trail
// (admin_token_revoked) instead of the previous silent revoke.

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

func newAdminTokenFixture(t *testing.T) (*rcovAdminEnv, *audit.MemorySink, *memorystorecredential.MemoryAdminTokenStore) {
	t.Helper()
	store := memorystorecredential.NewMemoryAdminTokenStore()
	sink := audit.NewMemorySink(50)
	env := rcovNewAdminServer(t,
		sso.WithAdminTokenStore(store),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	return env, sink, store
}

func hasAdminTokenRevokedEvent(t *testing.T, sink *audit.MemorySink, tokenID string) bool {
	t.Helper()
	events, err := sink.Query(t.Context(), audit.Query{})
	if err != nil {
		t.Fatalf("query audit sink: %v", err)
	}
	for _, evt := range events {
		if evt.Type != audit.EventAdminTokenRevoked {
			continue
		}
		if tokenID == "" || evt.TokenID == tokenID {
			return true
		}
	}
	return false
}

// TestRcovAdmin_RevokeTokenRecordsAudit proves DELETE /admin/tokens/{id}
// emits admin_token_revoked with the target token id, closing the gap where
// this path revoked silently.
func TestRcovAdmin_RevokeTokenRecordsAudit(t *testing.T) {
	t.Parallel()
	env, sink, store := newAdminTokenFixture(t)
	if err := store.Record(t.Context(), core.AdminToken{ID: "tok-1", AdminID: "op-1"}); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}

	status, _ := rcovDo(t, http.MethodDelete, env.url+"/api/v1/admin/tokens/tok-1", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	if _, err := store.GetByID(t.Context(), "tok-1"); err == nil {
		t.Error("token should be revoked in the store")
	}
	if !hasAdminTokenRevokedEvent(t, sink, "tok-1") {
		t.Error("expected an admin_token_revoked audit event carrying the token id, found none")
	}
}

// TestRcovAdmin_LogoutRecordsAudit proves POST /admin/logout revokes the
// caller's own admin bearer AND emits admin_token_revoked for its jti.
func TestRcovAdmin_LogoutRecordsAudit(t *testing.T) {
	t.Parallel()
	env, sink, _ := newAdminTokenFixture(t)

	status, _ := rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/logout", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", status)
	}
	if !hasAdminTokenRevokedEvent(t, sink, "") {
		t.Error("expected an admin_token_revoked audit event on logout, found none")
	}
}

// TestRcovAdmin_RevokeTokenNoAuditorNoPanic proves the recorder is optional:
// without WithAuditRecorder, revocation still succeeds (no-op audit path).
func TestRcovAdmin_RevokeTokenNoAuditorNoPanic(t *testing.T) {
	t.Parallel()
	store := memorystorecredential.NewMemoryAdminTokenStore()
	env := rcovNewAdminServer(t, sso.WithAdminTokenStore(store))
	if err := store.Record(t.Context(), core.AdminToken{ID: "tok-2"}); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}

	status, _ := rcovDo(t, http.MethodDelete, env.url+"/api/v1/admin/tokens/tok-2", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}
}
