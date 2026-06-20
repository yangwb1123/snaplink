package ssotest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

// TestSessionTenantIndex_LoginStampsTenant proves the fix that closes the
// tenant-session revoke loop: a login through a tenant-bound client stamps the
// created session's TenantID, so SessionTenantIndex.DeleteByTenant (the
// efficient direct-index revoke path) actually finds it. Before the fix,
// createSession never set TenantID, so the index matched zero rows and only the
// membership-roster fallback worked.
func TestSessionTenantIndex_LoginStampsTenant(t *testing.T) {
	const tenantID = "t-idx"
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-idx", Provider: "stub"},
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "idx-app", Name: "Idx", Active: true,
		TenantID:              tenantID,
		AllowedAuthenticators: []string{stub.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	mgr := defaultimpl.NewMemorySessionManager(0)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(stub),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(mgr),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(8))),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body := `{"provider":"stub","client_id":"idx-app","credential":{"u":"x"}}`
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}

	// The direct tenant index must now find the freshly-created session.
	idx, ok := sso.SessionManager(mgr).(sso.SessionTenantIndex)
	if !ok {
		t.Fatal("MemorySessionManager does not implement SessionTenantIndex")
	}
	n, err := idx.DeleteByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n < 1 {
		t.Errorf("DeleteByTenant removed %d sessions; want >=1 (login must stamp Session.TenantID)", n)
	}
}
