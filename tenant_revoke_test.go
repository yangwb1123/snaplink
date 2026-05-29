package sso_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// RevokeTenantRefreshTokens enumerates a tenant's clients and purges every
// refresh token bound to them, leaving other tenants untouched. It is the
// active-revocation companion to the lazy suspension check.
func TestServer_RevokeTenantRefreshTokens(t *testing.T) {
	ctx := context.Background()

	clients := defaultimpl.NewMemoryClientStore()
	for _, c := range []*sso.Client{
		{ID: "ca", TenantID: "t1"},
		{ID: "cb", TenantID: "t1"},
		{ID: "cc", TenantID: "t2"},
	} {
		if err := clients.Add(ctx, c); err != nil {
			t.Fatalf("add client %s: %v", c.ID, err)
		}
	}

	rts := defaultimpl.NewMemoryRefreshTokenStore()
	mk := func(tok, client string) {
		if err := rts.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: "u", ClientID: client, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	mk("t1a", "ca")
	mk("t1b", "cb")
	mk("t2a", "cc")

	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithClientStore(clients),
		sso.WithRefreshTokenStore(rts, time.Hour),
	)

	n, err := srv.RevokeTenantRefreshTokens(ctx, "t1")
	if err != nil {
		t.Fatalf("RevokeTenantRefreshTokens: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d, want 2 (t1 has 2 clients, 1 token each)", n)
	}
	// A client outside the tenant keeps its token.
	if _, err := rts.Inspect(ctx, "t2a"); err != nil {
		t.Fatalf("t2 token should survive: %v", err)
	}
	// Empty tenant is a no-op (no accidental fleet-wide wipe).
	if blank, _ := srv.RevokeTenantRefreshTokens(ctx, ""); blank != 0 {
		t.Fatalf("empty tenant revoked %d, want 0", blank)
	}
}
