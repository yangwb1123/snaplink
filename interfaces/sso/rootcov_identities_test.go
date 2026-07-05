package sso_test

// rootcov_identities_test.go covers the self-service identity-linking surface
// (GET/DELETE /me/identities, domains/identitylink) added alongside
// server_me.go's handler delegates: listing, unlinking, the oracle-safe 404
// for an unknown/foreign link id, and the "don't lock yourself out" guard
// that refuses to unlink a sole remaining identity when the account has no
// other authentication method.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	identitylinkmemory "github.com/snaplink/sso/domains/identitylink/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRcov_MyIdentities_ListAndUnlink covers the happy path against
// rcovNewServer's standard fixture — rcovUser already has a password
// credential (set by rcovNewServer), so unlinking their only identity down
// to zero is allowed.
func TestRcov_MyIdentities_ListAndUnlink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := identitylinkmemory.New()
	s := rcovNewServer(t, sso.WithIdentityLinkStore(store))
	access, _ := rcovDirectLogin(t, s)

	link, err := store.Link(ctx, rcovUser, "google", "sub-alice")
	if err != nil {
		t.Fatalf("seed link: %v", err)
	}

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/me/identities", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /me/identities = %d body=%v", status, out)
	}
	ids, _ := out["identities"].([]any)
	if len(ids) != 1 {
		t.Fatalf("identities = %v, want 1 entry", out["identities"])
	}

	// Unauthenticated => 401 (matches every other /me/* surface).
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/me/identities", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth GET /me/identities = %d, want 401", status)
	}

	// rcovUser has a password credential, so unlinking the only identity is
	// ALLOWED (they still have a way to log in).
	status, out = rcovDo(t, http.MethodDelete, s.http.URL+"/me/identities/"+link.ID, access, nil)
	if status != http.StatusNoContent {
		t.Fatalf("DELETE /me/identities/:id = %d body=%v, want 204", status, out)
	}

	status, out = rcovDo(t, http.MethodGet, s.http.URL+"/me/identities", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET after unlink = %d body=%v", status, out)
	}
	ids, _ = out["identities"].([]any)
	if len(ids) != 0 {
		t.Errorf("identities after unlink = %v, want empty", out["identities"])
	}
}

// TestRcov_MyIdentities_UnknownOrForeignID covers the oracle-safe 404: a
// missing id and another user's link id must respond identically.
func TestRcov_MyIdentities_UnknownOrForeignID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := identitylinkmemory.New()
	s := rcovNewServer(t, sso.WithIdentityLinkStore(store))
	access, _ := rcovDirectLogin(t, s)

	status, _ := rcovDo(t, http.MethodDelete, s.http.URL+"/me/identities/does-not-exist", access, nil)
	if status != http.StatusNotFound {
		t.Errorf("DELETE unknown id = %d, want 404", status)
	}

	foreign, err := store.Link(ctx, "someone-else-entirely", "google", "sub-else")
	if err != nil {
		t.Fatalf("seed foreign link: %v", err)
	}
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/identities/"+foreign.ID, access, nil)
	if status != http.StatusNotFound {
		t.Errorf("DELETE foreign id = %d, want 404 (oracle-safe)", status)
	}

	// The foreign link must be untouched by the failed cross-user attempt.
	links, err := store.ListByUser(ctx, "someone-else-entirely")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(links) != 1 {
		t.Errorf("foreign user's links = %+v, want 1 (unchanged)", links)
	}
}

// TestRcov_MyIdentities_GuardLastAuthMethod builds a DEDICATED server with no
// password credential store wired, so an identity-only user's sole linked
// identity is their ONLY way to authenticate. Unlinking it must be refused.
func TestRcov_MyIdentities_GuardLastAuthMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		identityUser = "identity-only-user"
		clientID     = "identities-guard-client"
		clientSecret = "identities-guard-secret"
	)
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: identityUser}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: clientID, Secret: clientSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "federated" && p == "n/a" {
				return &sso.AuthResult{UserID: identityUser}, nil
			}
			return nil, errors.New("bad credentials")
		}))
	store := identitylinkmemory.New()
	link, err := store.Link(ctx, identityUser, "google", "sub-identity-only")
	if err != nil {
		t.Fatalf("seed link: %v", err)
	}

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIdentityLinkStore(store),
		// Deliberately NO WithPasswordCredentialStore: identityUser has no
		// password fallback, so their one linked identity is their ONLY way in.
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": "federated", "password": "n/a"},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("login response missing access_token: %v", out)
	}

	status, out = rcovDo(t, http.MethodDelete, httpSrv.URL+"/me/identities/"+link.ID, access, nil)
	if status != http.StatusConflict {
		t.Fatalf("DELETE last identity = %d body=%v, want 409", status, out)
	}
	if out["error"] != "identity_unlink_last_method" {
		t.Errorf("error code = %v, want identity_unlink_last_method", out["error"])
	}

	// The blocked attempt must not have partially mutated state.
	remaining, err := store.ListByUser(ctx, identityUser)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("remaining links = %+v, want 1 (unchanged)", remaining)
	}
}
