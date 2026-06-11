package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// newRefreshGraceHarness mirrors newRefreshFamilyHarness (same seed client +
// family-tracking MemoryRefreshTokenStore) but optionally arms the refresh
// double-submit grace window.
func newRefreshGraceHarness(t *testing.T, grace time.Duration) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rfUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rfClientID, Secret: rfSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rfUser, Provider: "password"}, nil
		},
	))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	}
	if grace > 0 {
		opts = append(opts, sso.WithRefreshRotationGrace(grace))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store
}

// TestRefreshGrace_DoubleSubmitReturnsSameSuccessor: with the grace window
// armed, a benign re-presentation of a just-rotated token returns the SAME
// successor tokens (200) instead of killing the family — the logout-storm fix.
func TestRefreshGrace_DoubleSubmitReturnsSameSuccessor(t *testing.T) {
	srv, _ := newRefreshGraceHarness(t, time.Hour)
	refresh1 := rfLogin(t, srv)

	status, body := rfRotate(t, srv, refresh1)
	if status != http.StatusOK {
		t.Fatalf("first rotation status=%d body=%v", status, body)
	}
	refresh2, _ := body["refresh_token"].(string)
	access2, _ := body["access_token"].(string)
	if refresh2 == "" {
		t.Fatal("no refresh2 from first rotation")
	}

	// Second presentation of the SAME consumed token (the double-submit):
	// grace replay -> SAME successor, 200, NOT invalid_grant.
	status2, body2 := rfRotate(t, srv, refresh1)
	if status2 != http.StatusOK {
		t.Fatalf("grace double-submit status=%d want 200 (body=%v)", status2, body2)
	}
	if r, _ := body2["refresh_token"].(string); r != refresh2 {
		t.Errorf("grace replay refresh_token=%q, want the same successor %q", r, refresh2)
	}
	if a, _ := body2["access_token"].(string); a != access2 {
		t.Error("grace replay access_token differs from the original successor")
	}

	// The family MUST still be alive — refresh2 still rotates.
	if status3, _ := rfRotate(t, srv, refresh2); status3 != http.StatusOK {
		t.Errorf("family was killed despite grace: refresh2 rotation status=%d", status3)
	}
}

// TestRefreshGrace_DisabledStillKillsFamily: without the grace window (the
// default), the same double-submit still trips reuse detection — the grace is
// opt-in and does NOT weaken BCP §4.13 by default.
func TestRefreshGrace_DisabledStillKillsFamily(t *testing.T) {
	srv, _ := newRefreshGraceHarness(t, 0)
	refresh1 := rfLogin(t, srv)
	if status, _ := rfRotate(t, srv, refresh1); status != http.StatusOK {
		t.Fatal("first rotation failed")
	}
	status2, body2 := rfRotate(t, srv, refresh1)
	if status2 != http.StatusBadRequest || body2["error"] != "invalid_grant" {
		t.Errorf("without grace, a double-submit must be invalid_grant; got status=%d err=%v", status2, body2["error"])
	}
}
