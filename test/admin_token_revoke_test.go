package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

// TestAdminUserPasswordResetTokens_Revoke verifies the helpdesk endpoint
// invalidates all of a user's pending forgot-password tokens, leaves other
// users' tokens untouched, and is idempotent.
func TestAdminUserPasswordResetTokens_Revoke(t *testing.T) {
	ctx := context.Background()
	store := defaultimpl.NewMemoryPasswordResetStore()
	exp := time.Now().Add(time.Hour)
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-a1", UserID: "u-alice", ExpiresAt: exp})
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-a2", UserID: "u-alice", ExpiresAt: exp})
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-b1", UserID: "u-bob", ExpiresAt: exp})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithPasswordResetStore(store, time.Hour),
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/password-reset-tokens", "")
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, body)
	}
	if got, _ := body["revoked"].(float64); int(got) != 2 {
		t.Errorf("revoked=%v, want 2", body["revoked"])
	}
	// Alice's tokens are gone; Bob's survives.
	if _, err := store.Consume(ctx, "pr-a1"); err == nil {
		t.Error("alice's reset token pr-a1 still present after admin revoke")
	}
	if _, err := store.Consume(ctx, "pr-b1"); err != nil {
		t.Errorf("bob's reset token wrongly revoked: %v", err)
	}
	// Idempotent: a second revoke with no pending tokens returns 0.
	_, body2 := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/password-reset-tokens", "")
	if got, _ := body2["revoked"].(float64); int(got) != 0 {
		t.Errorf("second revoke=%v, want 0", body2["revoked"])
	}
}

// TestAdminUserEmailChangeTokens_Revoke mirrors the password-reset test for the
// verified-email-change token store.
func TestAdminUserEmailChangeTokens_Revoke(t *testing.T) {
	ctx := context.Background()
	store := defaultimpl.NewMemoryEmailChangeStore()
	exp := time.Now().Add(time.Hour)
	_ = store.Issue(ctx, &core.EmailChangeToken{Token: "ec-a1", UserID: "u-alice", NewEmail: "a@new.example", ExpiresAt: exp})
	_ = store.Issue(ctx, &core.EmailChangeToken{Token: "ec-b1", UserID: "u-bob", NewEmail: "b@new.example", ExpiresAt: exp})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithEmailChangeStore(store, time.Hour),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/email-change-tokens", "")
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, body)
	}
	if got, _ := body["revoked"].(float64); int(got) != 1 {
		t.Errorf("revoked=%v, want 1", body["revoked"])
	}
	if _, err := store.Consume(ctx, "ec-a1"); err == nil {
		t.Error("alice's email-change token still present after admin revoke")
	}
	if _, err := store.Consume(ctx, "ec-b1"); err != nil {
		t.Errorf("bob's email-change token wrongly revoked: %v", err)
	}
}

// TestAdminTokenRevoke_NotMountedWithoutStores confirms the routes are absent
// when the backing stores aren't wired (byte-identical off).
func TestAdminTokenRevoke_NotMountedWithoutStores(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	for _, p := range []string{
		"/api/v1/admin/users/u/password-reset-tokens",
		"/api/v1/admin/users/u/email-change-tokens",
	} {
		code, _ := doReq(t, hs, http.MethodDelete, p, "")
		if code != http.StatusNotFound {
			t.Errorf("%s status=%d, want 404 (unmounted)", p, code)
		}
	}
}

// TestAdminUserPasswordResetTokens_List verifies the helpdesk GET lists a user's
// pending reset tokens with expiry — and NEVER leaks the token value.
func TestAdminUserPasswordResetTokens_List(t *testing.T) {
	ctx := context.Background()
	store := defaultimpl.NewMemoryPasswordResetStore()
	exp := time.Now().Add(time.Hour)
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-secret-1", UserID: "u-alice", ExpiresAt: exp})
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-secret-2", UserID: "u-alice", ExpiresAt: exp})
	_ = store.Issue(ctx, &core.PasswordResetToken{Token: "pr-secret-b", UserID: "u-bob", ExpiresAt: exp})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithPasswordResetStore(store, time.Hour),
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodGet, "/api/v1/admin/users/u-alice/password-reset-tokens", "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, body)
	}
	if got, _ := body["count"].(float64); int(got) != 2 {
		t.Errorf("count=%v, want 2", body["count"])
	}
	// The token value must NOT appear anywhere in the response.
	for _, secret := range []string{"pr-secret-1", "pr-secret-2"} {
		if strings.Contains(toJSONString(t, body), secret) {
			t.Errorf("response leaked token value %q", secret)
		}
	}
}

func toJSONString(t *testing.T, v any) string {
	t.Helper()
	b, _ := json.Marshal(v)
	return string(b)
}
