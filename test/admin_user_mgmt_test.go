package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
)

// newAdminUserMgmtHarness wires a server with consent + MFA-enrollment stores
// (no AdminMiddleware — the bare SDK server; gating is the operator's
// cmd-level concern). Seeds one consent grant + one MFA factor for u-alice.
func newAdminUserMgmtHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryConsentStore, *defaultimpl.MemoryMFAEnrollmentStore) {
	t.Helper()
	consent := defaultimpl.NewMemoryConsentStore()
	_ = consent.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID: "u-alice", ClientID: "app-x", Scopes: []string{"openid"}, GrantedAt: time.Now(),
	})
	mfa := defaultimpl.NewMemoryMFAEnrollmentStore()
	mfa.AddFactor("u-alice", sso.MFAEnrolledFactor{ID: "factor-1", Method: "totp", Label: "Phone"})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithConsentStore(consent),
		sso.WithMFAEnrollmentStore(mfa),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, consent, mfa
}

func TestAdminUserConsents_ListAndRevoke(t *testing.T) {
	srv, _, _ := newAdminUserMgmtHarness(t)

	code, body := doReq(t, srv, http.MethodGet, "/api/v1/admin/users/u-alice/consents", "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, body)
	}
	if list, _ := body["consents"].([]any); len(list) != 1 {
		t.Fatalf("want 1 consent, got %v", body)
	}

	// Revoke the grant.
	dc, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/users/u-alice/consents/app-x", "")
	if dc != http.StatusNoContent {
		t.Fatalf("revoke status=%d", dc)
	}
	_, after := doReq(t, srv, http.MethodGet, "/api/v1/admin/users/u-alice/consents", "")
	if list, _ := after["consents"].([]any); len(list) != 0 {
		t.Errorf("after revoke = %v, want empty", after)
	}

	// Revoking a now-missing grant is a 404.
	nc, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/users/u-alice/consents/app-x", "")
	if nc != http.StatusNotFound {
		t.Errorf("revoke missing = %d, want 404", nc)
	}
}

func TestAdminUserMFA_ListAndRemove(t *testing.T) {
	srv, _, _ := newAdminUserMgmtHarness(t)

	code, body := doReq(t, srv, http.MethodGet, "/api/v1/admin/users/u-alice/mfa", "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, body)
	}
	factors, _ := body["factors"].([]any)
	if len(factors) != 1 {
		t.Fatalf("want 1 factor, got %v", body)
	}

	// Remove the factor.
	dc, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/users/u-alice/mfa/factor-1", "")
	if dc != http.StatusNoContent {
		t.Fatalf("remove status=%d", dc)
	}
	_, after := doReq(t, srv, http.MethodGet, "/api/v1/admin/users/u-alice/mfa", "")
	if fs, _ := after["factors"].([]any); len(fs) != 0 {
		t.Errorf("after remove = %v, want empty", after)
	}

	// Removing a factor the user doesn't have is a 404 (oracle-safe ownership).
	nc, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/users/u-alice/mfa/no-such", "")
	if nc != http.StatusNotFound {
		t.Errorf("remove missing = %d, want 404", nc)
	}
}

func TestAdminUserPassword_Reset(t *testing.T) {
	ctx := context.Background()
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	_ = pw.SetPassword(ctx, "u-alice", "old-pass")
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithPasswordCredentialStore(pw),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	raw, _ := json.Marshal(map[string]any{"new_password": "new-pass"})
	req, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/admin/users/u-alice/password", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", resp.StatusCode)
	}

	// The new password verifies; the old one no longer does.
	if err := pw.VerifyPassword(ctx, "u-alice", "new-pass"); err != nil {
		t.Errorf("new password does not verify after admin reset: %v", err)
	}
	if err := pw.VerifyPassword(ctx, "u-alice", "old-pass"); err == nil {
		t.Error("old password still verifies after admin reset")
	}

	// Missing new_password → 400.
	req2, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/admin/users/u-alice/password", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("post empty: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("empty body status=%d, want 400", resp2.StatusCode)
	}
}

func TestAdminUserDeviceSecrets_Revoke(t *testing.T) {
	ctx := context.Background()
	ds := defaultimpl.NewMemoryDeviceSecretStore()
	_ = ds.Issue(ctx, &sso.DeviceSecret{Secret: "s1", Subject: "u-alice", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour)})
	_ = ds.Issue(ctx, &sso.DeviceSecret{Secret: "s2", Subject: "u-alice", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour)})
	_ = ds.Issue(ctx, &sso.DeviceSecret{Secret: "s3", Subject: "u-bob", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour)})
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithDeviceSecretStore(ds, time.Hour),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/device-secrets", "")
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, body)
	}
	if got, _ := body["revoked"].(float64); int(got) != 2 {
		t.Errorf("revoked = %v, want 2", body["revoked"])
	}
	// Alice's bindings are gone; Bob's is untouched.
	if _, err := ds.Consume(ctx, "s1"); err == nil {
		t.Error("alice's device secret s1 still present after admin revoke")
	}
	if _, err := ds.Consume(ctx, "s3"); err != nil {
		t.Errorf("bob's device secret wrongly revoked: %v", err)
	}
}

// TestAdminUserRefreshTokens_Revoke proves the admin bulk-revoke endpoint (a)
// kills every refresh token the target user holds across MULTIPLE clients,
// and (b) never touches another user's tokens.
func TestAdminUserRefreshTokens_Revoke(t *testing.T) {
	ctx := context.Background()
	rt := defaultimpl.NewMemoryRefreshTokenStore()
	exp := time.Now().Add(time.Hour)
	// Alice holds tokens with two different clients; Bob holds one.
	if err := rt.Issue(ctx, "alice-tok-app1", &oauth.RefreshToken{UserID: "u-alice", ClientID: "app-1", ExpiresAt: exp}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := rt.Issue(ctx, "alice-tok-app2", &oauth.RefreshToken{UserID: "u-alice", ClientID: "app-2", ExpiresAt: exp}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := rt.Issue(ctx, "bob-tok-app1", &oauth.RefreshToken{UserID: "u-bob", ClientID: "app-1", ExpiresAt: exp}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithRefreshTokenStore(rt, time.Hour),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/refresh-tokens", "")
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, body)
	}
	if got, _ := body["revoked"].(float64); int(got) != 2 {
		t.Errorf("revoked = %v, want 2 (across both of alice's clients)", body["revoked"])
	}

	// Alice's tokens (both clients) are gone.
	if _, err := rt.Consume(ctx, "alice-tok-app1"); err == nil {
		t.Error("alice's app-1 refresh token still present after admin revoke")
	}
	if _, err := rt.Consume(ctx, "alice-tok-app2"); err == nil {
		t.Error("alice's app-2 refresh token still present after admin revoke")
	}
	// Bob's token is untouched.
	if _, err := rt.Consume(ctx, "bob-tok-app1"); err != nil {
		t.Errorf("bob's refresh token wrongly revoked: %v", err)
	}

	// Idempotent: revoking again (nothing left) returns 0, not an error.
	code2, body2 := doReq(t, hs, http.MethodDelete, "/api/v1/admin/users/u-alice/refresh-tokens", "")
	if code2 != http.StatusOK {
		t.Fatalf("second revoke status=%d body=%v", code2, body2)
	}
	if got, _ := body2["revoked"].(float64); int(got) != 0 {
		t.Errorf("second revoke = %v, want 0", body2["revoked"])
	}
}

func TestAdminUserEmail_ForceSet(t *testing.T) {
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: "u-alice", Email: "old@example.com"})
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	// Force-set the email.
	raw, _ := json.Marshal(map[string]any{"email": "new@example.com"})
	req, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/admin/users/u-alice/email", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", resp.StatusCode)
	}
	got, _ := users.GetByID(ctx, "u-alice")
	if got.Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", got.Email)
	}

	// Empty email → 400.
	raw2, _ := json.Marshal(map[string]any{"email": "  "})
	req2, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/admin/users/u-alice/email", bytes.NewReader(raw2))
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req2)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("empty email status=%d, want 400", resp2.StatusCode)
	}

	// Unknown user → 404.
	raw3, _ := json.Marshal(map[string]any{"email": "x@example.com"})
	req3, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/admin/users/ghost/email", bytes.NewReader(raw3))
	req3.Header.Set("Content-Type", "application/json")
	resp3, _ := http.DefaultClient.Do(req3)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("unknown user status=%d, want 404", resp3.StatusCode)
	}
}

// TestAdminUserMgmt_NotMountedWithoutStores confirms the routes are absent when
// the backing stores aren't wired (byte-identical off).
func TestAdminUserMgmt_NotMountedWithoutStores(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	for _, p := range []string{"/api/v1/admin/users/u/consents", "/api/v1/admin/users/u/mfa"} {
		resp, err := http.Get(hs.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status=%d, want 404 (unmounted)", p, resp.StatusCode)
		}
	}
}
