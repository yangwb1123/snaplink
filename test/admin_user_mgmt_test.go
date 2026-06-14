package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
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
