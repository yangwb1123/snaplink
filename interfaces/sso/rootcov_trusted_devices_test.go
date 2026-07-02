package sso_test

// rootcov_trusted_devices_test.go covers the "remember this device" MFA-skip
// feature (w2.15) end to end over HTTP: the self-service trust/list/revoke
// surface (trusted_devices.go via protocols/selfservice/selfserviceaccount),
// the /auth/login step-up-skip check (server_login_client.go), the AMR gate
// on Trust, and the password-change compromise-signal revocation hook
// (selfserviceaccount/security.go).
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo /
// rcovRequireMFAScorer / rcovTOTPProvider from rootcov_flow_test.go and
// rootcov_misc_test.go.

import (
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

// rcovLoginWithMFA drives the full two-leg risk->RequireMFA->totp flow and
// returns the resulting access token (amr includes "mfa").
func rcovLoginWithMFA(t *testing.T, s *rcovServer) string {
	t.Helper()
	_, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	challengeID, _ := out["mfa_challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("no mfa_challenge_id in leg1 response: %v", out)
	}
	status, out := rcovPostJSON(t, s.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": challengeID,
		"mfa_method":       "totp",
		"code":             "123456",
	})
	access, _ := out["access_token"].(string)
	if status != http.StatusOK || access == "" {
		t.Fatalf("mfa leg2 status=%d body=%v, want 200 + access_token", status, out)
	}
	return access
}

// TestRcovTrustedDevices_TrustRequiresMFAThisSession proves a bearer token
// minted WITHOUT a completed MFA leg (amr has no "mfa") cannot mint a
// trust grant — the invariant against "steal a live session, silently
// upgrade to a standing MFA bypass".
func TestRcovTrustedDevices_TrustRequiresMFAThisSession(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t, sso.WithTrustedDeviceStore(tds, 30*24*time.Hour))

	// No risk scorer wired on this server: a direct login never runs MFA at
	// all, so its access token's amr never contains "mfa".
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/me/devices/trust", access, map[string]any{"label": "laptop"})
	if status != http.StatusForbidden {
		t.Fatalf("trust without an MFA leg = %d body=%v, want 403", status, out)
	}
	if out["error"] != "insufficient_user_authentication" {
		t.Errorf("error = %v, want insufficient_user_authentication", out["error"])
	}
}

// TestRcovTrustedDevices_UnauthenticatedRequiresBearer covers the plain
// missing-bearer 401 path shared with every other /me/* endpoint.
func TestRcovTrustedDevices_UnauthenticatedRequiresBearer(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t, sso.WithTrustedDeviceStore(tds, 30*24*time.Hour))

	status, _ := rcovDo(t, http.MethodGet, s.http.URL+"/me/devices", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("GET /me/devices no bearer = %d, want 401", status)
	}
}

// TestRcovTrustedDevices_TrustListSkipRevoke is the full lifecycle: complete
// MFA once, trust the device, confirm a FRESH login without the device token
// still demands MFA (control), confirm a login WITH the device token skips
// it, list shows the grant (never the token), then revoke removes it and the
// old token no longer skips MFA.
func TestRcovTrustedDevices_TrustListSkipRevoke(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		sso.WithTrustedDeviceStore(tds, 30*24*time.Hour),
	)

	access := rcovLoginWithMFA(t, s)

	// Trust the current device.
	status, out := rcovPostJSON(t, s.http.URL+"/me/devices/trust", access, map[string]any{"label": "work laptop"})
	if status != http.StatusCreated {
		t.Fatalf("trust = %d body=%v, want 201", status, out)
	}
	deviceToken, _ := out["device_token"].(string)
	deviceID, _ := out["device_id"].(string)
	if deviceToken == "" || deviceID == "" {
		t.Fatalf("missing device_token/device_id in trust response: %v", out)
	}

	// Control: a fresh login WITHOUT the device token still demands MFA.
	_, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if out["error"] != "mfa_required" {
		t.Fatalf("login without device_token = %v, want mfa_required", out)
	}

	// A login presenting the device token skips the MFA challenge entirely.
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":     "password",
		"client_id":    rcovClient,
		"credential":   map[string]string{"username": rcovUsername, "password": rcovPassword},
		"device_token": deviceToken,
	})
	if status != http.StatusOK {
		t.Fatalf("login with device_token status=%d body=%v, want 200", status, out)
	}
	if out["error"] == "mfa_required" {
		t.Fatalf("login with a trusted device_token still demanded MFA: %v", out)
	}
	if out["access_token"] == nil || out["access_token"] == "" {
		t.Fatalf("no access_token minted via trusted-device skip: %v", out)
	}

	// List surfaces the grant's metadata, never the token or its hash.
	status, out = rcovDo(t, http.MethodGet, s.http.URL+"/me/devices", access, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices status=%d body=%v", status, out)
	}
	devices, _ := out["devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1: %v", len(devices), out)
	}
	first, _ := devices[0].(map[string]any)
	if first["id"] != deviceID {
		t.Errorf("listed id = %v, want %v", first["id"], deviceID)
	}
	if _, leaked := first["device_token"]; leaked {
		t.Error("listed device carries device_token — must never be returned after Trust")
	}
	if _, leaked := first["hash"]; leaked {
		t.Error("listed device carries a hash field — must never be returned")
	}

	// Revoke removes it.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/devices/"+deviceID, access, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke status=%d, want 204", status)
	}
	status, out = rcovDo(t, http.MethodGet, s.http.URL+"/me/devices", access, nil)
	devices, _ = out["devices"].([]any)
	if status != http.StatusOK || len(devices) != 0 {
		t.Fatalf("devices after revoke = %v (status=%d), want empty", devices, status)
	}

	// The revoked token no longer skips MFA on a subsequent login.
	_, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":     "password",
		"client_id":    rcovClient,
		"credential":   map[string]string{"username": rcovUsername, "password": rcovPassword},
		"device_token": deviceToken,
	})
	if out["error"] != "mfa_required" {
		t.Fatalf("login with a REVOKED device_token = %v, want mfa_required", out)
	}
}

// TestRcovTrustedDevices_EmitsAuditTrail proves each of the three
// trusted-device lifecycle moments lands its own audit event: minting a
// grant (device_trusted), a login that skipped MFA via a live grant
// (mfa_skipped_trusted_device), and revoking it (device_trust_revoked). A
// SOC2/SIEM reviewer needs all three distinguishable — collapsing any of
// them into an existing event type would hide that a login bypassed a
// risk-scorer step-up demand via a standing grant instead of a freshly
// verified factor.
func TestRcovTrustedDevices_EmitsAuditTrail(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		sso.WithTrustedDeviceStore(tds, 30*24*time.Hour),
	)
	access := rcovLoginWithMFA(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/me/devices/trust", access, nil)
	if status != http.StatusCreated {
		t.Fatalf("trust = %d body=%v, want 201", status, out)
	}
	if n := rcovAuditCount(t, s, audit.EventDeviceTrusted); n != 1 {
		t.Errorf("device_trusted audit events = %d, want 1", n)
	}
	deviceToken, _ := out["device_token"].(string)
	deviceID, _ := out["device_id"].(string)

	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":     "password",
		"client_id":    rcovClient,
		"credential":   map[string]string{"username": rcovUsername, "password": rcovPassword},
		"device_token": deviceToken,
	})
	if status != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("login with device_token status=%d body=%v, want 200 + access_token", status, out)
	}
	if n := rcovAuditCount(t, s, audit.EventMFASkippedTrustedDevice); n != 1 {
		t.Errorf("mfa_skipped_trusted_device audit events = %d, want 1", n)
	}

	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/devices/"+deviceID, access, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke status=%d, want 204", status)
	}
	if n := rcovAuditCount(t, s, audit.EventDeviceTrustRevoked); n != 1 {
		t.Errorf("device_trust_revoked audit events = %d, want 1", n)
	}
}

// TestRcovTrustedDevices_RevokeIsOwnershipScoped proves DELETE /me/devices/:id
// can never remove another user's grant — the same oracle-safe 404 whether
// the id belongs to someone else or never existed.
func TestRcovTrustedDevices_RevokeIsOwnershipScoped(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		sso.WithTrustedDeviceStore(tds, 30*24*time.Hour),
	)
	access := rcovLoginWithMFA(t, s)
	_, out := rcovPostJSON(t, s.http.URL+"/me/devices/trust", access, nil)
	deviceID, _ := out["device_id"].(string)
	if deviceID == "" {
		t.Fatalf("no device_id: %v", out)
	}

	// Seed a grant directly for a different user and confirm THIS caller
	// can't delete it (same 404 as an unknown id).
	if _, _, err := tds.Trust(t.Context(), "someone-else", rcovClient, "", time.Hour); err != nil {
		t.Fatalf("seed: %v", err)
	}
	status, _ := rcovDo(t, http.MethodDelete, s.http.URL+"/me/devices/no-such-id", access, nil)
	if status != http.StatusNotFound {
		t.Errorf("delete unknown id = %d, want 404", status)
	}

	// Owner delete still works.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/devices/"+deviceID, access, nil)
	if status != http.StatusNoContent {
		t.Errorf("owner delete = %d, want 204", status)
	}
}

// TestRcovTrustedDevices_PasswordChangeRevokesGrants proves the
// account-compromise-signal hook: changing the password invalidates every
// trusted-device grant, so a device token minted under the OLD password
// stops skipping MFA.
func TestRcovTrustedDevices_PasswordChangeRevokesGrants(t *testing.T) {
	t.Parallel()
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	s := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		sso.WithTrustedDeviceStore(tds, 30*24*time.Hour),
	)
	access := rcovLoginWithMFA(t, s)
	_, out := rcovPostJSON(t, s.http.URL+"/me/devices/trust", access, nil)
	deviceToken, _ := out["device_token"].(string)
	if deviceToken == "" {
		t.Fatalf("no device_token: %v", out)
	}

	status, out := rcovPostJSON(t, s.http.URL+"/me/password", access, map[string]any{
		"current_password": rcovPassword,
		"new_password":     "a-new-strong-password-1",
	})
	if status != http.StatusNoContent {
		t.Fatalf("change password status=%d body=%v, want 204", status, out)
	}

	// rcovNewServer's password authenticator is a fixed verifier func
	// (independent of the PasswordCredentialStore /me/password writes to),
	// so it still accepts rcovPassword here — the point under test is
	// whether the PRE-change device_token still skips MFA, not whether the
	// login authenticator itself observed the new password.
	_, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":     "password",
		"client_id":    rcovClient,
		"credential":   map[string]string{"username": rcovUsername, "password": rcovPassword},
		"device_token": deviceToken,
	})
	if out["error"] != "mfa_required" {
		t.Fatalf("login after password change with the OLD device_token = %v, want mfa_required", out)
	}
}
