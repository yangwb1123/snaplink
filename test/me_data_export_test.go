package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/compliance"
)

// dataExportExtra is an optional []compliance.SubjectExporter to attach to
// the harness's Exporter, letting individual tests cover the Exporter+Extra
// -> HTTP response path (compliance.SubjectExporters output specifically)
// independently of the cmd/sso-server build-ordering concern covered by
// cmd/sso-server's TestBuildApp_SelfServiceDataExport_* tests.
func newDataExportHarness(t *testing.T, withExport bool, extra ...compliance.SubjectExporter) (*httptest.Server, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice", Email: "alice@example.com", Name: "Alice"})
	sessions := defaultimpl.NewMemorySessionManager()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "exp-app", Secret: "s", Name: "Export App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withExport {
		opts = append(opts, sso.WithSelfServiceDataExport(&compliance.Exporter{Users: users, Sessions: sessions, Extra: extra}))
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "exp-app",
			"credential": map[string]string{"username": "alice", "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login: no token: %v", out)
		}
		return tok
	}
	return hs, loginAs
}

func TestMyDataExport_ReturnsOwnBundle(t *testing.T) {
	srv, loginAs := newDataExportHarness(t, true)
	code, body := doReq(t, srv, http.MethodGet, "/me/data-export", loginAs())
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, body)
	}
	if body["subject"] != "u-alice" {
		t.Errorf("subject = %v, want u-alice", body["subject"])
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("export has no data section: %v", body)
	}
	if u, _ := data["user"].(map[string]any); u == nil || u["id"] != "u-alice" {
		t.Errorf("export user section = %v, want id u-alice", data["user"])
	}
}

func TestMyDataExport_RequiresBearer(t *testing.T) {
	srv, _ := newDataExportHarness(t, true)
	if code, _ := doReq(t, srv, http.MethodGet, "/me/data-export", ""); code != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", code)
	}
}

func TestMyDataExport_NotMountedWithoutExporter(t *testing.T) {
	srv, loginAs := newDataExportHarness(t, false)
	if code, _ := doReq(t, srv, http.MethodGet, "/me/data-export", loginAs()); code != http.StatusNotFound {
		t.Errorf("without exporter = %d, want 404 (unmounted)", code)
	}
}

// TestMyDataExport_IncludesConsentAndMFA drives the Exporter+Extra->HTTP
// response path with real memory consent + MFA-enrollment stores wired as
// SubjectExporters, proving GDPR Art. 15 self-service export now returns the
// same two domains the self-service account-erase path already deletes.
func TestMyDataExport_IncludesConsentAndMFA(t *testing.T) {
	consentStore := defaultimpl.NewMemoryConsentStore()
	if err := consentStore.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID: "u-alice", ClientID: "exp-app", Scopes: []string{"openid"}, GrantedAt: time.Now(),
	}); err != nil {
		t.Fatalf("record consent: %v", err)
	}
	mfaStore := defaultimpl.NewMemoryMFAEnrollmentStore()
	mfaStore.AddFactor("u-alice", sso.MFAEnrolledFactor{ID: "f1", Method: "totp", AddedAt: time.Now()})

	srv, loginAs := newDataExportHarness(t, true, compliance.SubjectExporters(consentStore, mfaStore)...)
	code, body := doReq(t, srv, http.MethodGet, "/me/data-export", loginAs())
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, body)
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("export has no data section: %v", body)
	}
	consentData, ok := data[compliance.ExportKeyConsent].([]any)
	if !ok || len(consentData) != 1 {
		t.Errorf("data.consent = %v, want one grant", data[compliance.ExportKeyConsent])
	}
	mfaData, ok := data[compliance.ExportKeyMFAEnrollments].([]any)
	if !ok || len(mfaData) != 1 {
		t.Errorf("data.mfa_enrollments = %v, want one factor", data[compliance.ExportKeyMFAEnrollments])
	}
}
