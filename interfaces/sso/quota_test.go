package sso_test

// quota_test.go exercises the tenant client-create quota gate wired into the
// RFC 7591 DCR /register path via the RegisterDeps.CheckClientCreateQuota hook
// (retiring the formerly-dead checkQuotaBeforeCreate helper). The session-quota
// path is the enforcement precedent this mirrors: fail-open on a non-quota store
// error, 403 quota_exceeded when the tenant is at its cap.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// dcrRegisterBody is the minimal RFC 7591 metadata a tenant-scoped register
// needs; tenant is honored only when the endpoint is IAT-gated (open
// registration drops it — see registrationTenant).
func dcrRegisterBody(tenant string) map[string]any {
	return map[string]any{
		"client_name":   "quota-probe",
		"tenant_id":     tenant,
		"redirect_uris": []string{"https://quota.example.com/cb"},
	}
}

// TestDCRRegister_QuotaExceeded proves the client-create quota is now LIVE on
// the DCR path: with MaxClients=1 the first tenant-scoped register succeeds and
// the second is rejected 403 quota_exceeded (governance code, not an oracle).
func TestDCRRegister_QuotaExceeded(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(context.Background(), "t-acme", &core.TenantQuota{MaxClients: 1}); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	// AllowOpenRegistration MUST stay false so registrationTenant honors the
	// body tenant_id (open registration is anonymous, hence tenant-less).
	s := rcovNewServer(t,
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{InitialAccessToken: "iat", DefaultActive: true}),
		sso.WithTenantQuotaStore(qs),
	)

	status, out := rcovPostJSON(t, s.http.URL+"/register", "iat", dcrRegisterBody("t-acme"))
	if status != http.StatusCreated {
		t.Fatalf("first register = %d body=%v, want 201", status, out)
	}

	status, out = rcovPostJSON(t, s.http.URL+"/register", "iat", dcrRegisterBody("t-acme"))
	if status != http.StatusForbidden {
		t.Fatalf("second register = %d body=%v, want 403", status, out)
	}
	if got := out["error"]; got != core.ErrQuotaExceededCode {
		t.Fatalf("error = %v, want %s", got, core.ErrQuotaExceededCode)
	}
}

// TestDCRRegister_QuotaFailOpen proves the DCR path fails OPEN on a non-quota
// store error (the AGENTS.md §3 governance posture the session path uses): a
// store outage must never block client creation.
func TestDCRRegister_QuotaFailOpen(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t,
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{InitialAccessToken: "iat", DefaultActive: true}),
		sso.WithTenantQuotaStore(faultyQuotaStore{
			TenantQuotaStore: memorystoreidentity.NewMemoryTenantQuotaStore(),
		}),
	)
	status, out := rcovPostJSON(t, s.http.URL+"/register", "iat", dcrRegisterBody("t-acme"))
	if status != http.StatusCreated {
		t.Fatalf("register under store outage = %d body=%v, want 201 (fail-open)", status, out)
	}
}

// TestDCRRegister_OpenRegistrationTenantless proves an open-registration client
// is tenant-less (registrationTenant returns ""), so the quota hook short-
// circuits and a configured per-tenant cap never gates anonymous registration.
func TestDCRRegister_OpenRegistrationTenantless(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(context.Background(), "t-acme", &core.TenantQuota{MaxClients: 1}); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	s := rcovNewServer(t,
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true}),
		sso.WithTenantQuotaStore(qs),
	)
	// Both succeed: the body tenant_id is dropped under open registration, so
	// the hook no-ops on an empty tenant regardless of the cap.
	for i := 0; i < 2; i++ {
		status, out := rcovPostJSON(t, s.http.URL+"/register", "", dcrRegisterBody("t-acme"))
		if status != http.StatusCreated {
			t.Fatalf("open register #%d = %d body=%v, want 201", i+1, status, out)
		}
	}
	// The tenant counter must be untouched (nothing was ever charged).
	u, err := qs.GetUsage(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if u.Clients != 0 {
		t.Fatalf("tenant clients charged for open registration = %d, want 0", u.Clients)
	}
}

// faultyQuotaStore wraps a real quota store but forces IncrementUsage to fail
// with a non-ErrQuotaExceeded error, so tests can assert the fail-open path.
// It is a fault injector, not a behavior mock — MemoryTenantQuotaStore cannot
// itself simulate a store outage.
type faultyQuotaStore struct {
	core.TenantQuotaStore
}

func (faultyQuotaStore) IncrementUsage(context.Context, string, core.ResourceType, int64) error {
	return errors.New("quota store unavailable")
}

// addFailingClientStore wraps a real ClientStore but forces Add to fail, so
// tests can prove a client-create quota charge is released when persistence
// fails AFTER the charge — a fault injector, not a behavior mock.
type addFailingClientStore struct {
	core.ClientStore
}

func (addFailingClientStore) Add(context.Context, *core.Client) error {
	return errors.New("client store unavailable")
}

// TestDCRRegister_QuotaReleasedOnPersistFailure proves the client-create
// quota charge is released when the client-store write fails afterward —
// closing the leak where a transient persist failure permanently
// over-counted the tenant's usage (no compensating decrement previously
// existed at all).
func TestDCRRegister_QuotaReleasedOnPersistFailure(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	s := rcovNewServer(t,
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{InitialAccessToken: "iat", DefaultActive: true}),
		sso.WithTenantQuotaStore(qs),
		sso.WithClientStore(addFailingClientStore{ClientStore: memorystoreidentity.NewMemoryClientStore()}),
	)

	status, _ := rcovPostJSON(t, s.http.URL+"/register", "iat", dcrRegisterBody("t-acme"))
	if status != http.StatusInternalServerError {
		t.Fatalf("register with forced persist failure = %d, want 500", status)
	}

	u, err := qs.GetUsage(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if u.Clients != 0 {
		t.Fatalf("tenant client quota not released after persist failure: clients = %d, want 0", u.Clients)
	}
}

// createFailingSessionManager wraps a real SessionManager but forces Create
// to fail. Deliberately does NOT implement SessionMetaCreator (only the base
// core.SessionManager is embedded) so createSession's type-assertion falls
// back to the plain Create path this wrapper intercepts.
type createFailingSessionManager struct {
	core.SessionManager
}

func (createFailingSessionManager) Create(context.Context, string) (*core.Session, error) {
	return nil, errors.New("session store unavailable")
}

// TestLogin_SessionQuotaReleasedOnCreateFailure proves the tenant session
// quota charge is released when session-store Create fails afterward —
// closing the leak where a transient session-store failure permanently
// over-counted the tenant's session usage (no compensating decrement
// previously existed at all).
func TestLogin_SessionQuotaReleasedOnCreateFailure(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	s := rcovNewServer(t,
		sso.WithTenantQuotaStore(qs),
		sso.WithSessionManager(createFailingSessionManager{SessionManager: memorystoreidentity.NewMemorySessionManager()}),
	)
	s.clients.AddSeed(&sso.Client{
		ID: "tenant-client", Secret: rcovSecret, Name: "Tenant Client",
		RedirectURIs: []string{rcovRedirect}, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true, TenantID: "t-acme",
	})

	status, _ := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  "tenant-client",
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusInternalServerError {
		t.Fatalf("login with forced session-create failure = %d, want 500", status)
	}

	u, err := qs.GetUsage(context.Background(), "t-acme")
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if u.Sessions != 0 {
		t.Fatalf("tenant session quota not released after create failure: sessions = %d, want 0", u.Sessions)
	}
}
