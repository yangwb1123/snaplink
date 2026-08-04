package sso_test

// quota_test.go exercises the tenant client-create quota gate wired into the
// RFC 7591 DCR /register path via the RegisterDeps.CheckClientCreateQuota hook
// (retiring the formerly-dead checkQuotaBeforeCreate helper). The session-quota
// path is the enforcement precedent this mirrors: fail-open on a non-quota store
// error, 403 quota_exceeded when the tenant is at its cap.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
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

func TestLogin_SessionQuotaExceededIsSingleForbiddenResponse(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(t.Context(), "t-acme", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	s := newTenantQuotaLoginServer(t, qs, memorystoreidentity.NewMemorySessionManager())
	status, _ := postTenantQuotaLogin(t, s)
	if status != http.StatusOK {
		t.Fatalf("first login = %d, want 200", status)
	}
	status, out := postTenantQuotaLogin(t, s)
	if status != http.StatusForbidden || out["error"] != core.ErrQuotaExceededCode {
		t.Fatalf("second login = %d body=%v, want one 403 quota_exceeded", status, out)
	}
}

type testSessionQuotaReconciler struct {
	core.SessionManager
	store core.TenantQuotaResourceStore
}

type quotaOwningSessionManager struct {
	core.SessionManager
}

func (m quotaOwningSessionManager) CreateWithMeta(context.Context, string, core.SessionMeta) (*core.Session, error) {
	return nil, core.ErrQuotaExceeded
}

func (quotaOwningSessionManager) ReconcileTenantSessionQuota(context.Context, string) error {
	return nil
}

func (quotaOwningSessionManager) ManagesTenantSessionQuota() {}

func TestLogin_SessionQuotaManagerOwnsAdmissionResponse(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	manager := quotaOwningSessionManager{SessionManager: memorystoreidentity.NewMemorySessionManager()}
	s := newTenantQuotaLoginServer(t, qs, manager)
	status, out := postTenantQuotaLogin(t, s)
	if status != http.StatusForbidden || out["error"] != core.ErrQuotaExceededCode {
		t.Fatalf("manager-owned denial = %d body=%v, want 403 quota_exceeded", status, out)
	}
	u, err := qs.GetUsage(t.Context(), "t-acme")
	if err != nil || u.Sessions != 0 {
		t.Fatalf("legacy charge ran for manager-owned quota: usage=%+v err=%v", u, err)
	}
}

func (m testSessionQuotaReconciler) ReconcileTenantSessionQuota(ctx context.Context, tenantID string) error {
	usage, err := m.store.GetResourceUsage(ctx, tenantID, core.ResourceSessions)
	if err != nil {
		return err
	}
	_, err = m.store.ReconcileUsage(ctx, tenantID, core.ResourceSessions, 0, usage.Generation)
	return err
}

func TestLogin_SessionQuotaReconcilesStaleLimitBeforeDeny(t *testing.T) {
	t.Parallel()
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(t.Context(), "t-acme", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	if err := qs.IncrementUsage(t.Context(), "t-acme", core.ResourceSessions, 1); err != nil {
		t.Fatal(err)
	}
	manager := testSessionQuotaReconciler{
		SessionManager: memorystoreidentity.NewMemorySessionManager(), store: qs,
	}
	s := newTenantQuotaLoginServer(t, qs, manager)
	status, out := postTenantQuotaLogin(t, s)
	if status != http.StatusOK {
		t.Fatalf("login after stale-gauge reconciliation = %d body=%v", status, out)
	}
	u, err := qs.GetUsage(t.Context(), "t-acme")
	if err != nil || u.Sessions != 1 {
		t.Fatalf("usage after admitted login = %+v err=%v, want 1", u, err)
	}
}

func newTenantQuotaLoginServer(t *testing.T, quotas core.TenantQuotaStore, sessions core.SessionManager) *rcovServer {
	t.Helper()
	s := rcovNewServer(t, sso.WithTenantQuotaStore(quotas), sso.WithSessionManager(sessions))
	s.clients.AddSeed(&sso.Client{
		ID: "tenant-client", Secret: rcovSecret, Name: "Tenant Client",
		RedirectURIs: []string{rcovRedirect}, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true, TenantID: "t-acme",
	})
	return s
}

func postTenantQuotaLogin(t *testing.T, s *rcovServer) (int, map[string]any) {
	t.Helper()
	return rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": "tenant-client",
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
}

const quotaTokenClient = "quota-token-client"

func addQuotaTokenClient(s *rcovServer) {
	s.clients.AddSeed(&sso.Client{
		ID: quotaTokenClient, Secret: rcovSecret, Name: "Quota Token Client",
		TokenStrategy: "jwt", GrantTypes: []string{sso.GrantClientCredentials},
		Active: true, TenantID: "t-acme",
	})
}

func quotaTokenRequest(t *testing.T, s *rcovServer, idempotencyKey string) (int, http.Header, map[string]any, []byte) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"grant_type": sso.GrantClientCredentials, "client_id": quotaTokenClient, "client_secret": rcovSecret,
	})
	if err != nil {
		t.Fatalf("marshal token request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, s.http.URL+"/token", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new token request: %v", err)
	}
	req.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	out := make(map[string]any)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, resp.Header.Clone(), out, raw
}

func TestTokenRateQuotaExceededUsesStableNoStore429(t *testing.T) {
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(t.Context(), "t-acme", &core.TenantQuota{MaxTokenRate: 1}); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if err := qs.IncrementUsage(t.Context(), "t-acme", core.ResourceTokenRate, 60); err != nil {
		t.Fatalf("prefill token window: %v", err)
	}
	s := rcovNewServer(t, sso.WithTenantQuotaStore(qs))
	addQuotaTokenClient(s)

	status, header, out, raw := quotaTokenRequest(t, s, "")
	if status != http.StatusTooManyRequests || out["error"] != ratelimit.ErrRateLimited {
		t.Fatalf("status=%d body=%s, want 429 %s", status, raw, ratelimit.ErrRateLimited)
	}
	if header.Get("Retry-After") != "1" || header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v, want Retry-After=1 and token no-store headers", header)
	}
	if bytes.Contains(raw, []byte("t-acme")) {
		t.Fatalf("tenant identifier leaked in quota response: %s", raw)
	}
}

func TestTokenRateQuotaIdempotencyReplayCountsOnce(t *testing.T) {
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := qs.SetQuota(t.Context(), "t-acme", &core.TenantQuota{MaxTokenRate: 1}); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if err := qs.IncrementUsage(t.Context(), "t-acme", core.ResourceTokenRate, 59); err != nil {
		t.Fatalf("prefill token window: %v", err)
	}
	cache := defaultimpl.NewMemoryIdempotentCache(time.Hour)
	t.Cleanup(cache.Close)
	s := rcovNewServer(t, sso.WithTenantQuotaStore(qs), sso.WithIdempotentStore(cache))
	addQuotaTokenClient(s)

	firstStatus, _, first, _ := quotaTokenRequest(t, s, "same-operation")
	replayStatus, _, replay, _ := quotaTokenRequest(t, s, "same-operation")
	if firstStatus != http.StatusOK || replayStatus != http.StatusOK || replay["access_token"] != first["access_token"] {
		t.Fatalf("first=%d/%v replay=%d/%v, want cached success", firstStatus, first, replayStatus, replay)
	}
	usage, err := qs.GetUsage(t.Context(), "t-acme")
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.TokenRate != 1 {
		t.Fatalf("token rate = %v, want 1 (59 prefill + one real dispatch, no replay charge)", usage.TokenRate)
	}
}

func TestTokenRateQuotaStoreFailureFailsOpenAndAudits(t *testing.T) {
	s := rcovNewServer(t, sso.WithTenantQuotaStore(faultyQuotaStore{
		TenantQuotaStore: memorystoreidentity.NewMemoryTenantQuotaStore(),
	}))
	addQuotaTokenClient(s)
	status, _, out, _ := quotaTokenRequest(t, s, "")
	if status != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("status=%d body=%v, want fail-open token success", status, out)
	}
	events, err := s.sink.Query(t.Context(), audit.Query{Type: audit.EventTenantQuotaStoreFailure})
	if err != nil || len(events) != 1 {
		t.Fatalf("quota failure events=%d err=%v, want one", len(events), err)
	}
	event := events[0]
	if event.Reason != "increment_failed" || event.TenantID != "t-acme" || event.ClientID != quotaTokenClient ||
		event.Metadata["resource"] != string(core.ResourceTokenRate) {
		t.Fatalf("quota failure event = %+v", event)
	}
}

func TestReleaseDeletedClientQuotaUsesStoredTenant(t *testing.T) {
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	for _, clientID := range []string{"client-1", "client-2"} {
		if _, err := qs.ReserveResource(t.Context(), "t-acme", core.ResourceClients, clientID); err != nil {
			t.Fatalf("ReserveResource(%s): %v", clientID, err)
		}
	}
	srv := sso.NewServer(sso.WithTenantQuotaStore(qs))
	srv.ReleaseDeletedClientQuota(t.Context(), &sso.Client{ID: "client-1", TenantID: "t-acme"})
	// Admin/DCR deletion retries must not decrement another client's unit.
	srv.ReleaseDeletedClientQuota(t.Context(), &sso.Client{ID: "client-1", TenantID: "t-acme"})
	srv.ReleaseDeletedClientQuota(t.Context(), nil)
	usage, err := qs.GetUsage(t.Context(), "t-acme")
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.Clients != 1 {
		t.Fatalf("clients = %d, want 1 after idempotent admin deletion release", usage.Clients)
	}
}

func TestTokenRateQuotaDoesNotChargeFailedClientAuthentication(t *testing.T) {
	qs := memorystoreidentity.NewMemoryTenantQuotaStore()
	s := rcovNewServer(t, sso.WithTenantQuotaStore(qs))
	addQuotaTokenClient(s)
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": sso.GrantClientCredentials, "client_id": quotaTokenClient, "client_secret": "wrong",
	})
	if status != http.StatusUnauthorized || out["error"] != sso.ErrInvalidClient {
		t.Fatalf("status=%d body=%v, want opaque invalid_client", status, out)
	}
	usage, err := qs.GetUsage(t.Context(), "t-acme")
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.TokenRate != 0 {
		t.Fatalf("failed client authentication charged token quota: %v", usage.TokenRate)
	}
}
