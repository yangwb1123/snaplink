package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/tenantcollab"
	tenantcollabmem "github.com/snaplink/sso/domains/tenantcollab/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

// Cross-tenant B2B collaboration test fixtures. "ctc" = cross-tenant
// collaboration. homeClient/guestClient are bound to DIFFERENT tenants
// (TenantID) via Client.TenantID directly — no tenant.Store/middleware is
// needed to exercise the token-exchange gate, since tokExEnforceTenantCollaboration
// reads client.TenantID + the subject_token's originating client's TenantID
// straight off the ClientStore.
const (
	ctcUser        = "u-ctc-guest"
	ctcHomeTenant  = "tenant-home"
	ctcGuestTenant = "tenant-guest"
	ctcHomeClient  = "ctc-home-client"
	ctcGuestClient = "ctc-guest-client"
	ctcSecret      = "ctc-secret"
	ctcAPI         = "https://api.ctc.example.com"
)

// ctcHarness bundles the shared stores so a test can inspect/mutate the
// tenantcollab stores directly after building the server.
type ctcHarness struct {
	srv       *httptest.Server
	extUsers  *tenantcollabmem.ExternalUserStore
	collab    *tenantcollabmem.CollaborationStore
	auditSink *audit.MemorySink
}

func newCrossTenantHarness(t *testing.T, wireStores bool) *ctcHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: ctcUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: ctcHomeClient, Secret: ctcSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		TenantID:              ctcHomeTenant,
	})
	clients.AddSeed(&sso.Client{
		ID: ctcGuestClient, Secret: ctcSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		TenantID:              ctcGuestTenant,
		AllowedResources:      []string{ctcAPI},
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: username, Provider: "password"}, nil
		},
	))

	h := &ctcHarness{
		extUsers:  tenantcollabmem.NewExternalUserStore(),
		collab:    tenantcollabmem.NewCollaborationStore(),
		auditSink: audit.NewMemorySink(100),
	}
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(audit.New(h.auditSink)),
	}
	if wireStores {
		opts = append(opts, sso.WithExternalUserStore(h.extUsers), sso.WithTenantCollaborationStore(h.collab))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	h.srv = httpSrv
	return h
}

func ctcLogin(t *testing.T, srv *httptest.Server, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": ctcUser, "password": "y"},
		"scope":      []string{"read", "write"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %v (status=%d)", out, resp.StatusCode)
	}
	return tok
}

func ctcExchange(t *testing.T, srv *httptest.Server, subjectTok, scope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {ctcGuestClient},
		"client_secret":      {ctcSecret},
		"subject_token":      {subjectTok},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {ctcAPI},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestCrossTenant_UnwiredIsNoOp proves that without WithExternalUserStore /
// WithTenantCollaborationStore, a cross-tenant exchange (different client
// tenants) behaves exactly as it did before this feature existed — no new
// restriction appears unless the operator opts in.
func TestCrossTenant_UnwiredIsNoOp(t *testing.T) {
	h := newCrossTenantHarness(t, false)
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	status, body := ctcExchange(t, h.srv, subjectTok, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — feature unwired, byte-identical to pre-feature)", status, body)
	}
}

// TestCrossTenant_DeniedWithNoTrustOrRegistration proves the fail-closed
// default: wiring BOTH stores with nothing seeded denies every cross-tenant
// hop (no accidental widening of tenant isolation).
func TestCrossTenant_DeniedWithNoTrustOrRegistration(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	status, body := ctcExchange(t, h.srv, subjectTok, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v (want 400 invalid_grant — no trust, no registration)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestCrossTenant_DeniedWithTrustButNoRegistration proves a tenant-level
// TenantCollaboration trust row ALONE is not sufficient — the specific
// subject must ALSO be registered via ExternalUserStore.
func TestCrossTenant_DeniedWithTrustButNoRegistration(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	ctx := context.Background()
	if err := h.collab.Put(ctx, &tenantcollab.TenantCollaboration{
		GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant,
	}); err != nil {
		t.Fatalf("Put collaboration: %v", err)
	}
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	status, body := ctcExchange(t, h.srv, subjectTok, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v (want 400 invalid_grant — trusted tenant but unregistered subject)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestCrossTenant_DeniedWithRegistrationButNoTrust proves an ExternalUserStore
// registration ALONE is not sufficient without the tenant-level trust row.
func TestCrossTenant_DeniedWithRegistrationButNoTrust(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	ctx := context.Background()
	if err := h.extUsers.Add(ctx, &tenantcollab.GuestRecord{
		GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant, ExternalSubjectID: ctcUser,
	}); err != nil {
		t.Fatalf("Add guest record: %v", err)
	}
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	status, body := ctcExchange(t, h.srv, subjectTok, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v (want 400 invalid_grant — registered subject but untrusted tenant)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestCrossTenant_AllowedWithTrustAndRegistration is the full happy path:
// BOTH the tenant-level trust AND the per-subject guest registration are
// present, so the cross-tenant exchange succeeds — and the resulting audit
// trail carries original_subject/original_tenant so a SIEM can trace the
// guest action back to its home account (item 4).
func TestCrossTenant_AllowedWithTrustAndRegistration(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	ctx := context.Background()
	if err := h.collab.Put(ctx, &tenantcollab.TenantCollaboration{
		GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant,
	}); err != nil {
		t.Fatalf("Put collaboration: %v", err)
	}
	if err := h.extUsers.Add(ctx, &tenantcollab.GuestRecord{
		GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant, ExternalSubjectID: ctcUser,
		Roles: []string{"read", "write"},
	}); err != nil {
		t.Fatalf("Add guest record: %v", err)
	}
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	status, body := ctcExchange(t, h.srv, subjectTok, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — trusted tenant + registered guest)", status, body)
	}
	if body["access_token"] == "" || body["access_token"] == nil {
		t.Fatalf("expected access_token in %v", body)
	}

	events, err := h.auditSink.Query(ctx, audit.Query{Type: audit.EventCrossTenantTokenExchange})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 cross_tenant_token_exchange event, got %d", len(events))
	}
	evt := events[0]
	if evt.Metadata["original_subject"] != ctcUser {
		t.Errorf("original_subject=%q want %q", evt.Metadata["original_subject"], ctcUser)
	}
	if evt.Metadata["original_tenant"] != ctcHomeTenant {
		t.Errorf("original_tenant=%q want %q", evt.Metadata["original_tenant"], ctcHomeTenant)
	}
	if evt.Metadata["guest_tenant_id"] != ctcGuestTenant {
		t.Errorf("guest_tenant_id=%q want %q", evt.Metadata["guest_tenant_id"], ctcGuestTenant)
	}
}

// TestCrossTenant_GuestRolesNarrowScope proves a GuestRecord's Roles further
// narrow the exchanged scope — requesting a scope outside the guest's Roles
// is rejected with invalid_scope, never silently dropped or widened.
func TestCrossTenant_GuestRolesNarrowScope(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	ctx := context.Background()
	_ = h.collab.Put(ctx, &tenantcollab.TenantCollaboration{GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant})
	_ = h.extUsers.Add(ctx, &tenantcollab.GuestRecord{
		GuestTenantID: ctcGuestTenant, HomeTenantID: ctcHomeTenant, ExternalSubjectID: ctcUser,
		Roles: []string{"read"}, // deliberately excludes "write"
	})
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	// Requesting only "read" (within the guest's Roles) succeeds.
	status, body := ctcExchange(t, h.srv, subjectTok, "read")
	if status != http.StatusOK {
		t.Fatalf("read-only status=%d body=%v (want 200)", status, body)
	}

	// Requesting "write" (outside the guest's Roles) is rejected.
	status, body = ctcExchange(t, h.srv, subjectTok, "write")
	if status != http.StatusBadRequest {
		t.Fatalf("write status=%d body=%v (want 400 invalid_scope — outside guest Roles)", status, body)
	}
	if body["error"] != sso.ErrInvalidScope {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidScope)
	}
}

// TestCrossTenant_SameTenantExchangeUnaffected proves the gate never fires
// for a same-tenant exchange, even with both stores wired and nothing
// seeded — there is no cross-tenant boundary here for it to police.
func TestCrossTenant_SameTenantExchangeUnaffected(t *testing.T) {
	h := newCrossTenantHarness(t, true)
	// Log in AND exchange via the SAME (home) client/tenant.
	subjectTok := ctcLogin(t, h.srv, ctcHomeClient)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {ctcHomeClient},
		"client_secret":      {ctcSecret},
		"subject_token":      {subjectTok},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	resp, err := http.PostForm(h.srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s (want 200 — same-tenant exchange must be unaffected)", resp.StatusCode, raw)
	}
}
