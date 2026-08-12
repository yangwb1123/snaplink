package sso_test

// rootcov2_tenant_roles_test.go drives the tenant_id + roles claims through
// the real login orchestrator (AC-6 family): tenant-bound direct-mint login
// with a seeded roster, JIT provisioning ordering, no-membership, tenant-less
// byte-compat, pairwise-subject keying, the store-outage fail-open with audit
// event, and the roles-preserved-across-refresh-rotation pin.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// trrDecodePayload returns the decoded payload map of a compact JWS.
func trrDecodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	pl := map[string]any{}
	if err := json.Unmarshal(raw, &pl); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	return pl
}

// trrRoles reads the `roles` claim as a string slice, nil when absent.
func trrRoles(t *testing.T, payload map[string]any) []string {
	t.Helper()
	raw, present := payload["roles"]
	if !present {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("roles claim is not an array: %v", raw)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("roles element not a string: %v", v)
		}
		out = append(out, s)
	}
	return out
}

// trrErroringTenantStore is the error-injecting core.TenantUserStore stub
// (fault injection, not a mock — MemoryTenantUserStore.Get can only return
// ErrNoMembership or nil, so an outage needs a stub).
type trrErroringTenantStore struct{ err error }

func (t *trrErroringTenantStore) Add(context.Context, *sso.TenantMembership) error { return nil }
func (t *trrErroringTenantStore) Remove(context.Context, string, string) error     { return nil }
func (t *trrErroringTenantStore) Get(context.Context, string, string) (*sso.TenantMembership, error) {
	return nil, t.err
}
func (t *trrErroringTenantStore) ListByTenant(context.Context, string) ([]*sso.TenantMembership, error) {
	return nil, nil
}
func (t *trrErroringTenantStore) ListByUser(context.Context, string) ([]*sso.TenantMembership, error) {
	return nil, nil
}

// trrCapturingLogger counts Error calls so the fail-open path can assert it
// logged the outage (tenant_residency_test.go pattern).
type trrCapturingLogger struct{ errors atomic.Int64 }

func (l *trrCapturingLogger) Info(string, ...any)  {}
func (l *trrCapturingLogger) Debug(string, ...any) {}
func (l *trrCapturingLogger) Error(string, ...any) { l.errors.Add(1) }

// trrLogin drives one direct-mint password login and returns the decoded
// access-token payload.
func trrLogin(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	status, out := rcovPostJSON(t, srv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token minted: %v", out)
	}
	return trrDecodePayload(t, tok)
}

// trrRolesServer wires the minimal server for the roles claim variants.
// mutate (optional) adjusts the seeded client before NewServer — the pairwise
// variant uses it to set SubjectType, which must be seeded on the client.
func trrRolesServer(t *testing.T, tenantID string, roster *defaultimpl.MemoryTenantUserStore, mutate func(*sso.Client), opts ...sso.Option) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser, Email: "alice@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	client := &sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true, TenantID: tenantID,
	}
	if mutate != nil {
		mutate(client)
	}
	clients.AddSeed(client)
	sink := audit.NewMemorySink(50)
	base := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(audit.New(sink)),
	}
	if roster != nil {
		base = append(base, sso.WithTenantUserStore(roster))
	}
	srv := sso.NewServer(append(base, opts...)...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

// TestRcov2TR_TenantBoundLoginCarriesClaims is AC-6 base: a tenant-bound
// client whose user is a roster member mints a token carrying tenant_id (the
// client binding) and roles (the membership role).
func TestRcov2TR_TenantBoundLoginCarriesClaims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	roster := defaultimpl.NewMemoryTenantUserStore()
	_ = roster.Add(ctx, &sso.TenantMembership{
		TenantID: "tenant-acme", UserID: rcovUser, Role: core.TenantRoleMember, CreatedAt: time.Now(),
	})
	srv, _ := trrRolesServer(t, "tenant-acme", roster, nil)

	payload := trrLogin(t, srv)
	if got := payload["tenant_id"]; got != "tenant-acme" {
		t.Errorf("tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, payload); len(got) != 1 || got[0] != "member" {
		t.Errorf("roles = %v, want [member]", got)
	}
}

// TestRcov2TR_JITProvisionedRoleVisibleOnFirstLogin pins the JIT ordering:
// ensureJITMembership runs BEFORE the mint, so a user auto-provisioned on
// this login already sees roles:["member"] on the very first token.
func TestRcov2TR_JITProvisionedRoleVisibleOnFirstLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	roster := defaultimpl.NewMemoryTenantUserStore()
	srv, _ := trrRolesServer(t, "tenant-acme", roster, nil, sso.WithJITMembership())

	payload := trrLogin(t, srv)
	if got := payload["tenant_id"]; got != "tenant-acme" {
		t.Errorf("tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, payload); len(got) != 1 || got[0] != "member" {
		t.Errorf("roles = %v, want [member] (JIT provisioned before the mint)", got)
	}
	if _, err := roster.Get(ctx, "tenant-acme", rcovUser); err != nil {
		t.Errorf("JIT membership not persisted: %v", err)
	}
}

// TestRcov2TR_NoMembershipOmitsRoles pins the fail-open collapse: a
// tenant-bound client whose user is NOT on the roster mints tenant_id but
// NO roles claim (absence, not an error).
func TestRcov2TR_NoMembershipOmitsRoles(t *testing.T) {
	t.Parallel()
	srv, _ := trrRolesServer(t, "tenant-acme", defaultimpl.NewMemoryTenantUserStore(), nil)

	payload := trrLogin(t, srv)
	if got := payload["tenant_id"]; got != "tenant-acme" {
		t.Errorf("tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, payload); got != nil {
		t.Errorf("roles = %v, want absent (no membership, no JIT)", got)
	}
}

// TestRcov2TR_TenantLessStaysByteCompatible: no tenant binding -> neither
// claim appears on the wire.
func TestRcov2TR_TenantLessStaysByteCompatible(t *testing.T) {
	t.Parallel()
	srv, _ := trrRolesServer(t, "", nil, nil)

	payload := trrLogin(t, srv)
	if _, present := payload["tenant_id"]; present {
		t.Error("tenant_id present despite tenant-less client")
	}
	if _, present := payload["roles"]; present {
		t.Error("roles present despite tenant-less client")
	}
}

// TestRcov2TR_PairwiseSubjectStillResolvesRoles pins the pairwise keying:
// with a pairwise client the token sub is the per-sector pseudonym, but
// roles resolve from the LOCAL subject (the store is keyed (TenantID,
// UserID)); the pseudonym keyed lookup would fail open to empty.
func TestRcov2TR_PairwiseSubjectStillResolvesRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	roster := defaultimpl.NewMemoryTenantUserStore()
	_ = roster.Add(ctx, &sso.TenantMembership{
		TenantID: "tenant-acme", UserID: rcovUser, Role: core.TenantRoleAdmin, CreatedAt: time.Now(),
	})
	srv, _ := trrRolesServer(t, "tenant-acme", roster, func(c *sso.Client) {
		c.SubjectType = security.SubjectTypePairwise
	},
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
		sso.WithPairwiseSalt("trr-pairwise-salt"),
	)

	status, out := rcovPostJSON(t, srv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	tok, _ := out["access_token"].(string)
	payload := trrDecodePayload(t, tok)
	sub, _ := payload["sub"].(string)
	if sub == "" || sub == rcovUser {
		t.Fatalf("pairwise sub not applied: sub=%q", sub)
	}
	if got := payload["tenant_id"]; got != "tenant-acme" {
		t.Errorf("tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, payload); len(got) != 1 || got[0] != "admin" {
		t.Errorf("roles = %v, want [admin] (resolved from the LOCAL subject, not the pseudonym %q)", got, sub)
	}
}

// TestRcov2TR_StoreOutageFailsOpenMintsTokenWithoutRoles pins the fail-open
// contract on the deliverable: a roster outage still mints a valid token
// (tenant_id present, roles omitted), logs the failure, and records the
// role_resolution_failed audit event (details-only-in-audit).
func TestRcov2TR_StoreOutageFailsOpenMintsTokenWithoutRoles(t *testing.T) {
	t.Parallel()
	logger := &trrCapturingLogger{}
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser, Email: "alice@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true, TenantID: "tenant-acme",
	})
	sink := audit.NewMemorySink(50)
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithTenantUserStore(&trrErroringTenantStore{err: errors.New("roster store down")}),
		sso.WithLogger(logger),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	payload := trrLogin(t, httpSrv)
	if got := payload["tenant_id"]; got != "tenant-acme" {
		t.Errorf("tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, payload); got != nil {
		t.Errorf("roles = %v, want absent (fail-open outage)", got)
	}
	if n := logger.errors.Load(); n == 0 {
		t.Error("fail-open outage was not logged")
	}
	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventRoleResolutionFailed})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("role_resolution_failed audit event missing on outage")
	}
	if e := events[0]; e.TenantID != "tenant-acme" || e.ClientID != rcovClient || e.ActorID != rcovUser {
		t.Errorf("audit event = %+v, want tenant/client/actor stamped", e)
	}
}

// TestRcov2TR_RolesSurviveRefreshRotation pins the propagate-unchanged
// lineage: a direct-mint login's server-managed refresh token carries the
// roles vector, so the FIRST rotation re-mints the SAME roles claim instead
// of silently dropping it mid-session.
func TestRcov2TR_RolesSurviveRefreshRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	roster := defaultimpl.NewMemoryTenantUserStore()
	_ = roster.Add(ctx, &sso.TenantMembership{
		TenantID: "tenant-acme", UserID: rcovUser, Role: core.TenantRoleMember, CreatedAt: time.Now(),
	})
	srv, _ := trrRolesServer(t, "tenant-acme", roster, nil)

	status, out := rcovPostJSON(t, srv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	first := trrDecodePayload(t, out["access_token"].(string))
	if got := trrRoles(t, first); len(got) != 1 || got[0] != "member" {
		t.Fatalf("first token roles = %v, want [member]", got)
	}
	refresh, _ := out["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no server-managed refresh token issued at direct-mint login")
	}

	status, out = rcovPostJSON(t, srv.URL+"/token", "", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("refresh rotation = %d body=%v", status, out)
	}
	rotated := trrDecodePayload(t, out["access_token"].(string))
	if got := rotated["tenant_id"]; got != "tenant-acme" {
		t.Errorf("rotated tenant_id = %v, want tenant-acme", got)
	}
	if got := trrRoles(t, rotated); len(got) != 1 || got[0] != "member" {
		t.Errorf("rotated roles = %v, want [member] (lineage must survive rotation)", got)
	}
}
