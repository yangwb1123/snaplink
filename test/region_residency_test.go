package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/geo"
	geostatic "github.com/snaplink/sso/geo/static"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

// These are the live integration tests for the data-residency feature: a
// full *sso.Server over HTTP, the region middleware mounted, and the
// /auth/login residency gate enforcing a tenant's ResidencyPolicy. They are
// the wire-level counterpart to the in-package engine unit tests in
// tenant_residency_test.go (which call checkTenantResidency directly).

const residencyTenantID = "tenant-eu"

// residencyTenant is bound to eu-west-1 and allows ONLY eu-west-1 — any
// other serving region is outside AllowedRegions. EnforceWrites is varied
// per-test by the matrix helpers below.
func residencyTenant(enforceWrites bool, allowed ...string) *tenant.Tenant {
	if len(allowed) == 0 {
		allowed = []string{"eu-west-1"}
	}
	return &tenant.Tenant{
		ID: residencyTenantID, Slug: "eu", Name: "EU", Status: tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: allowed,
		EnforceWrites:  enforceWrites,
	}
}

// residencyFixture builds a server with a tenant-bound client. When resolver
// is non-nil the region middleware is mounted and the residency check enabled;
// when nil neither is wired (the inert / byte-identical path). The client is
// bound to residencyTenantID — clientTenantOK passes (no tenant host resolves
// on these requests), so the residency gate is what decides.
func residencyFixture(t *testing.T, resolver region.Resolver, seed *tenant.Tenant) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		TenantID:              residencyTenantID,
		AllowedAuthenticators: []string{stub.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	tstore := tenantmemory.New()
	if seed != nil {
		if err := tstore.PutTenant(context.Background(), seed); err != nil {
			t.Fatalf("PutTenant: %v", err)
		}
	}
	sink := audit.NewMemorySink(20)
	opts := []sso.Option{
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(stub),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithTenantStore(tstore),
		sso.WithAuditRecorder(audit.New(sink)),
	}
	if resolver != nil {
		opts = append(opts,
			sso.WithRegionMiddleware(resolver, region.MiddlewareOptions{}),
			sso.WithTenantResidencyCheck(0),
		)
	}
	srv := sso.NewServer(opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

// doResidencyLogin posts a login and returns status + decoded body.
func doResidencyLogin(t *testing.T, ts *httptest.Server) (int, map[string]any) {
	t.Helper()
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v body=%s", err, raw)
		}
	}
	return resp.StatusCode, out
}

// TestResidency_DisallowedRegion_LoginRejectedWithIss proves the primary
// control: a login served from a region outside the tenant's AllowedRegions
// is rejected with region_not_allowed, and the RFC 9207 `iss` is PRESENT in
// the error body — proving authzErrorBody (not errorBody) backs the gate.
func TestResidency_DisallowedRegion_LoginRejectedWithIss(t *testing.T) {
	// Pinned to us-east-1, which is NOT in the tenant's allowed set.
	ts, _ := residencyFixture(t, region.ConfigPinnedResolver{Region: "us-east-1"}, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%v)", status, body)
	}
	if got := body[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	// iss MUST be present — this is the §2 RFC 9207 invariant the residency
	// error response shares with every other /auth/login response.
	if iss, ok := body[sso.KeyIss].(string); !ok || iss == "" {
		t.Errorf("iss missing/empty on residency error body: %v", body)
	}
}

// TestResidency_HomeRegion_LoginSucceedsWithServingRegion proves a server
// pinned to the tenant's home region serves the login normally AND surfaces
// serving_region in the success response.
func TestResidency_HomeRegion_LoginSucceedsWithServingRegion(t *testing.T) {
	ts, _ := residencyFixture(t, region.ConfigPinnedResolver{Region: "eu-west-1"}, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%v)", status, body)
	}
	if _, ok := body[sso.KeyAccessToken]; !ok {
		t.Errorf("no access_token on success: %v", body)
	}
	if got := body[sso.KeyServingRegion]; got != "eu-west-1" {
		t.Errorf("serving_region = %v, want eu-west-1", got)
	}
}

// TestResidency_NoRegionWired_LoginSucceeds proves the nil-default
// byte-identical guarantee at the wire level: the SAME constrained tenant +
// client, but with NO WithRegionMiddleware / WithTenantResidencyCheck, logs in
// successfully and carries no serving_region. The middleware isn't installed,
// the gate sees servingRegion=="" and returns nil.
func TestResidency_NoRegionWired_LoginSucceeds(t *testing.T) {
	ts, _ := residencyFixture(t, nil, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inert residency) body=%v", status, body)
	}
	if _, ok := body[sso.KeyAccessToken]; !ok {
		t.Errorf("no access_token despite inert residency: %v", body)
	}
	if _, present := body[sso.KeyServingRegion]; present {
		t.Errorf("serving_region present despite no region middleware: %v", body)
	}
}

// TestResidency_EnforceWritesMatrix proves the write-side semantics. The
// tenant ALLOWS eu-central-1 (a non-home allowed region). Served from there:
//   - EnforceWrites=true  → login (a write/mint) → residency_violation.
//   - EnforceWrites=false → login succeeds (the policy is advisory).
func TestResidency_EnforceWritesMatrix(t *testing.T) {
	const servingNonHomeAllowed = "eu-central-1"
	allowed := []string{"eu-west-1", servingNonHomeAllowed}

	t.Run("enforce_writes_true_blocks", func(t *testing.T) {
		ts, _ := residencyFixture(t,
			region.ConfigPinnedResolver{Region: servingNonHomeAllowed},
			residencyTenant(true, allowed...))

		status, body := doResidencyLogin(t, ts)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%v)", status, body)
		}
		if got := body[sso.KeyError]; got != sso.ErrResidencyViolation {
			t.Errorf("error = %v, want %q", got, sso.ErrResidencyViolation)
		}
		if iss, ok := body[sso.KeyIss].(string); !ok || iss == "" {
			t.Errorf("iss missing on residency_violation body: %v", body)
		}
	})

	t.Run("enforce_writes_false_allows", func(t *testing.T) {
		ts, _ := residencyFixture(t,
			region.ConfigPinnedResolver{Region: servingNonHomeAllowed},
			residencyTenant(false, allowed...))

		status, body := doResidencyLogin(t, ts)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (advisory) body=%v", status, body)
		}
		if got := body[sso.KeyServingRegion]; got != servingNonHomeAllowed {
			t.Errorf("serving_region = %v, want %s", got, servingNonHomeAllowed)
		}
	})
}

// TestResidency_AuditCarriesServingRegionWithoutClobberingGeo proves the audit
// enrichment: a successful login event carries region.serving in Metadata, and
// the geo.* keys (also wired here) are NOT clobbered.
func TestResidency_AuditCarriesServingRegionWithoutClobberingGeo(t *testing.T) {
	// Build the fixture, then ALSO wire geo so we can prove both namespaces
	// coexist. residencyFixture doesn't take a geo provider, so build inline.
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		TenantID:              residencyTenantID,
		AllowedAuthenticators: []string{stub.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	tstore := tenantmemory.New()
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	geoProv := geostatic.New()
	_ = geoProv.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", Region: "US-CA"})
	sink := audit.NewMemorySink(20)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(stub),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithTenantStore(tstore),
		sso.WithGeoProvider(geoProv),
		// Pin to the home region so the login SUCCEEDS (we want a login event).
		sso.WithRegionMiddleware(region.ConfigPinnedResolver{Region: "eu-west-1"}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(0),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.5.6.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	events, err := sink.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var login *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogin {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatalf("no login event recorded; got %d events", len(events))
	}
	if got := login.Metadata["region.serving"]; got != "eu-west-1" {
		t.Errorf("region.serving = %q, want eu-west-1 (full meta=%v)", got, login.Metadata)
	}
	// geo.* must survive alongside region.serving (SetMeta merges, never
	// clobbers — §2 audit-metadata invariant).
	if got := login.Metadata["geo.country_code"]; got != "US" {
		t.Errorf("geo.country_code clobbered: %v", login.Metadata)
	}
	if got := login.Metadata["geo.region"]; got != "US-CA" {
		t.Errorf("geo.region clobbered/conflated with region.serving: %v", login.Metadata)
	}
}

// --- prompt=none silent-renewal residency gate ---------------------------
//
// The credential path's residency gate sits AFTER an earlier prompt=none
// branch that mints a fresh access/id token and returns. Without a gate on
// that branch, a valid-session prompt=none request from a DISALLOWED serving
// region mints tokens, bypassing the primary write control. These tests
// exercise that branch over the full server.

const (
	residencyPromptUserID  = "user-renew"
	residencyPromptClient  = "renew-app"
	residencyPromptPass    = "pw"
	residencyServingHeader = "X-Serving-Region"
)

// residencyRenewalFixture wires a server whose serving region is resolved
// from the X-Serving-Region header (Default = the tenant's home eu-west-1).
// A request with no header resolves to the allowed home region; a request
// carrying the header pins traffic to whatever region it names. That lets one
// server BOTH mint the initial session + id_token_hint from the home region
// AND replay a prompt=none renewal from a disallowed region — exactly the
// silent-renewal-bypass scenario. A JWT issuer (shared access+id) makes the
// minted id_token_hint validate on the second hop.
func residencyRenewalFixture(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: residencyPromptUserID})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    residencyPromptClient,
		Active:                true,
		TenantID:              residencyTenantID,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != residencyPromptPass {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: residencyPromptUserID, Provider: "password"}, nil
		},
	))

	tstore := tenantmemory.New()
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(2 * time.Minute))
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
		// Home region is the header Default — a request without the header
		// resolves to eu-west-1 (allowed). With it, traffic pins to the
		// named region (us-east-1 → disallowed).
		sso.WithRegionMiddleware(region.HeaderResolver{
			Header:  residencyServingHeader,
			Default: "eu-west-1",
		}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(0),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// residencyHomeLogin performs the initial credential login from the home
// region (no serving header) and returns the minted id_token to use as the
// silent-renewal hint.
func residencyHomeLogin(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body := map[string]any{
		"provider":   "password",
		"client_id":  residencyPromptClient,
		"credential": map[string]string{"username": residencyPromptUserID, "password": residencyPromptPass},
		"scope":      []string{"openid"},
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("home login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home login status=%d body=%s", resp.StatusCode, rb)
	}
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	hint, _ := out["id_token"].(string)
	if hint == "" {
		t.Fatalf("no id_token from home login: %v", out)
	}
	return hint
}

// postRenewalFromRegion replays a prompt=none silent renewal carrying the
// serving-region header (empty servingRegion → no header → home region).
func postRenewalFromRegion(t *testing.T, ts *httptest.Server, hint, servingRegion string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"client_id":     residencyPromptClient,
		"prompt":        "none",
		"id_token_hint": hint,
		"scope":         []string{"openid"},
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if servingRegion != "" {
		req.Header.Set(residencyServingHeader, servingRegion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(rb) > 0 {
		_ = json.Unmarshal(rb, &out)
	}
	return resp.StatusCode, out
}

// TestResidency_PromptNone_DisallowedRegion_Blocked is the regression test for
// the silent-renewal bypass: a valid-session prompt=none renewal served from a
// region OUTSIDE the tenant's allowed set must be rejected (403,
// region_not_allowed, iss present) — NOT mint a fresh token. This FAILS
// against the pre-fix code (the prompt=none branch minted before the residency
// gate ran) and passes once that branch is gated.
func TestResidency_PromptNone_DisallowedRegion_Blocked(t *testing.T) {
	ts := residencyRenewalFixture(t)
	hint := residencyHomeLogin(t, ts) // mints session + id_token from home.

	status, body := postRenewalFromRegion(t, ts, hint, "us-east-1")
	if status != http.StatusForbidden {
		t.Fatalf("prompt=none from disallowed region status=%d, want 403 (bypass!) body=%v", status, body)
	}
	if got := body[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	// A blocked renewal must NOT leak a freshly minted token.
	if _, ok := body[sso.KeyAccessToken]; ok {
		t.Errorf("blocked prompt=none renewal still minted an access_token: %v", body)
	}
	// RFC 9207 iss rides the authz error body (§2: authzErrorBody, not errorBody).
	if iss, ok := body[sso.KeyIss].(string); !ok || iss == "" {
		t.Errorf("iss missing/empty on residency-blocked renewal: %v", body)
	}
}

// TestResidency_PromptNone_HomeRegion_Mints proves the gate doesn't break the
// happy path: the same renewal served from the home region succeeds and mints
// a fresh access token.
func TestResidency_PromptNone_HomeRegion_Mints(t *testing.T) {
	ts := residencyRenewalFixture(t)
	hint := residencyHomeLogin(t, ts)

	status, body := postRenewalFromRegion(t, ts, hint, "") // no header → home.
	if status != http.StatusOK {
		t.Fatalf("prompt=none from home region status=%d, want 200 body=%v", status, body)
	}
	if _, ok := body[sso.KeyAccessToken].(string); !ok {
		t.Errorf("home-region renewal minted no access_token: %v", body)
	}
}
