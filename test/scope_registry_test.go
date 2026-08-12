package ssotest

// B4-2 scope-registry e2e acceptance (T-8(d)): the global scope registry
// (scope-matrix-v2) gates /token issuance when wired; the default-unwired
// server stays byte-identical. Named pins: A-1b (byte-identical rejection
// body), rows 2-6 of the design acceptance table, A-8a..A-8f.
//
// Jurisdiction: /token only. Login direct mints are NOT registry-checked
// (their scopes surface at /token refresh, where they ARE checked) — that is
// exactly the pre-enablement family scenario A-8b pins.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/scopecontract"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
)

const (
	srUser       = "u-sr"
	srClientReg  = "sr-matrix"
	srClientAny  = "sr-unrestricted"
	srSecret     = "sr-secret"
	srIssuer     = "https://sso-sr.test"
	srOIDCScopes = "openid profile email address phone offline_access"
)

// srRegistry builds the shipped Memory registry: nine-scope matrix + the
// pre-seeded OIDC protocol set.
func srRegistry(t *testing.T) *scoperegistry.Memory {
	t.Helper()
	reg, err := scoperegistry.NewMemory(scopecontract.Matrix(), nil)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	return reg
}

// srSeedClients seeds a matrix-allowlist client (its own allowlist is the
// same nine scopes, so minting is allowlist- and registry-conformant) and an
// unrestricted client (nil allowlist — the registry is then the ONLY gate).
func srSeedClients(clients *defaultimpl.MemoryClientStore) {
	clients.AddSeed(&sso.Client{
		ID: srClientReg, Secret: srSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         scopecontract.Matrix(),
	})
	clients.AddSeed(&sso.Client{
		ID: srClientAny, Secret: srSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// nil AllowedScopes ⇒ unrestricted — the registry is the only gate.
	})
}

// newScopeRegistryHarness builds a server with the registry WIRED
// (registryOn=true) or unwired (registryOn=false — the byte-compat baseline).
func newScopeRegistryHarness(t *testing.T, registryOn bool) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: srUser})
	clients := defaultimpl.NewMemoryClientStore()
	srSeedClients(clients)
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: srUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithIssuer(srIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	}
	if registryOn {
		opts = append(opts, sso.WithScopeRegistry(srRegistry(t)))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// srCC mints a client_credentials token and returns status + raw body + parsed.
func srCC(t *testing.T, srv *httptest.Server, clientID, scope string) (int, string, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {srSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, string(raw), out
}

// srRefreshRaw presents a refresh token and returns status + raw body + parsed.
func srRefreshRaw(t *testing.T, srv *httptest.Server, refresh, scope string) (int, string, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {srClientAny},
		"client_secret": {srSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, string(raw), out
}

// srLogin mints via /auth/login direct mint — OUTSIDE the registry
// jurisdiction, the documented pre-enablement-family source.
func srLogin(t *testing.T, srv *httptest.Server, clientID string, scopes []string) (int, map[string]any) {
	t.Helper()
	return scPostJSON(t, srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     clientID,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         scopes,
	})
}

// Row 2: all nine scope-matrix-v2 scopes mint 200 under enabled mode.
func TestScopeRegistry_MatrixScopesMintable(t *testing.T) {
	srv := newScopeRegistryHarness(t, true)
	for _, sc := range scopecontract.Matrix() {
		st, raw, out := srCC(t, srv, srClientReg, sc)
		if st != http.StatusOK {
			t.Fatalf("scope %q: status=%d body=%s", sc, st, raw)
		}
		if out["scope"] != sc {
			t.Errorf("scope %q: token scope = %v", sc, out["scope"])
		}
	}
	// admin:* also covers concrete admin:read/admin:write under its prefix.
	for _, sc := range []string{"admin:read", "admin:write"} {
		if st, raw, _ := srCC(t, srv, srClientReg, sc); st != http.StatusOK {
			t.Fatalf("scope %q via admin:* pattern: status=%d body=%s", sc, st, raw)
		}
	}
}

// A-1b + A-8f: the registry rejection is byte-identical to the allowlist
// rejection — plain {"error":"invalid_scope"}, no trace_id — across clients
// and branches, so a client cannot distinguish registry state.
func TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody(t *testing.T) {
	srv := newScopeRegistryHarness(t, true)

	// Allowlist rejection (pre-existing gate) on the same server.
	stAllow, rawAllow, _ := srCC(t, srv, srClientReg, "admin:read billing:typo")
	if stAllow != http.StatusBadRequest {
		t.Fatalf("allowlist rejection status=%d body=%s", stAllow, rawAllow)
	}
	// Registry rejection (unrestricted client — registry is the only gate).
	stReg, rawReg, _ := srCC(t, srv, srClientAny, "billing:typo")
	if stReg != http.StatusBadRequest {
		t.Fatalf("registry rejection status=%d body=%s", stReg, rawReg)
	}
	// A-8f: mixed registered + unregistered on the unrestricted client.
	stMix, rawMix, out := srCC(t, srv, srClientAny, "profile billing:typo")
	if stMix != http.StatusBadRequest {
		t.Fatalf("mixed status=%d body=%s", stMix, rawMix)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("mixed error = %v want invalid_scope", out["error"])
	}
	want := `{"error":"invalid_scope"}`
	for name, got := range map[string]string{"allowlist": rawAllow, "registry": rawReg, "mixed": rawMix} {
		if strings.TrimSpace(got) != want {
			t.Errorf("%s body = %q, want byte-identical %q (no trace_id)", name, got, want)
		}
		if strings.Contains(got, "trace_id") {
			t.Errorf("%s body leaks trace_id: %q", name, got)
		}
	}
}

// A-8a: the five OIDC standard scopes stay mintable under an enabled registry
// (they are pre-seeded protocol scopes, not matrix members — a matrix-only
// registry would 400 here). client_credentials is the sharpest direct-mint.
func TestScopeRegistry_OIDCStandardScopesMintableAcrossGrants(t *testing.T) {
	srv := newScopeRegistryHarness(t, true)
	st, raw, out := srCC(t, srv, srClientAny, srOIDCScopes)
	if st != http.StatusOK {
		t.Fatalf("cc with OIDC scopes: status=%d body=%s", st, raw)
	}
	got, _ := out["scope"].(string)
	for _, sc := range strings.Split(srOIDCScopes, " ") {
		if !strings.Contains(got, sc) {
			t.Errorf("token scope %q missing %q", got, sc)
		}
	}
	// device_sso (Native SSO trigger) is also pre-seeded.
	if st, raw, _ := srCC(t, srv, srClientAny, "openid device_sso profile"); st != http.StatusOK {
		t.Fatalf("cc with device_sso: status=%d body=%s", st, raw)
	}
}

// A-8b: refresh-chain conformance. A family minted OUTSIDE /token (login
// direct mint — the webauthn analog) with OIDC scopes refreshes fine; a
// family carrying an UNREGISTERED scope fails closed at the next rotation
// with the byte-identical plain invalid_scope body (FM-6 drain window).
func TestScopeRegistry_RefreshChainPreservesOIDCScopes(t *testing.T) {
	srv := newScopeRegistryHarness(t, true)

	t.Run("oidc family survives rotation", func(t *testing.T) {
		st, login := srLogin(t, srv, srClientAny, strings.Split(srOIDCScopes, " "))
		if st != http.StatusOK {
			t.Fatalf("login: status=%d body=%v", st, login)
		}
		refresh, _ := login["refresh_token"].(string)
		if refresh == "" {
			t.Fatalf("no refresh token: %v", login)
		}
		// Omitted scope keeps the family scopes; subset narrows.
		for _, scope := range []string{"", "openid profile"} {
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
				"client_id":     {srClientAny},
				"client_secret": {srSecret},
			}
			if scope != "" {
				form.Set("scope", scope)
			}
			st, out := scPostForm(t, srv, "/token", form)
			if st != http.StatusOK {
				t.Fatalf("refresh scope=%q: status=%d body=%v", scope, st, out)
			}
			refresh, _ = out["refresh_token"].(string)
			if refresh == "" {
				t.Fatal("rotation lost the refresh token")
			}
		}
	})

	t.Run("pre-enablement family fails closed at rotation", func(t *testing.T) {
		// Direct mint (outside /token jurisdiction) with an unregistered
		// scope — exactly a family minted before the registry flip.
		st, login := srLogin(t, srv, srClientAny, []string{"anything"})
		if st != http.StatusOK {
			t.Fatalf("login: status=%d body=%v", st, login)
		}
		refresh, _ := login["refresh_token"].(string)
		if refresh == "" {
			t.Fatal("no refresh token")
		}
		st, raw, out := srRefreshRaw(t, srv, refresh, "")
		if st != http.StatusBadRequest {
			t.Fatalf("refresh of unregistered family: status=%d body=%s", st, raw)
		}
		if out["error"] != sso.ErrInvalidScope {
			t.Fatalf("error = %v want invalid_scope", out["error"])
		}
		if strings.TrimSpace(raw) != `{"error":"invalid_scope"}` || strings.Contains(raw, "trace_id") {
			t.Fatalf("body = %q, want byte-identical plain invalid_scope (no trace_id)", raw)
		}
	})
}

// A-8d: under an enabled registry scopes_supported must not advertise a scope
// /token rejects (anything is filtered; OIDC standard scopes survive the
// pre-seed). Registry-off stays the full union — byte-identical to HEAD.
func TestScopeRegistry_DiscoveryAdvertisesOnlyRegistered(t *testing.T) {
	clients := func() *defaultimpl.MemoryClientStore {
		c := defaultimpl.NewMemoryClientStore()
		c.AddSeed(&sso.Client{
			ID: "sr-disco", Secret: "s", Active: true,
			AllowedScopes: []string{"openid", "profile", "email", "anything"},
		})
		return c
	}
	build := func(registryOn bool) *httptest.Server {
		t.Helper()
		issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
		opts := []sso.Option{
			sso.WithIssuer(srIssuer),
			sso.WithClientStore(clients()),
			sso.WithTokenIssuer("jwt", issuer),
			sso.WithDefaultTokenStrategy("jwt"),
			sso.WithIDTokenIssuer(issuer),
		}
		if registryOn {
			opts = append(opts, sso.WithScopeRegistry(srRegistry(t)))
		}
		srv := sso.NewServer(opts...)
		httpSrv := httptest.NewServer(srv.Handler())
		t.Cleanup(httpSrv.Close)
		return httpSrv
	}
	scopes := func(srv *httptest.Server) map[string]bool {
		t.Helper()
		doc := fetchDiscovery(t, srv)
		raw, _ := doc["scopes_supported"].([]any)
		out := map[string]bool{}
		for _, s := range raw {
			v, _ := s.(string)
			out[v] = true
		}
		return out
	}
	on := scopes(build(true))
	if on["anything"] {
		t.Error("registry ON: unregistered 'anything' still advertised")
	}
	for _, sc := range []string{"openid", "profile", "email"} {
		if !on[sc] {
			t.Errorf("registry ON: OIDC scope %q dropped from scopes_supported", sc)
		}
	}
	off := scopes(build(false))
	for _, sc := range []string{"openid", "profile", "email", "anything"} {
		if !off[sc] {
			t.Errorf("registry OFF: %q missing from the full union (regression anchor)", sc)
		}
	}
}

// FM-1/FM-2: mixed-replica divergence pin — the same client+scope request
// answers 400 on the enabled replica and 200 on the disabled one. This is the
// documented pre/post-flip state, never a surprise: enablement is a
// deployment-wide config change, and two replicas from the same snapshot
// answer identically (deterministic build-once registry).
func TestScopeRegistry_MixedReplicaDivergence(t *testing.T) {
	on := newScopeRegistryHarness(t, true)
	off := newScopeRegistryHarness(t, false)
	if st, raw, _ := srCC(t, on, srClientAny, "anything"); st != http.StatusBadRequest {
		t.Fatalf("enabled replica: status=%d body=%s, want 400", st, raw)
	}
	if st, raw, _ := srCC(t, off, srClientAny, "anything"); st != http.StatusOK {
		t.Fatalf("disabled replica: status=%d body=%s, want 200 (byte-compat baseline)", st, raw)
	}
}

// Row 4 anchor: the default-unwired server is byte-identical — the existing
// TestScope_* suites run against it unmodified; this pair pins the same
// client+scope across the registry flag.
func TestScopeRegistry_DefaultPathUnwired_ByteIdentical(t *testing.T) {
	off := newScopeRegistryHarness(t, false)
	st, raw, out := srCC(t, off, srClientAny, "anything")
	if st != http.StatusOK || out["scope"] != "anything" {
		t.Fatalf("unwired: status=%d body=%s, want 200 pass-through", st, raw)
	}
}

// Matrix pin row 6 (composition side): the scopecontract audit relay constant
// equals the billing default. cmd/snaplink-billing owns the literal; this is
// the drift guard between the two.
func TestScopeRegistry_AuditRelayScopeMatchesBillingDefault(t *testing.T) {
	// The billing binary exact-enforces this value at boot
	// (cmd/snaplink-billing/config.go, defaultAuditScope); the constant here
	// is the registry-side copy of the same literal.
	if scopecontract.ScopeAuditEventWrite != "audit:event:write" {
		t.Fatalf("ScopeAuditEventWrite = %q, want the billing default literal", scopecontract.ScopeAuditEventWrite)
	}
}
