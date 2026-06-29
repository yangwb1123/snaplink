package serverwebauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// Per-tenant signing-key isolation for the cmd WebAuthn id_token mint.
//
// /webauthn/login/finish?client_id= mints an id_token; before this change
// it always used the single shared deps.IDTokenIssuer, so a tenant's
// WebAuthn id_token was signed by the shared key — the last surface that
// bypassed WithTenantTokenIssuer. These tests drive issueWebAuthnToken
// directly (the WebAuthn ceremony itself is exercised elsewhere) over a
// real *sso.Server wired through MountWebAuthnRoutes, proving the id_token
// is signed by the TENANT's key and that misconfigured/opaque tenant
// strategies fail closed rather than falling back to the shared key.
//
// Real Ed25519 / session issuers throughout — no mocks (AGENTS.md §8).

// webauthnJOSEKid extracts the JOSE header `kid` of a compact JWS,
// asserting alg=EdDSA along the way.
func webauthnJOSEKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWT: %q", token)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	var h struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("header parse: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Fatalf("unexpected alg %q (want EdDSA)", h.Alg)
	}
	return h.Kid
}

// newWebAuthnTenantDeps builds a *sso.Server with a default issuer, a
// distinct tenant issuer mapped via WithTenantTokenIssuer, and an opaque
// (session) strategy, then returns WebAuthnDeps wired through the real
// MountWebAuthnRoutes path so deps.IDTokenIssuerForClient == the server's
// per-tenant selector. clients are seeded into the shared client store.
func newWebAuthnTenantDeps(t *testing.T, def, tenantA *defaultimpl.Ed25519JWTIssuer, session sso.TokenIssuer, clients ...*sso.Client) *WebAuthnDeps {
	t.Helper()
	clientStore := defaultimpl.NewMemoryClientStore()
	for _, c := range clients {
		if err := clientStore.Add(context.Background(), c); err != nil {
			t.Fatalf("seed client %s: %v", c.ID, err)
		}
	}
	issuers := map[string]sso.TokenIssuer{
		"default":  def,
		"tenant-a": tenantA,
	}
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clientStore),
		sso.WithTokenIssuer("default", def),
		sso.WithTokenIssuer("tenant-a", tenantA),
		sso.WithDefaultTokenStrategy("default"),
		sso.WithIDTokenIssuer(def), // shared id_token issuer == default key
		sso.WithTenantTokenIssuer("ta", "tenant-a"),
	}
	if session != nil {
		issuers["opaque"] = session
		opts = append(opts,
			sso.WithTokenIssuer("opaque", session),
			sso.WithTenantTokenIssuer("topaque", "opaque"),
		)
	}
	// "tmissing" maps to a strategy that is never registered → unregistered
	// tenant issuer (fail-closed path).
	opts = append(opts, sso.WithTenantTokenIssuer("tmissing", "missing"))

	srv := sso.NewServer(opts...)

	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "Example AS",
		RPOrigins:     []string{"https://sso.example.com"},
		SessionTTL:    time.Minute,
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	deps := &WebAuthnDeps{
		Helper:        h,
		ClientStore:   clientStore,
		TokenIssuers:  issuers,
		DefaultStrat:  "default",
		IDTokenIssuer: def,
	}
	// Handler() runs Mount(), which must precede Handle() — the route
	// registration MountWebAuthnRoutes performs.
	_ = srv.Handler()
	// Exercise the production wiring: this is where the per-tenant selector
	// and the encryption hook get attached from *sso.Server.
	if err := MountWebAuthnRoutes(srv, deps); err != nil {
		t.Fatalf("MountWebAuthnRoutes: %v", err)
	}
	if deps.IDTokenIssuerForClient == nil {
		t.Fatal("MountWebAuthnRoutes did not wire IDTokenIssuerForClient")
	}
	return deps
}

func TestWebAuthnIDToken_PerTenantKey(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	tenantA := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	if def.KeyID() == tenantA.KeyID() {
		t.Fatalf("expected distinct kids, got def==tenantA==%s", def.KeyID())
	}

	tenantClient := &sso.Client{
		ID: "ca", TenantID: "ta", Active: true,
		AllowedScopes: []string{sso.ScopeOpenID, "profile"},
	}
	noTenantClient := &sso.Client{
		ID: "cn", Active: true,
		AllowedScopes: []string{sso.ScopeOpenID, "profile"},
	}
	deps := newWebAuthnTenantDeps(t, def, tenantA, nil, tenantClient, noTenantClient)

	req, _ := http.NewRequest(http.MethodPost, "http://x/", nil)

	// Tenant client: the WebAuthn id_token is signed by the TENANT key.
	res, err := issueWebAuthnToken(req, deps, "ca", "alice")
	if err != nil {
		t.Fatalf("issue (tenant): %v", err)
	}
	if res.IDToken == "" {
		t.Fatal("tenant client: id_token empty (openid was in scope)")
	}
	if got := webauthnJOSEKid(t, res.IDToken); got != tenantA.KeyID() {
		t.Fatalf("tenant id_token kid %q, want tenant-a kid %q", got, tenantA.KeyID())
	}
	// The access token comes from client.TokenStrategy (unset → DefaultStrat
	// "default"), so it rides the default key. The id_token now rides the
	// tenant key — the change isolates the id_token surface specifically.

	// Non-tenant client: falls back to the shared id_token issuer (default key).
	resN, err := issueWebAuthnToken(req, deps, "cn", "bob")
	if err != nil {
		t.Fatalf("issue (no tenant): %v", err)
	}
	if resN.IDToken == "" {
		t.Fatal("no-tenant client: id_token empty (openid was in scope)")
	}
	if got := webauthnJOSEKid(t, resN.IDToken); got != def.KeyID() {
		t.Fatalf("no-tenant id_token kid %q, want default kid %q", got, def.KeyID())
	}
}

// A tenant whose strategy is opaque/session (a TokenIssuer that is NOT an
// oidc.IDTokenIssuer) must OMIT the id_token — never sign it with the
// shared key. The access token (also opaque) is still issued; only the
// id_token is withheld, exactly as /auth/login behaves with no issuer.
func TestWebAuthnIDToken_OpaqueTenantOmits(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	tenantA := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	session := defaultimpl.NewSessionTokenIssuer() // TokenIssuer, not IDTokenIssuer

	opaqueClient := &sso.Client{
		ID: "co", TenantID: "topaque", Active: true,
		AllowedScopes: []string{sso.ScopeOpenID},
	}
	deps := newWebAuthnTenantDeps(t, def, tenantA, session, opaqueClient)

	req, _ := http.NewRequest(http.MethodPost, "http://x/", nil)
	res, err := issueWebAuthnToken(req, deps, "co", "carol")
	if err != nil {
		t.Fatalf("issue (opaque tenant): unexpected error %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("opaque tenant: access token should still be issued")
	}
	if res.IDToken != "" {
		t.Fatalf("opaque tenant: id_token must be omitted (fail closed), got %q", res.IDToken)
	}
}

// A tenant mapping that names an unregistered issuer must fail closed. Now
// that the ACCESS token also routes through the per-tenant selector
// (IssuerForClient), the misconfiguration is caught at the access-token mint
// (errWebAuthnNoIssuer → 500) — even earlier than the id_token step — never
// falling back to a shared key for any token type.
func TestWebAuthnIDToken_UnregisteredTenantFailsClosed(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	tenantA := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))

	missingClient := &sso.Client{
		ID: "cx", TenantID: "tmissing", Active: true,
		AllowedScopes: []string{sso.ScopeOpenID},
	}
	deps := newWebAuthnTenantDeps(t, def, tenantA, nil, missingClient)

	req, _ := http.NewRequest(http.MethodPost, "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "cx", "dave")
	if !errors.Is(err, errWebAuthnNoIssuer) {
		t.Fatalf("unregistered tenant issuer: got %v, want errWebAuthnNoIssuer (fail closed at access-token mint)", err)
	}
	status, code := webauthnIssueErrorStatus(err)
	if status != http.StatusInternalServerError || code != "server_error" {
		t.Fatalf("error mapping: got (%d, %q) want (500, server_error)", status, code)
	}
}

// Backward-compat: an embedder that constructs WebAuthnDeps WITHOUT the
// per-tenant selector (IDTokenIssuerForClient nil) gets byte-identical
// legacy behavior — the shared IDTokenIssuer signs every client's
// id_token, tenant or not.
func TestWebAuthnIDToken_LegacyNoSelectorUsesSharedIssuer(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))

	store := defaultimpl.NewMemoryClientStore()
	c := &sso.Client{
		ID: "ca", TenantID: "ta", Active: true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{sso.ScopeOpenID},
	}
	_ = store.Add(context.Background(), c)
	// No MountWebAuthnRoutes → IDTokenIssuerForClient stays nil.
	deps := &WebAuthnDeps{
		ClientStore:   store,
		TokenIssuers:  map[string]sso.TokenIssuer{"jwt": def},
		DefaultStrat:  "jwt",
		IDTokenIssuer: def,
	}
	req, _ := http.NewRequest(http.MethodPost, "http://x/", nil)
	res, err := issueWebAuthnToken(req, deps, "ca", "erin")
	if err != nil {
		t.Fatalf("issue (legacy): %v", err)
	}
	if res.IDToken == "" {
		t.Fatal("legacy: id_token empty (openid was in scope)")
	}
	if got := webauthnJOSEKid(t, res.IDToken); got != def.KeyID() {
		t.Fatalf("legacy id_token kid %q, want shared issuer kid %q", got, def.KeyID())
	}
}
