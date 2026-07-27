package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// Per-tenant signing-key isolation extended to the signed /userinfo
// surface (OIDC Core §5.3.2). UserinfoSigner is an optional extension of
// IDTokenIssuer signing on the same key, so a client bound to a tenant
// with a registered tenant issuer (WithTenantTokenIssuer) must have its
// signed userinfo JWT signed by THAT tenant's key — not the shared one.
// A tenant whose strategy can't sign userinfo (opaque/session, or an
// unregistered tenant issuer) must fall through to plain JSON rather than
// sign with the shared key (fail-closed by omission). Non-tenant clients
// keep using the shared signer.
//
// Real Ed25519 / session issuers throughout — no mocks (AGENTS.md §8).

const (
	utUserID   = "u-tenant"
	utPassword = "pw"
	utSecret   = "sec"

	// Distinct token strategies feed three different signing keys.
	utStratDefault = "default"
	utStratTenantA = "tenant-a"
	utStratOpaque  = "opaque"

	// Clients: a non-tenant client (shared key), a tenant client whose
	// tenant maps to tenant-a's key, and a tenant whose strategy is
	// opaque (a TokenIssuer that can't sign userinfo).
	//
	// There is deliberately NO "unregistered tenant issuer" client here:
	// the access-token selector (issuerForClient) consults the SAME
	// tenant mapping, so a tenant pointing at an unregistered issuer
	// fails closed at /auth/login (no_token_strategy) before /userinfo is
	// ever reached. That selector's err-path is exercised where it is
	// reachable — the cmd WebAuthn id_token mint, whose access token uses
	// client.TokenStrategy directly (see
	// TestWebAuthnIDToken_UnregisteredTenantFailsClosed) — and the
	// selector itself is unit-tested in tenant_signing_isolation_test.go.
	utClientShared = "ut-shared"
	utClientTenant = "ut-tenant"
	utClientOpaque = "ut-opaque"
)

// utJOSEKid extracts the JOSE `kid` of a compact JWS, asserting alg=EdDSA.
func utJOSEKid(t *testing.T, token string) string {
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

type utHarness struct {
	srv     *httptest.Server
	def     *defaultimpl.Ed25519JWTIssuer
	tenantA *defaultimpl.Ed25519JWTIssuer
}

func newUserinfoTenantHarness(t *testing.T) *utHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: utUserID, Email: "tenant@example.com", Name: "Tina",
	})

	def := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	tenantA := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	session := defaultimpl.NewSessionTokenIssuer() // TokenIssuer, NOT UserinfoSigner
	if def.KeyID() == tenantA.KeyID() {
		t.Fatalf("expected distinct kids, got def==tenantA==%s", def.KeyID())
	}

	clients := defaultimpl.NewMemoryClientStore()
	// Non-tenant client → shared signer.
	clients.AddSeed(&sso.Client{
		ID: utClientShared, Secret: utSecret, Active: true,
		AllowedAuthenticators:     []string{"password"},
		AllowedScopes:             []string{sso.ScopeOpenID, "email", "profile"},
		TokenStrategy:             utStratDefault,
		UserinfoSignedResponseAlg: "EdDSA",
	})
	// Tenant client whose tenant maps to tenant-a's key.
	clients.AddSeed(&sso.Client{
		ID: utClientTenant, Secret: utSecret, Active: true, TenantID: "ta",
		AllowedAuthenticators:     []string{"password"},
		AllowedScopes:             []string{sso.ScopeOpenID, "email", "profile"},
		TokenStrategy:             utStratTenantA,
		UserinfoSignedResponseAlg: "EdDSA",
	})
	// Tenant whose strategy is opaque (can't sign userinfo) → fail closed.
	clients.AddSeed(&sso.Client{
		ID: utClientOpaque, Secret: utSecret, Active: true, TenantID: "topaque",
		AllowedAuthenticators:     []string{"password"},
		AllowedScopes:             []string{sso.ScopeOpenID, "email", "profile"},
		TokenStrategy:             utStratOpaque,
		UserinfoSignedResponseAlg: "EdDSA",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != utPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: utUserID, Provider: "password"}, nil
		},
	))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer(utStratDefault, def),
		sso.WithTokenIssuer(utStratTenantA, tenantA),
		sso.WithTokenIssuer(utStratOpaque, session),
		sso.WithDefaultTokenStrategy(utStratDefault),
		// Shared id_token/userinfo issuer == default key.
		sso.WithIDTokenIssuer(def),
		sso.WithTenantTokenIssuer("ta", utStratTenantA),
		sso.WithTenantTokenIssuer("topaque", utStratOpaque),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &utHarness{srv: httpSrv, def: def, tenantA: tenantA}
}

func utLogin(t *testing.T, h *utHarness, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": utUserID, "password": utPassword},
		"scope":      []string{sso.ScopeOpenID, "email", "profile"},
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token for %s: %s", clientID, rb)
	}
	return access
}

// utUserinfo GETs /userinfo with the bearer and returns (contentType, body).
func utUserinfo(t *testing.T, h *utHarness, accessToken string) (string, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.Header.Get("Content-Type"), string(body)
}

func TestUserinfoTenant_SignedByTenantKey(t *testing.T) {
	h := newUserinfoTenantHarness(t)

	// Tenant client: signed userinfo carries the TENANT key's kid.
	tok := utLogin(t, h, utClientTenant)
	ct, body := utUserinfo(t, h, tok)
	if ct != "application/jwt" {
		t.Fatalf("tenant client Content-Type = %q want application/jwt", ct)
	}
	if got := utJOSEKid(t, body); got != h.tenantA.KeyID() {
		t.Fatalf("tenant userinfo signed by kid %q, want tenant-a kid %q", got, h.tenantA.KeyID())
	}
}

func TestUserinfoTenant_NonTenantUsesSharedKey(t *testing.T) {
	h := newUserinfoTenantHarness(t)

	// Non-tenant client: signed userinfo falls back to the shared (default) key.
	tok := utLogin(t, h, utClientShared)
	ct, body := utUserinfo(t, h, tok)
	if ct != "application/jwt" {
		t.Fatalf("shared client Content-Type = %q want application/jwt", ct)
	}
	if got := utJOSEKid(t, body); got != h.def.KeyID() {
		t.Fatalf("non-tenant userinfo signed by kid %q, want default kid %q", got, h.def.KeyID())
	}
}

// A tenant whose registered strategy can't sign userinfo (opaque/session,
// not a UserinfoSigner) must fall through to plain JSON — NOT sign with
// the shared key.
func TestUserinfoTenant_OpaqueTenantFallsToJSON(t *testing.T) {
	h := newUserinfoTenantHarness(t)

	tok := utLogin(t, h, utClientOpaque)
	ct, body := utUserinfo(t, h, tok)
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("opaque tenant Content-Type = %q want application/json (fail closed, not signed)", ct)
	}
	// Sanity: it really is the JSON claim set, not a JWS.
	var claims map[string]any
	if err := json.Unmarshal([]byte(body), &claims); err != nil {
		t.Fatalf("opaque tenant body is not JSON: %v (%s)", err, body)
	}
	if claims["sub"] != utUserID {
		t.Fatalf("opaque tenant userinfo sub = %v want %s", claims["sub"], utUserID)
	}
}
