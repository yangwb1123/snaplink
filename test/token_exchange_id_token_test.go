package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

// idTokenExchangeAlgs is the alg allowlist for verifying the exchanged
// id_token's signature against the published JWKS (the default issuer
// signs with EdDSA).
var idTokenExchangeAlgs = map[string]struct{}{"EdDSA": {}}

// newIDTokenExchangeHarness wires an IDTokenIssuer (the same Ed25519
// instance backs both the access-token strategy and id_token issuance, the
// canonical "one signing key, one JWKS entry" deployment). Returns the
// HTTP server and the issuer so tests can fetch the JWKS for verification.
func newIDTokenExchangeHarness(t *testing.T) (*httptest.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: txUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: txClientID, Secret: txSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			// AMR + ACR so the exchange has real factor strength to propagate
			// into the id_token (the load-bearing claim-propagation check).
			return &sso.AuthResult{
				UserID:      txUserID,
				Provider:    "password",
				AuthMethods: []string{"pwd"},
				AchievedACR: "urn:test:acr:1",
			}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, issuer
}

func TestTokenExchange_IDTokenOutput(t *testing.T) {
	srv, issuer := newIDTokenExchangeHarness(t)
	// openid scope at /auth/login marks this as an OIDC session — the
	// precondition for an exchanged id_token.
	subject := txLogin(t, srv, []string{"openid", "read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {txClientID},
		"client_secret":        {txSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["issued_token_type"] != "urn:ietf:params:oauth:token-type:id_token" {
		t.Errorf("issued_token_type = %v want id_token URN", body["issued_token_type"])
	}
	// The access token is still returned alongside (RFC 8693 §2.2.1 —
	// requested_token_type names what issued_token_type reports, not the
	// exclusive output).
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Errorf("access_token must still be present: %v", body)
	}
	idTok, _ := body["id_token"].(string)
	if idTok == "" {
		t.Fatalf("missing id_token in response: %v", body)
	}

	// The id_token must verify against the published JWKS — a real,
	// independent signature check (not a trust-the-issuer round trip).
	jwks, err := issuer.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	payload, err := security.VerifyCompactJWS(idTok, jwks, idTokenExchangeAlgs)
	if err != nil {
		t.Fatalf("id_token signature does not verify against JWKS: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("id_token payload: %v", err)
	}

	// Required OIDC Core claims.
	if claims["sub"] != txUserID {
		t.Errorf("sub = %v want %q", claims["sub"], txUserID)
	}
	if claims["aud"] != txClientID {
		t.Errorf("aud = %v want %q (the exchanging client)", claims["aud"], txClientID)
	}
	if claims["iss"] == nil || claims["iss"] == "" {
		t.Errorf("iss claim missing")
	}
	if claims["exp"] == nil {
		t.Errorf("exp claim missing")
	}
	// at_hash binds the access token returned in the same response
	// (OIDC Core §3.1.3.6).
	if claims["at_hash"] == nil || claims["at_hash"] == "" {
		t.Errorf("at_hash missing — must bind the accompanying access_token: %v", claims)
	}

	// Propagated auth context from the inbound subject_token.
	if claims["acr"] != "urn:test:acr:1" {
		t.Errorf("acr = %v want propagated urn:test:acr:1", claims["acr"])
	}
	amr, ok := claims["amr"].([]any)
	if !ok || len(amr) == 0 || amr[0] != "pwd" {
		t.Errorf("amr = %v want propagated [pwd]", claims["amr"])
	}
	if claims["auth_time"] == nil {
		t.Errorf("auth_time missing — must propagate the original login moment")
	}
}

func TestTokenExchange_IDTokenWithoutIssuerRejected(t *testing.T) {
	// The default harness wires no IDTokenIssuer. Requesting an id_token
	// must collapse to invalid_request (oracle-safe: identical to an
	// unsupported requested_token_type, so it never reveals whether OIDC
	// is configured).
	srv := newTokenExchangeHarness(t, nil)
	subject := txLogin(t, srv, []string{"openid"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {txClientID},
		"client_secret":        {txSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (no IDTokenIssuer wired) body=%v", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
	if body["id_token"] != nil {
		t.Errorf("id_token must not be present on rejection: %v", body["id_token"])
	}
}

func TestTokenExchange_IDTokenRequiresOpenIDScope(t *testing.T) {
	// An id_token is only meaningful for an OIDC exchange. With an issuer
	// wired but no openid scope on the subject token, requesting id_token
	// is malformed → invalid_request (oracle-safe).
	srv, _ := newIDTokenExchangeHarness(t)
	subject := txLogin(t, srv, []string{"read"}) // no openid

	status, body := postExchange(t, srv, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {txClientID},
		"client_secret":        {txSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (no openid scope) body=%v", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
}

func TestTokenExchange_AccessTokenOutputUnchangedWithIssuer(t *testing.T) {
	// Wiring an IDTokenIssuer must NOT change the default (access_token)
	// exchange behavior — no id_token leaks in, issued_token_type stays
	// access_token.
	srv, _ := newIDTokenExchangeHarness(t)
	subject := txLogin(t, srv, []string{"openid", "read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		// no requested_token_type → defaults to access_token
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %v want access_token", body["issued_token_type"])
	}
	if body["id_token"] != nil {
		t.Errorf("id_token must NOT be present on an access-token exchange: %v", body["id_token"])
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Errorf("access_token missing: %v", body)
	}
	// Sanity: keep core in the import graph and assert the wire URN const.
	if core.TokenTypeIDToken != "urn:ietf:params:oauth:token-type:id_token" {
		t.Errorf("unexpected id_token URN const: %q", core.TokenTypeIDToken)
	}
}
