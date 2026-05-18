package sso_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// TestOIDC_DiscoveryJWKSAndIDTokenAreConsistent drives the FULL OIDC
// bootstrap dance against a real httptest server. Proves the three
// pieces are wired correctly to each other:
//
//   discovery → publishes jwks_uri + id_token_signing_alg_values_supported
//        ↓
//   JWKS endpoint → publishes the EdDSA public key under its kid
//        ↓
//   ID Token from /auth/login → signed by EdDSA, kid matches, signature
//        verifies under the JWKS public key
//
// A failure at any link breaks the test, which is the point — this is
// the canonical "did I wire OIDC correctly" smoke test for downstream
// SDK users. Anything that drifts (kid format, alg name, JWKS shape,
// ID token claim names) will fail here long before an RP integration.
func TestOIDC_DiscoveryJWKSAndIDTokenAreConsistent(t *testing.T) {
	const (
		issuerName = "https://sso.example.test"
		user       = "u-end2end"
		clientID   = "rp"
		clientSec  = "secret"
	)

	// ----- server setup -----
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: user})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: clientID, Secret: clientSec,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: user, Provider: "password"}, nil
		},
	))
	// One issuer for everything — the canonical wiring.
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(issuerName),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer(issuerName),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// ----- step 1: discovery -----
	discoResp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer discoResp.Body.Close()
	disco := map[string]any{}
	_ = json.NewDecoder(discoResp.Body).Decode(&disco)

	jwksURI, _ := disco["jwks_uri"].(string)
	if jwksURI == "" {
		t.Fatalf("discovery missing jwks_uri: %v", disco)
	}
	algs, _ := disco["id_token_signing_alg_values_supported"].([]any)
	if len(algs) == 0 || algs[0] != "EdDSA" {
		t.Fatalf("expected EdDSA in id_token_signing_alg_values_supported, got %v", algs)
	}
	if disco["issuer"] != issuerName {
		t.Fatalf("issuer mismatch in discovery: got %v want %q", disco["issuer"], issuerName)
	}

	// ----- step 2: JWKS -----
	jwksResp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("JWKS fetch: %v", err)
	}
	defer jwksResp.Body.Close()
	jwksRaw, _ := io.ReadAll(jwksResp.Body)
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksRaw, &jwks); err != nil {
		t.Fatalf("JWKS decode: %v raw=%s", err, jwksRaw)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS empty")
	}
	jwk := jwks.Keys[0]
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" {
		t.Errorf("JWK shape wrong: %+v", jwk)
	}
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		t.Fatalf("JWK x decode: %v len=%d", err, len(pubKeyBytes))
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// ----- step 3: login with openid scope -----
	loginBody, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid"},
		"nonce":      "deadbeef",
	})
	loginResp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()
	var loginOut map[string]any
	_ = json.NewDecoder(loginResp.Body).Decode(&loginOut)
	idToken, _ := loginOut["id_token"].(string)
	if idToken == "" {
		t.Fatalf("login missing id_token: %v", loginOut)
	}

	// ----- step 4: verify ID Token signature against JWKS pubkey -----
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("ID token not 3-segment JWT: %d parts", len(parts))
	}
	// Header sanity: kid must match the JWK's kid, alg must be EdDSA.
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatalf("header decode: %v", err)
	}
	if header.Alg != "EdDSA" {
		t.Errorf("header.alg = %q want EdDSA", header.Alg)
	}
	if header.Kid != jwk.Kid {
		t.Errorf("kid drift: token kid=%q vs JWK kid=%q — issuer + JWKS not sharing the same key", header.Kid, jwk.Kid)
	}

	// Verify the signature using the JWKS-published public key.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("sig decode: %v", err)
	}
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		t.Fatal("ID Token signature does NOT verify under the public key fetched from JWKS — the OIDC pipeline is broken")
	}

	// Payload sanity: nonce echoed, sub correct, iss matches discovery.
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload["nonce"] != "deadbeef" {
		t.Errorf("nonce echo failed: %v", payload["nonce"])
	}
	if payload["sub"] != user {
		t.Errorf("sub = %v want %q", payload["sub"], user)
	}
	if payload["iss"] != issuerName {
		t.Errorf("iss = %v want %q (must match discovery)", payload["iss"], issuerName)
	}
	if payload["aud"] != clientID {
		t.Errorf("aud = %v want %q (single-string audience for OIDC)", payload["aud"], clientID)
	}
}
