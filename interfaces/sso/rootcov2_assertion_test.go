package sso_test

// rootcov2_assertion_test.go drives the RFC 7521/7523 private_key_jwt client
// authentication path (pairwise_client_assertion.go verifyJWTClientAssertion) —
// a large uncovered function. It registers a client with an Ed25519 JWKS and
// authenticates a client_credentials grant by signing a real client_assertion
// JWT with the matching private key. Oracle-safety: a bad assertion collapses
// to invalid_client.
//
// REUSES rcov2NewDPoPKey (Ed25519 keypair) from rootcov2_dpop_test.go and the
// rcov* HTTP helpers.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const rcov2AssertIssuer = "https://rcov2-assert.example.com"

// rcov2SignAssertion builds an RFC 7523 client assertion JWT signed by key for
// (clientID, audience), with the given kid and exp offset.
func rcov2SignAssertion(t *testing.T, key rcov2DPoPKey, kid, clientID, audience string, exp time.Duration) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	payload := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(exp).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(key.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// rcov2AssertionServer registers a client whose JWKS holds key's public OKP key
// under kid, with private_key_jwt as its token-endpoint auth method.
func rcov2AssertionServer(t *testing.T, key rcov2DPoPKey, kid string) *rcovServer {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:            rcovClient,
		Name:          "Assertion Client",
		TokenStrategy: "jwt",
		Active:        true,
		SkipConsent:   true,
		JWKS: []sso.JWK{{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(key.pub),
		}},
	})
	srv := sso.NewServer(
		sso.WithIssuer(rcov2AssertIssuer),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &rcovServer{http: httpSrv, clients: clients}
}

// TestRcov2A_PrivateKeyJWT authenticates a client_credentials grant via a valid
// private_key_jwt client assertion, then proves the oracle-safe rejections.
func TestRcov2A_PrivateKeyJWT(t *testing.T) {
	t.Parallel()
	key := rcov2NewDPoPKey(t)
	const kid = "assert-key-1"
	s := rcov2AssertionServer(t, key, kid)

	// Valid assertion (aud = the configured issuer) => mints.
	assertion := rcov2SignAssertion(t, key, kid, rcovClient, rcov2AssertIssuer, time.Minute)
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      assertion,
		"scope":                 "read",
	})
	if status != http.StatusOK {
		t.Fatalf("private_key_jwt = %d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("private_key_jwt minted no token: %v", tok)
	}

	// Wrong audience => invalid_client (oracle-safe).
	bad := rcov2SignAssertion(t, key, kid, rcovClient, "https://wrong-aud.example.com", time.Minute)
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      bad,
		"scope":                 "read",
	})
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("wrong-aud assertion = %d, want 401/400 invalid_client (body=%v)", status, out)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("wrong-aud error = %v, want invalid_client", out["error"])
	}

	// Assertion signed by a DIFFERENT key (signature mismatch) => invalid_client.
	other := rcov2NewDPoPKey(t)
	forged := rcov2SignAssertion(t, other, kid, rcovClient, rcov2AssertIssuer, time.Minute)
	status, out = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      forged,
		"scope":                 "read",
	})
	if out["error"] != "invalid_client" {
		t.Errorf("forged-signature error = %v, want invalid_client (status=%d)", out["error"], status)
	}

	// Replaying the SAME valid assertion (jti seen) => invalid_client.
	status, out = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      assertion,
		"scope":                 "read",
	})
	if out["error"] != "invalid_client" {
		t.Errorf("replayed assertion error = %v, want invalid_client (status=%d)", out["error"], status)
	}
}

// rcov2KeepContext keeps the context import referenced for future helpers.
var _ = context.Background
