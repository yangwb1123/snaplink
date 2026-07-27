package sso_test

// workload_identity_clientauth_test.go drives the cloud workload-identity
// /token client-authentication path end to end: a Client is registered with
// TokenEndpointAuthMethod=ClientAuthWorkloadIdentity (no client_secret) and
// authenticates a client_credentials grant by presenting a fake-cloud-issued
// RS256 token as client_assertion, verified against a fake JWKS endpoint
// (httptest — not a mock of our own code) standing in for the real cloud
// provider. Mirrors rootcov2_assertion_test.go's private_key_jwt coverage,
// but for WithWorkloadIdentityProviders / security.NewGCPWorkloadIdentityValidator.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

const (
	wiClientID = "wi-client"
	wiIssuer   = "https://wi.example.com"
	wiSubject  = "workload-sa@my-project.iam.gserviceaccount.com"
)

// wiRSAKey is a throwaway RSA keypair for signing fake-cloud tokens in tests.
type wiRSAKey struct {
	priv *rsa.PrivateKey
	jwk  core.JWK
}

func newWIRSAKey(t *testing.T, kid string) wiRSAKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	return wiRSAKey{
		priv: priv,
		jwk: core.JWK{
			Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(eb),
		},
	}
}

// signWIToken signs an RS256 compact JWS (a fake GCP-shaped ID token) for claims.
func signWIToken(t *testing.T, k wiRSAKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// wiClaims builds a GCP-shaped ID token claim set: iss is ALWAYS
// security.GCPIssuer (the preset's fixed, non-configurable issuer) since
// that's what NewGCPWorkloadIdentityValidator checks; only the JWKS URL is
// swapped out for the fake test server.
func wiClaims(sub, email, aud string, exp time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   security.GCPIssuer,
		"sub":   sub,
		"email": email,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(exp).Unix(),
	}
}

// wiJWKSServer serves {"keys":[...]} at its root — a fake cloud JWKS endpoint.
func wiJWKSServer(t *testing.T, keys ...core.JWK) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wiTestServer wires an *sso.Server with one client configured for workload-
// identity auth (no client_secret at all) and a GCP provider pointed at the
// fake JWKS server. wired controls whether WithWorkloadIdentityProviders is
// even called, so a test can prove "unconfigured = zero behavior change".
func wiTestServer(t *testing.T, jwksURL string, wired bool) *rcovServer {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                      wiClientID,
		Name:                    "Workload Identity Client",
		TokenStrategy:           "jwt",
		Active:                  true,
		SkipConsent:             true,
		TokenEndpointAuthMethod: sso.ClientAuthWorkloadIdentity,
		Attributes: map[string]string{
			security.AttrWorkloadIdentityProvider: "gcp",
			security.AttrWorkloadIdentitySubject:  wiSubject,
		},
	})

	opts := []sso.Option{
		sso.WithIssuer(wiIssuer),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if wired {
		gcpValidator, err := security.NewGCPWorkloadIdentityValidator(security.NewHTTPJWKSSource(jwksURL))
		if err != nil {
			t.Fatalf("new gcp validator: %v", err)
		}
		opts = append(opts, sso.WithWorkloadIdentityProviders(gcpValidator))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &rcovServer{http: httpSrv, clients: clients}
}

func wiTokenRequest(assertion string) map[string]any {
	return map[string]any{
		"grant_type":            "client_credentials",
		"client_id":             wiClientID,
		"client_assertion_type": sso.ClientAssertionTypeWorkloadIdentity,
		"client_assertion":      assertion,
		"scope":                 "read",
	}
}

func TestWorkloadIdentityClientAuth_HappyPath(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	s := wiTestServer(t, jwks.URL, true)

	token := signWIToken(t, key, "gcp-key-1", wiClaims("1234567890", wiSubject, wiIssuer, time.Hour))
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", wiTokenRequest(token))
	if status != http.StatusOK {
		t.Fatalf("workload identity auth = %d body=%v, want 200", status, out)
	}
	if out["access_token"] == "" || out["access_token"] == nil {
		t.Errorf("no access_token minted: %v", out)
	}
}

func TestWorkloadIdentityClientAuth_WrongSubjectRejected(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	s := wiTestServer(t, jwks.URL, true)

	// A DIFFERENT service account than the one registered on the client —
	// the cloud will happily vouch for this identity; the client-attribute
	// binding is what must still refuse it.
	token := signWIToken(t, key, "gcp-key-1", wiClaims("999", "someone-else@my-project.iam.gserviceaccount.com", wiIssuer, time.Hour))
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", wiTokenRequest(token))
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("wrong subject = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("wrong subject error = %v, want invalid_client (oracle-safe)", out["error"])
	}
}

func TestWorkloadIdentityClientAuth_WrongAudienceRejected(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	s := wiTestServer(t, jwks.URL, true)

	token := signWIToken(t, key, "gcp-key-1", wiClaims("1234567890", wiSubject, "https://a-different-relying-party.example", time.Hour))
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", wiTokenRequest(token))
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("wrong aud = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("wrong aud error = %v, want invalid_client", out["error"])
	}
}

func TestWorkloadIdentityClientAuth_ForgedSignatureRejected(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk) // JWKS only knows key's PUBLIC key.
	s := wiTestServer(t, jwks.URL, true)

	forgedKey := newWIRSAKey(t, "gcp-key-1") // same kid, different private key.
	token := signWIToken(t, forgedKey, "gcp-key-1", wiClaims("1234567890", wiSubject, wiIssuer, time.Hour))
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", wiTokenRequest(token))
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("forged signature = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("forged signature error = %v, want invalid_client", out["error"])
	}
}

func TestWorkloadIdentityClientAuth_UnwiredServerRejectsByteIdentically(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	// wired=false: WithWorkloadIdentityProviders is NEVER called — proves
	// "unconfigured = zero behavior change" (a client configured for
	// workload identity still can't authenticate; no panic, no special path).
	s := wiTestServer(t, jwks.URL, false)

	token := signWIToken(t, key, "gcp-key-1", wiClaims("1234567890", wiSubject, wiIssuer, time.Hour))
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", wiTokenRequest(token))
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("unwired server = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("unwired server error = %v, want invalid_client", out["error"])
	}
}

func TestWorkloadIdentityClientAuth_ClientNotConfiguredRejected(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	s := wiTestServer(t, jwks.URL, true)

	// A DIFFERENT, unregistered client_id — never opted into workload
	// identity at all.
	token := signWIToken(t, key, "gcp-key-1", wiClaims("1234567890", wiSubject, wiIssuer, time.Hour))
	req := wiTokenRequest(token)
	req["client_id"] = "some-other-client-never-registered"
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", req)
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("unknown client = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("unknown client error = %v, want invalid_client", out["error"])
	}
}

func TestWorkloadIdentityClientAuth_MissingClientIDRejected(t *testing.T) {
	t.Parallel()
	key := newWIRSAKey(t, "gcp-key-1")
	jwks := wiJWKSServer(t, key.jwk)
	s := wiTestServer(t, jwks.URL, true)

	token := signWIToken(t, key, "gcp-key-1", wiClaims("1234567890", wiSubject, wiIssuer, time.Hour))
	req := wiTokenRequest(token)
	delete(req, "client_id")
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", req)
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("missing client_id = %d, want 401/400", status)
	}
	if out["error"] != "invalid_client" {
		t.Errorf("missing client_id error = %v, want invalid_client", out["error"])
	}
}
