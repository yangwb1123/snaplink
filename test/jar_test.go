package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// RFC 9101 JAR: request parameter on /auth/login is a signed JWT
// whose claims override the outside parameters. Verifies against
// Client.JWKS; failures map to invalid_request_object.

const (
	jarClient      = "jar-client"
	jarUser        = "u-jar"
	jarPassword    = "pw"
	jarKid         = "jar-kid-1"
	jarASIssuer    = "https://sso.test"
	jarRedirectURI = "https://app.example.com/cb"
	jarRedirectAlt = "https://app.example.com/cb-alt"
	jarStateInJWT  = "state-inside-jwt"
	jarScopeInJWT  = "read write"
	jarNonceInJWT  = "nonce-xyz-42"
	jarPKCEInJWT   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012"
	jarBadRedirect = "https://attacker.example/steal"
)

type jarHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

func newJARHarness(t *testing.T) *jarHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jarUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    jarClient,
		Secret:                "jar-secret",
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jarRedirectURI, jarRedirectAlt},
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jarKid,
			Alg: "EdDSA",
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == jarUser && p == jarPassword {
				return &sso.AuthResult{UserID: jarUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	server := sso.NewServer(
		sso.WithIssuer(jarASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(server.Handler())
	t.Cleanup(httpSrv.Close)
	return &jarHarness{srv: httpSrv, signKey: priv, pubKey: pub}
}

// signJAR builds + signs a JAR JWT from the supplied claim map.
// Uses the harness's Ed25519 key + the jarKid in the header.
func (h *jarHarness) signJAR(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "oauth-authz-req+jwt",
		"kid": kid,
	}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (h *jarHarness) loginJAR(t *testing.T, jwt string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jarClient,
		"credential": map[string]string{"username": jarUser, "password": jarPassword},
		"request":    jwt,
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestJAR_VerifySignatureAndMerge(t *testing.T) {
	h := newJARHarness(t)
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss":                   jarClient,
		"aud":                   jarASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"client_id":             jarClient,
		"response_type":         "code",
		"redirect_uri":          jarRedirectURI,
		"scope":                 jarScopeInJWT,
		"state":                 jarStateInJWT,
		"nonce":                 jarNonceInJWT,
		"code_challenge":        jarPKCEInJWT,
		"code_challenge_method": "plain",
	}, jarKid)
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["code"] == "" || body["code"] == nil {
		t.Fatalf("no code in JAR-driven code-flow response: %v", body)
	}
	if body["state"] != jarStateInJWT {
		t.Errorf("state = %v want %q (echoed from JWT)", body["state"], jarStateInJWT)
	}
}

func TestJAR_JWTRedirectURIOverridesOutside(t *testing.T) {
	// The whole point of JAR: an attacker can flip the URL
	// parameter to a phishing redirect_uri, but the JWT-bound
	// redirect_uri MUST win.
	h := newJARHarness(t)
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss":                   jarClient,
		"aud":                   jarASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"client_id":             jarClient,
		"response_type":         "code",
		"redirect_uri":          jarRedirectURI, // legitimate
		"code_challenge":        jarPKCEInJWT,
		"code_challenge_method": "plain",
	}, jarKid)

	// Caller sends a tampered redirect_uri OUTSIDE the JWT.
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     jarClient,
		"credential":    map[string]string{"username": jarUser, "password": jarPassword},
		"request":       jwt,
		"redirect_uri":  jarBadRedirect,
		"response_type": "code",
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (JWT redirect_uri legitimate); got %d: %s", resp.StatusCode, raw)
	}
	// If the outside parameter had won, jarBadRedirect would have
	// failed the IsRedirectURIValid check and returned 400.
}

func TestJAR_RejectsBadSignature(t *testing.T) {
	h := newJARHarness(t)
	jwt := h.signJAR(t, map[string]any{
		"iss":           jarClient,
		"aud":           jarASIssuer,
		"client_id":     jarClient,
		"response_type": "code",
		"redirect_uri":  jarRedirectURI,
	}, jarKid)
	// Tamper with the signature segment.
	parts := []byte(jwt)
	last := bytes.LastIndexByte(parts, '.')
	parts[last+1] = 'A'
	parts[last+2] = 'A'
	status, body := h.loginJAR(t, string(parts))
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

func TestJAR_RejectsUnknownKid(t *testing.T) {
	h := newJARHarness(t)
	jwt := h.signJAR(t, map[string]any{
		"iss":           jarClient,
		"aud":           jarASIssuer,
		"client_id":     jarClient,
		"response_type": "code",
		"redirect_uri":  jarRedirectURI,
	}, "unknown-kid")
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

func TestJAR_RejectsAudMismatch(t *testing.T) {
	// Mix-up defense: a JAR JWT crafted for a different AS must
	// not be accepted here. RFC 9101 §6.3 mandates the audience
	// check.
	h := newJARHarness(t)
	jwt := h.signJAR(t, map[string]any{
		"iss":           jarClient,
		"aud":           "https://other-as.example",
		"client_id":     jarClient,
		"response_type": "code",
		"redirect_uri":  jarRedirectURI,
	}, jarKid)
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

func TestJAR_RejectsExpired(t *testing.T) {
	h := newJARHarness(t)
	old := time.Now().Unix() - 3600
	jwt := h.signJAR(t, map[string]any{
		"iss":           jarClient,
		"aud":           jarASIssuer,
		"iat":           old - 60,
		"exp":           old, // expired one hour ago
		"client_id":     jarClient,
		"response_type": "code",
		"redirect_uri":  jarRedirectURI,
	}, jarKid)
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

func TestJAR_RejectsClientIDMismatch(t *testing.T) {
	// JWT iss = client_id is recommended; client_id in JWT MUST
	// match the outside client_id. Detects an attacker who
	// captured a JAR JWT for one client and replays it under
	// another client_id.
	h := newJARHarness(t)
	jwt := h.signJAR(t, map[string]any{
		"iss":           "different-client",
		"aud":           jarASIssuer,
		"client_id":     "different-client",
		"response_type": "code",
		"redirect_uri":  jarRedirectURI,
	}, jarKid)
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

func TestJAR_ClientWithoutJWKSRejects(t *testing.T) {
	// A JAR-signed request against a client that has no
	// registered JWKS MUST fail invalid_request_object — there's
	// no key to verify against.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jarUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jarClient, Secret: "s", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jarRedirectURI},
		// no JWKS
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == jarUser && p == jarPassword {
				return &sso.AuthResult{UserID: jarUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	srv := sso.NewServer(
		sso.WithIssuer(jarASIssuer),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Build a JWT signed with some throwaway key. The server has
	// no JWKS for this client → invalid_request_object.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hdr, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "oauth-authz-req+jwt"})
	pld, _ := json.Marshal(map[string]any{
		"iss": jarClient, "aud": jarASIssuer, "client_id": jarClient,
		"response_type": "code", "redirect_uri": jarRedirectURI,
	})
	si := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld)
	sig := ed25519.Sign(priv, []byte(si))
	jwt := si + "." + base64.RawURLEncoding.EncodeToString(sig)

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jarClient,
		"credential": map[string]string{"username": jarUser, "password": jarPassword},
		"request":    jwt,
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s want 400", resp.StatusCode, raw)
	}
}

func TestJAR_DiscoveryAdvertisesSupport(t *testing.T) {
	h := newJARHarness(t)
	resp, err := http.Get(h.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["request_parameter_supported"] != true {
		t.Errorf("request_parameter_supported = %v want true", doc["request_parameter_supported"])
	}
	// JAR request_uri NOT supported here; PAR's request_uri is a
	// different mechanism even though it shares the parameter
	// name on the wire.
	if doc["request_uri_parameter_supported"] != false {
		t.Errorf("request_uri_parameter_supported = %v want false", doc["request_uri_parameter_supported"])
	}
	// JAR request objects now verify through the shared asymmetric
	// verifier, so discovery advertises the full asymmetric allowlist
	// (EdDSA + ES256/384/512 + RS256 + PS256), not EdDSA-only.
	algs, ok := doc["request_object_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("request_object_signing_alg_values_supported missing/wrong type: %v", doc["request_object_signing_alg_values_supported"])
	}
	got := map[string]bool{}
	for _, a := range algs {
		got[a.(string)] = true
	}
	for _, want := range []string{"EdDSA", "ES256", "ES384", "ES512", "RS256", "PS256"} {
		if !got[want] {
			t.Errorf("request_object_signing_alg_values_supported = %v, want to contain %q", algs, want)
		}
	}
}

func TestJAR_NoRequestParam_LegacyBehavior(t *testing.T) {
	// Login WITHOUT a `request` parameter must continue to work
	// — JAR is opt-in.
	h := newJARHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jarClient,
		"credential": map[string]string{"username": jarUser, "password": jarPassword},
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s want 200 (legacy direct mint)", resp.StatusCode, raw)
	}
}
