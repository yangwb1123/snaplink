package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newIntrospectionJWTServer builds a server exactly like
// newIntrospectionServer, plus (when wireSigner) a SEPARATE, independently
// keyed Ed25519JWTIssuer wired ONLY via WithIntrospectionSigning — never
// registered as a token issuer — so these tests prove the RFC 9701
// response is signed by a genuinely DEDICATED key, not the access-token
// signer.
func newIntrospectionJWTServer(t *testing.T, wireSigner bool) (*httptest.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: introUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: introClient, Secret: introSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: introUser}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	introspectionSigner := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://issuer.test"))
	if wireSigner {
		opts = append(opts, sso.WithIntrospectionSigning(introspectionSigner))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, introspectionSigner
}

// postIntrospectAccept posts /token/introspect with an explicit Accept
// header (http.Post offers no header hook, unlike postIntrospect's plain
// JSON helper).
func postIntrospectAccept(t *testing.T, srv *httptest.Server, token, accept string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"token": token, "client_id": introClient, "client_secret": introSecret,
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token/introspect", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// jwtIntrospectAccept is the RFC 9701 §5 Accept header value requesting
// the JWT-formatted introspection response.
const jwtIntrospectAccept = "application/token-introspection+jwt"

func TestIntrospectionJWT_SignedResponseWhenRequested(t *testing.T) {
	srv, signer := newIntrospectionJWTServer(t, true)
	access, _ := loginForTokens(t, srv)

	resp := postIntrospectAccept(t, srv, access, jwtIntrospectAccept)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != jwtIntrospectAccept {
		t.Fatalf("Content-Type = %q, want %q", ct, jwtIntrospectAccept)
	}

	jws := string(raw)
	parts := splitJWS(t, jws)

	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	decodeJWSSegment(t, parts[0], &hdr)
	if hdr.Typ != "token-introspection+jwt" {
		t.Errorf("typ = %q, want token-introspection+jwt", hdr.Typ)
	}
	if hdr.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", hdr.Alg)
	}

	// Verify against the DEDICATED introspection signer's key — proves the
	// response was NOT signed by the access-token issuer.
	sigInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(signer.PublicKey(), []byte(sigInput), sig) {
		t.Fatal("signature does not verify against the dedicated introspection signer's key")
	}

	var claims map[string]any
	decodeJWSSegment(t, parts[1], &claims)
	// iss comes from s.resolveIssuer(ctx) — the request's own base URL —
	// same convention every other signed response in this server follows
	// (RFC 9207 iss, JARM, signed discovery metadata), NOT the
	// introspection signer's own configured issuer string.
	if claims["iss"] != srv.URL {
		t.Errorf("iss = %v, want %v", claims["iss"], srv.URL)
	}
	if claims["aud"] != introClient {
		t.Errorf("aud = %v, want introspecting client id", claims["aud"])
	}
	if _, present := claims["sub"]; present {
		t.Error("top-level sub MUST NOT be set (RFC 9701 §8)")
	}
	if _, present := claims["exp"]; present {
		t.Error("top-level exp MUST NOT be set (RFC 9701 §8)")
	}
	nested, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("no nested token_introspection claim: %v", claims)
	}
	if active, _ := nested["active"].(bool); !active {
		t.Errorf("nested active = %v, want true", nested["active"])
	}
	if nested["sub"] != introUser {
		t.Errorf("nested sub = %v, want %q", nested["sub"], introUser)
	}
}

func TestIntrospectionJWT_PlainJSONWithoutAcceptHeader(t *testing.T) {
	// Signer wired, but the caller never opted in — existing integrations
	// must be unaffected.
	srv, _ := newIntrospectionJWTServer(t, true)
	access, _ := loginForTokens(t, srv)

	resp := postIntrospectAccept(t, srv, access, "")
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if active, _ := out["active"].(bool); !active {
		t.Errorf("active = %v, want true", out["active"])
	}
}

func TestIntrospectionJWT_PlainJSONWhenFeatureUnwired(t *testing.T) {
	// Accept header sent, but WithIntrospectionSigning was never called —
	// default-off: the header is silently ignored, never an error.
	srv, _ := newIntrospectionJWTServer(t, false)
	access, _ := loginForTokens(t, srv)

	resp := postIntrospectAccept(t, srv, access, jwtIntrospectAccept)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json (feature unwired)", ct)
	}
}

func TestIntrospectionJWT_DiscoveryAndJWKS(t *testing.T) {
	srv, _ := newIntrospectionJWTServer(t, true)

	var doc map[string]any
	discResp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = discResp.Body.Close() }()
	_ = json.NewDecoder(discResp.Body).Decode(&doc)
	algs, _ := doc["introspection_signing_alg_values_supported"].([]any)
	if !containsAny(algs, "EdDSA") {
		t.Errorf("introspection_signing_alg_values_supported = %v, want EdDSA", algs)
	}

	jwksResp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jwksResp.Body.Close() }()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.NewDecoder(jwksResp.Body).Decode(&jwks)
	var sigKid, introKid string
	for _, k := range jwks.Keys {
		switch k["use"] {
		case "introspection":
			introKid, _ = k["kid"].(string)
		case "sig":
			sigKid, _ = k["kid"].(string)
		}
	}
	if introKid == "" {
		t.Fatalf("no use=introspection key in JWKS: %v", jwks.Keys)
	}
	if sigKid == "" {
		t.Fatalf("no use=sig key in JWKS: %v", jwks.Keys)
	}
	if introKid == sigKid {
		t.Error("introspection key and access-token signing key share a kid — must be independently keyed")
	}
}

func TestIntrospectionJWT_DiscoveryOmitsWhenUnwired(t *testing.T) {
	srv, _ := newIntrospectionJWTServer(t, false)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, ok := doc["introspection_signing_alg_values_supported"]; ok {
		t.Error("introspection_signing_alg_values_supported must be absent without WithIntrospectionSigning")
	}
}

// splitJWS splits a compact-serialization JWS into its 3 segments, failing
// the test if the shape is wrong.
func splitJWS(t *testing.T, jws string) [3]string {
	t.Helper()
	var out [3]string
	n := 0
	start := 0
	for i := 0; i <= len(jws); i++ {
		if i == len(jws) || jws[i] == '.' {
			if n >= 3 {
				t.Fatalf("not a 3-segment JWS: %q", jws)
			}
			out[n] = jws[start:i]
			n++
			start = i + 1
		}
	}
	if n != 3 {
		t.Fatalf("not a 3-segment JWS (got %d segments): %q", n, jws)
	}
	return out
}

// decodeJWSSegment base64url-decodes a JWS header/payload segment and
// unmarshals it into v.
func decodeJWSSegment(t *testing.T, seg string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}
