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
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

const (
	jcaClientID = "jca-client"
	jcaUserID   = "u-jca"
	jcaPassword = "pw"
	jcaKid      = "jca-kid-1"
	jcaASIssuer = "https://sso.test"
	jcaRedirect = "https://app.example/cb"
)

type jcaHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
	store   security.JTIReplayStore
}

func newJCAHarness(t *testing.T, withReplay bool) *jcaHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jcaUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    jcaClientID,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jcaRedirect},
		// No Secret — confidential client authenticating purely
		// via JWT assertion.
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jcaKid, Alg: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != jcaPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: jcaUserID}, nil
		},
	))
	opts := []sso.Option{
		sso.WithIssuer(jcaASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(jcaASIssuer), defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	}
	var replay security.JTIReplayStore
	if withReplay {
		replay = defaultimpl.NewMemoryJTIReplayStore()
		opts = append(opts, sso.WithJTIReplayStore(replay))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &jcaHarness{srv: httpSrv, signKey: priv, store: replay}
}

func (h *jcaHarness) signAssertion(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// callTokenWithAssertion exercises /token grant=client_credentials
// using the assertion JWT for client auth. Returns status + body map.
func callTokenWithAssertion(t *testing.T, srv *httptest.Server, assertion string) (int, map[string]any) {
	t.Helper()
	form := "grant_type=client_credentials" +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + assertion
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestJWTClientAssertion_HappyPath(t *testing.T) {
	h := newJCAHarness(t, false)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID,
		"sub": jcaClientID,
		"aud": jcaASIssuer,
		"exp": now + 60,
		"iat": now,
		"jti": "jca-jti-1",
	}, jcaKid)
	status, body := callTokenWithAssertion(t, h.srv, jwt)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["access_token"] == nil {
		t.Errorf("no access_token: %v", body)
	}
}

func TestJWTClientAssertion_RejectsBadSignature(t *testing.T) {
	h := newJCAHarness(t, false)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": jcaClientID, "aud": jcaASIssuer,
		"exp": now + 60, "iat": now,
	}, jcaKid)
	// Tamper with the signature.
	parts := strings.Split(jwt, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")
	status, body := callTokenWithAssertion(t, h.srv, tampered)
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidClient {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidClient)
	}
}

func TestJWTClientAssertion_RejectsExpired(t *testing.T) {
	h := newJCAHarness(t, false)
	past := time.Now().Add(-time.Hour).Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": jcaClientID, "aud": jcaASIssuer,
		"exp": past, "iat": past - 60,
	}, jcaKid)
	status, _ := callTokenWithAssertion(t, h.srv, jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", status)
	}
}

func TestJWTClientAssertion_RejectsMismatchedIssSub(t *testing.T) {
	h := newJCAHarness(t, false)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": "different-id", // mismatched
		"aud": jcaASIssuer, "exp": now + 60, "iat": now,
	}, jcaKid)
	status, _ := callTokenWithAssertion(t, h.srv, jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", status)
	}
}

func TestJWTClientAssertion_RejectsWrongAudience(t *testing.T) {
	h := newJCAHarness(t, false)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": jcaClientID,
		"aud": "https://wrong-as.example",
		"exp": now + 60, "iat": now,
	}, jcaKid)
	status, _ := callTokenWithAssertion(t, h.srv, jwt)
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 (wrong aud must reject)", status)
	}
}

func TestJWTClientAssertion_RejectsUnknownAssertionType(t *testing.T) {
	h := newJCAHarness(t, false)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": jcaClientID, "aud": jcaASIssuer,
		"exp": now + 60, "iat": now,
	}, jcaKid)
	// Use an unrecognized assertion type (SAML2 not supported).
	form := "grant_type=client_credentials" +
		"&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer" +
		"&client_assertion=" + jwt
	resp, err := http.Post(h.srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (unsupported assertion type)", resp.StatusCode)
	}
}

func TestJWTClientAssertion_ReplayDetectedWhenStoreWired(t *testing.T) {
	h := newJCAHarness(t, true)
	now := time.Now().Unix()
	jwt := h.signAssertion(t, map[string]any{
		"iss": jcaClientID, "sub": jcaClientID, "aud": jcaASIssuer,
		"exp": now + 60, "iat": now,
		"jti": "replay-target-jca",
	}, jcaKid)

	if status, _ := callTokenWithAssertion(t, h.srv, jwt); status != http.StatusOK {
		t.Fatalf("first use status=%d want 200", status)
	}
	// Replay MUST be rejected.
	if status, body := callTokenWithAssertion(t, h.srv, jwt); status != http.StatusUnauthorized {
		t.Fatalf("replay status=%d want 401 body=%v", status, body)
	}
}

func TestJWTClientAssertion_DiscoveryAdvertisesPrivateKeyJWT(t *testing.T) {
	h := newJCAHarness(t, false)
	resp, err := http.Get(h.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	methods, _ := doc["token_endpoint_auth_methods_supported"].([]any)
	found := false
	for _, m := range methods {
		if m == "private_key_jwt" {
			found = true
		}
	}
	if !found {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want to contain private_key_jwt", methods)
	}
}
