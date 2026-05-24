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

const (
	jcaEPClientID = "jca-ep-client"
	jcaEPUserID   = "u-jca-ep"
	jcaEPPassword = "pw"
	jcaEPKid      = "jca-ep-kid"
	jcaEPISS      = "https://sso.test"
	jcaEPRedirect = "https://app.example/cb"
)

type jcaEPHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
}

func newJCAEPHarness(t *testing.T) *jcaEPHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jcaEPUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jcaEPClientID, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jcaEPRedirect},
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jcaEPKid, Alg: "EdDSA", Use: "sig",
			X: base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != jcaEPPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: jcaEPUserID}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithIssuer(jcaEPISS),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(jcaEPISS), defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 0),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &jcaEPHarness{srv: httpSrv, signKey: priv}
}

func (h *jcaEPHarness) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": jcaEPKid}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (h *jcaEPHarness) freshAssertion(t *testing.T, jti string) string {
	t.Helper()
	now := time.Now().Unix()
	return h.sign(t, map[string]any{
		"iss": jcaEPClientID, "sub": jcaEPClientID, "aud": jcaEPISS,
		"exp": now + 60, "iat": now, "jti": jti,
	})
}

func TestJWTClientAssertion_PARAuthenticatesClient(t *testing.T) {
	h := newJCAEPHarness(t)
	assertion := h.freshAssertion(t, "par-1")
	form := "client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + assertion +
		"&response_type=code&redirect_uri=" + jcaEPRedirect
	resp, err := http.Post(h.srv.URL+"/par", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["request_uri"] == nil {
		t.Errorf("no request_uri: %v", out)
	}
}

func TestJWTClientAssertion_IntrospectAuthenticatesClient(t *testing.T) {
	h := newJCAEPHarness(t)
	// Mint an access token via client_credentials with assertion.
	tokForm := "grant_type=client_credentials" +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + h.freshAssertion(t, "ep-introspect-mint")
	tokResp, err := http.Post(h.srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(tokForm)))
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	tokRB, _ := io.ReadAll(tokResp.Body)
	var tokOut map[string]any
	_ = json.Unmarshal(tokRB, &tokOut)
	access, _ := tokOut["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token from mint: %s", tokRB)
	}

	// Now introspect it using a fresh assertion.
	introForm := "token=" + access +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + h.freshAssertion(t, "ep-introspect-call")
	introResp, err := http.Post(h.srv.URL+"/token/introspect", "application/x-www-form-urlencoded", bytes.NewReader([]byte(introForm)))
	if err != nil {
		t.Fatal(err)
	}
	defer introResp.Body.Close()
	introRB, _ := io.ReadAll(introResp.Body)
	if introResp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status=%d body=%s", introResp.StatusCode, introRB)
	}
	var introOut map[string]any
	_ = json.Unmarshal(introRB, &introOut)
	if introOut["active"] != true {
		t.Errorf("active = %v want true", introOut["active"])
	}
}

func TestJWTClientAssertion_RevokeAuthenticatesClient(t *testing.T) {
	h := newJCAEPHarness(t)
	// Mint a token using client_credentials + assertion.
	tokForm := "grant_type=client_credentials" +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + h.freshAssertion(t, "ep-revoke-mint")
	tokResp, err := http.Post(h.srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(tokForm)))
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	var tokOut map[string]any
	_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
	access, _ := tokOut["access_token"].(string)

	// Revoke it.
	revForm := "token=" + access +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + h.freshAssertion(t, "ep-revoke-call")
	revResp, err := http.Post(h.srv.URL+"/token/revoke", "application/x-www-form-urlencoded", bytes.NewReader([]byte(revForm)))
	if err != nil {
		t.Fatal(err)
	}
	defer revResp.Body.Close()
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d", revResp.StatusCode)
	}
}
