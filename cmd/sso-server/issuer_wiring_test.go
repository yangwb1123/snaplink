package main

// issuer_wiring_test.go pins, end to end at the cmd/sso-server binary
// level, that cfg.Server.Issuer — never the request Host/base URL — is
// the single source of truth for the discovery issuer, the RFC 9207 `iss`
// in authorization responses, and the access/id-token `iss` claims.
// Design: docs/architect-analysis/auto/cmd-sso-server-issuer-wiring-design.md
// (T-2a/T-2b/T-2c; T-2d is the existing TestConfigRejectsSDKSentinel).
//
// These tests exist because the direction's acceptance checks were the one
// real gap: the wiring itself (config.ServerOptions -> sso.WithIssuer ->
// s.issuer -> resolveIssuer/discovery override, and serverbuildsign
// WithEd25519Issuer for the JWT iss) was already shipped. A regression here
// means a future refactor re-opened the G1 identity-anchor divergence the
// direction warned about.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
)

const (
	issWireIssuer   = "https://sso.example.com"
	issWireClientID = "iss-wire-client"
	issWireSecret   = "iss-wire-secret"
	issWireUser     = "iss-wire-user"
	issWirePassword = "iss-wire-pass"
	issWireRedirect = "https://rp.example/cb"
)

// newIssuerWiringServer builds the real binary composition (buildApp) with
// server.issuer pinned, one seeded JWT client (skip-consent, password
// authenticator) and one seeded bcrypt password user, then serves it over
// httptest. The bcrypt hash is generated per-test in a tempdir — no
// committed secrets, no YAML fixtures.
func newIssuerWiringServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.Issuer = issWireIssuer
	// The authorization_code grant is opt-in in this binary
	// (wireOAuthGrantStores only wires WithAuthCodeStore when enabled);
	// T-2b/T-2c exercise the code flow, so the fixture opts in. Default
	// backend is memory — no file or cluster dependency.
	cfg.OAuth.AuthCode.Enabled = true
	cfg.Clients = []config.ClientConfig{{
		ID:                    issWireClientID,
		Secret:                issWireSecret,
		RedirectURIs:          []string{issWireRedirect},
		AllowedScopes:         []string{"openid", "profile"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
		SkipConsent:           true,
	}}
	cfg.Authenticators.Password = &config.PasswordConfig{
		Enabled: true,
		Users: []config.PasswordUserConfig{{
			Username:       issWireUser,
			BcryptHashFile: writeBcryptHashFile(t, issWirePassword),
			SubjectID:      issWireUser,
		}},
	}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	t.Cleanup(func() { shutdownApp(t, a) })
	srv := httptest.NewServer(a.server.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// issWireDoGET issues a GET with extra headers (T-2a needs tampered
// X-Forwarded-* headers the shared fetchDoc helper cannot set).
func issWireDoGET(t *testing.T, rawURL string, headers map[string]string) (map[string]any, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new GET %s: %v", rawURL, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	return doc, resp.Header
}

// issWirePostJSON posts a JSON body and returns status, decoded map, and
// response headers.
func issWirePostJSON(t *testing.T, rawURL string, body map[string]any) (int, map[string]any, http.Header) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new POST %s: %v", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out, resp.Header
}

// issWirePostRaw is issWirePostJSON without JSON decoding — the form_post
// path answers with an auto-POST HTML page, not JSON.
func issWirePostRaw(t *testing.T, rawURL string, body map[string]any) (int, []byte, http.Header) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new POST %s: %v", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rb, resp.Header
}

// issWireTokenForm posts an application/x-www-form-urlencoded /token
// request with HTTP Basic client credentials — Basic wins over body
// credentials per bindOAuthParams, so the secret never rides the form.
func issWireTokenForm(t *testing.T, tokenURL, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", tokenURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// decodeJWTPayload decodes the payload segment of a JWT without signature
// verification — the token is this server's own response and the assertion
// is the `iss` payload value, not authenticity.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q has %d segments, want 3", token, len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal JWT payload: %v", err)
	}
	return payload
}

// TestBuildApp_DiscoveryIssuerIgnoresTamperedHost is acceptance (a): the
// discovery issuer must come from server.issuer, never from the request
// Host/base URL. The legacy first-hop trust path honors X-Forwarded-*
// (ForwardedHeadersTrusted defaults true with no TrustedProxies), so a
// tampered Host would surface as http://attacker.example here if the
// WithIssuer -> applyMFAIssuerSigning discovery override were dropped.
func TestBuildApp_DiscoveryIssuerIgnoresTamperedHost(t *testing.T) {
	t.Parallel()
	srv := newIssuerWiringServer(t)

	doc, _ := issWireDoGET(t, srv.URL+"/.well-known/openid-configuration", map[string]string{
		"X-Forwarded-Host":  "attacker.example",
		"X-Forwarded-Proto": "http",
	})
	got, ok := doc["issuer"].(string)
	if !ok || got != issWireIssuer {
		t.Fatalf("discovery issuer = %q (present=%v), want %q", got, ok, issWireIssuer)
	}
}

// TestBuildApp_AuthzErrorIssMatchesDiscoveryIssuer is acceptance (b): every
// RFC 9207 `iss` this server emits on the authorization endpoint — the
// unknown-client error body, the form_post hidden input, and the code-flow
// success envelope — equals the discovery issuer, and the credential
// endpoint carries the no-store header set.
func TestBuildApp_AuthzErrorIssMatchesDiscoveryIssuer(t *testing.T) {
	t.Parallel()
	srv := newIssuerWiringServer(t)

	doc := fetchDiscovery(t, srv.URL)
	discoveryIssuer, _ := doc["issuer"].(string)
	if discoveryIssuer != issWireIssuer {
		t.Fatalf("discovery issuer = %q, want %q", discoveryIssuer, issWireIssuer)
	}

	// Unknown client -> 401 invalid_client with RFC 9207 iss + no-store.
	status, body, hdr := issWirePostJSON(t, srv.URL+"/auth/login", map[string]any{
		"provider":  authenticators.MethodPassword,
		"client_id": "no-such-client",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown-client login = %d, want 401 (body=%v)", status, body)
	}
	if got, _ := body["error"].(string); got != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client", got)
	}
	if got, _ := body["iss"].(string); got != issWireIssuer {
		t.Fatalf("error body iss = %q, want %q", got, issWireIssuer)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if pragma := hdr.Get("Pragma"); pragma != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", pragma)
	}

	// form_post success renders the hidden iss input with the same value.
	status, rawBody, hdr := issWirePostRaw(t, srv.URL+"/auth/login", map[string]any{
		"provider":      authenticators.MethodPassword,
		"client_id":     issWireClientID,
		"credential":    map[string]string{"username": issWireUser, "password": issWirePassword},
		"response_type": "code",
		"redirect_uri":  issWireRedirect,
		"response_mode": "form_post",
		"state":         "fp-state",
	})
	if status != http.StatusOK {
		t.Fatalf("form_post login = %d, want 200", status)
	}
	if ct := hdr.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("form_post Content-Type = %q, want text/html", ct)
	}
	wantInput := `name="iss" value="` + issWireIssuer + `"`
	if !strings.Contains(string(rawBody), wantInput) {
		t.Errorf("form_post body missing %q:\n%s", wantInput, rawBody)
	}

	// Code-flow success envelope carries iss.
	status, body, _ = issWirePostJSON(t, srv.URL+"/auth/login", map[string]any{
		"provider":      authenticators.MethodPassword,
		"client_id":     issWireClientID,
		"credential":    map[string]string{"username": issWireUser, "password": issWirePassword},
		"response_type": "code",
		"redirect_uri":  issWireRedirect,
		"state":         "s-1",
	})
	if status != http.StatusOK {
		t.Fatalf("code login = %d, want 200 (body=%v)", status, body)
	}
	if got, _ := body["iss"].(string); got != issWireIssuer {
		t.Fatalf("code-flow success iss = %q, want %q", got, issWireIssuer)
	}
}

// TestBuildApp_TokenIssClaimsMatchDiscoveryIssuer is acceptance (c): the
// JWT `iss` claim of access and id tokens from both the client-credentials
// grant and a full authorization-code flow equals the discovery issuer.
// Both issuance paths derive iss from the shared Ed25519JWTIssuer built
// with WithEd25519Issuer(srv.Issuer), so a mismatch here means the JWT
// anchor and the discovery anchor diverged.
func TestBuildApp_TokenIssClaimsMatchDiscoveryIssuer(t *testing.T) {
	t.Parallel()
	srv := newIssuerWiringServer(t)

	doc := fetchDiscovery(t, srv.URL)
	discoveryIssuer, _ := doc["issuer"].(string)
	if discoveryIssuer != issWireIssuer {
		t.Fatalf("discovery issuer = %q, want %q", discoveryIssuer, issWireIssuer)
	}

	// Client-credentials grant, Basic client auth only.
	status, tok := issWireTokenForm(t, srv.URL+"/token", issWireClientID, issWireSecret, url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("client_credentials = %d, want 200 (body=%v)", status, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %v", tok)
	}
	if got, _ := decodeJWTPayload(t, access)["iss"].(string); got != issWireIssuer {
		t.Fatalf("client-credentials access_token iss = %q, want %q", got, issWireIssuer)
	}

	// Authorization-code flow: login with scope openid profile, exchange.
	status, body, _ := issWirePostJSON(t, srv.URL+"/auth/login", map[string]any{
		"provider":      authenticators.MethodPassword,
		"client_id":     issWireClientID,
		"credential":    map[string]string{"username": issWireUser, "password": issWirePassword},
		"response_type": "code",
		"redirect_uri":  issWireRedirect,
		"state":         "s-2",
		"scope":         []string{"openid", "profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("code login = %d, want 200 (body=%v)", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", body)
	}
	status, tok = issWireTokenForm(t, srv.URL+"/token", issWireClientID, issWireSecret, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {issWireRedirect},
	})
	if status != http.StatusOK {
		t.Fatalf("authorization_code = %d, want 200 (body=%v)", status, tok)
	}
	access, _ = tok["access_token"].(string)
	idToken, _ := tok["id_token"].(string)
	if access == "" || idToken == "" {
		t.Fatalf("exchange missing tokens (access=%q id=%q)", access, idToken)
	}
	for name, token := range map[string]string{"access_token": access, "id_token": idToken} {
		if got, _ := decodeJWTPayload(t, token)["iss"].(string); got != issWireIssuer {
			t.Fatalf("auth-code %s iss = %q, want %q", name, got, issWireIssuer)
		}
	}
}
