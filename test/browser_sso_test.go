package ssotest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc/browsersso"
	"github.com/yangwb1123/snaplink/shared/core"
)

const browserIssuer = "http://sso.example.test"
const browserVerifier = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

type browserHarness struct {
	server        *sso.Server
	http          *httptest.Server
	browser       *http.Client
	issuer        *defaultimpl.Ed25519JWTIssuer
	users         *defaultimpl.MemoryUserProvider
	sessions      core.SessionManager
	passwordCalls atomic.Int64
}

func newBrowserHarness(t *testing.T, enabled, consent bool, extra ...sso.Option) *browserHarness {
	t.Helper()
	h := &browserHarness{issuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(browserIssuer)), users: defaultimpl.NewMemoryUserProvider(), sessions: defaultimpl.NewMemorySessionManager()}
	clients := defaultimpl.NewMemoryClientStore()
	for _, id := range []string{"rp-a", "rp-b"} {
		clients.AddSeed(&sso.Client{ID: id, Name: id, Active: true, TokenStrategy: "jwt", RequirePKCE: true, TokenEndpointAuthMethod: "none",
			AllowedScopes: []string{"openid", id + ":read"}, AllowedResources: []string{id + "-api"},
			AllowedAuthenticators: []string{"password"}, RedirectURIs: []string{"https://" + id + ".example/callback"}, SkipConsent: id == "rp-a"})
	}
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(_ context.Context, user, password string) (*sso.AuthResult, error) {
		h.passwordCalls.Add(1)
		if user != "alice" || password != "test-password" {
			return nil, errors.New("invalid credential")
		}
		return &sso.AuthResult{UserID: "alice", ExternalID: "alice", Provider: "password", AuthMethods: []string{"pwd"}, AchievedACR: "urn:test:pwd", Attributes: map[string]string{"email": "alice@example.test"}}, nil
	}))
	opts := []sso.Option{sso.WithIssuer(browserIssuer), sso.WithUserProvider(h.users), sso.WithClientStore(clients), sso.WithSessionManager(h.sessions), sso.WithAuthenticator(password),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute), sso.WithTokenIssuer("jwt", h.issuer), sso.WithIDTokenIssuer(h.issuer),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour)}
	if enabled {
		opts = append(opts, sso.WithBrowserSSO(h.issuer, h.issuer))
	}
	if consent {
		opts = append(opts, sso.WithConsentStore(defaultimpl.NewMemoryConsentStore()))
	}
	opts = append(opts, extra...)
	h.server = sso.NewServer(opts...)
	h.http = httptest.NewServer(h.server.Handler())
	t.Cleanup(h.http.Close)
	jar, _ := cookiejar.New(nil)
	h.browser = &http.Client{Jar: jar}
	return h
}

func browserRequest(client string, resume bool) map[string]any {
	challenge := sha256.Sum256([]byte(browserVerifier))
	body := map[string]any{"client_id": client, "response_type": "code", "redirect_uri": "https://" + client + ".example/callback",
		"scope": []string{"openid", client + ":read"}, "resource": []string{client + "-api"}, "state": client + "-state", "nonce": client + "-nonce",
		"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"}
	if resume {
		body["resume_session"] = true
	} else {
		body["provider"] = "password"
		body["credential"] = map[string]string{"username": "alice", "password": "test-password"}
	}
	return body
}

func browserPost(t *testing.T, h *browserHarness, path string, body map[string]any) (int, map[string]any, http.Header) {
	t.Helper()
	raw, _ := json.Marshal(body)
	response, err := h.browser.Post(h.http.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	result := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		t.Fatal("credential response missing no-store")
	}
	return response.StatusCode, result, response.Header
}

func browserExchange(t *testing.T, h *browserHarness, client string, code any) map[string]any {
	t.Helper()
	response, err := h.browser.PostForm(h.http.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code.(string)}, "redirect_uri": {"https://" + client + ".example/callback"}, "code_verifier": {browserVerifier}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	out := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exchange failed: status=%d error=%v", response.StatusCode, out["error"])
	}
	return out
}

func browserCookie(t *testing.T, h *browserHarness) *http.Cookie {
	t.Helper()
	origin, _ := url.Parse(h.http.URL)
	for _, cookie := range h.browser.Jar.Cookies(origin) {
		if cookie.Name == browsersso.CookieName {
			return cookie
		}
	}
	t.Fatal("missing OP cookie")
	return nil
}

func TestE2E_BrowserSSO_SecondRPHasIndependentGrant(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	status, a, headers := browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	if status != 200 || a["code"] == nil {
		t.Fatalf("first RP login: %d error=%v", status, a["error"])
	}
	if !strings.Contains(headers.Get("Set-Cookie"), "HttpOnly") || !strings.Contains(headers.Get("Set-Cookie"), "SameSite=Lax") {
		t.Fatal("unsafe OP cookie attributes")
	}
	cookieBefore := browserCookie(t, h).Value
	aTokens := browserExchange(t, h, "rp-a", a["code"])
	status, discovery, _ := browserPost(t, h, "/auth/login", map[string]any{"client_id": "rp-b"})
	if status != 200 || discovery[browsersso.KeySupported] != true || discovery[browsersso.KeyAvailable] != true {
		t.Fatal("cookie session not discoverable")
	}
	status, b, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if status != 200 || b["code"] == nil {
		t.Fatalf("second RP resume: %d error=%v", status, b["error"])
	}
	bTokens := browserExchange(t, h, "rp-b", b["code"])
	if h.passwordCalls.Load() != 1 {
		t.Fatal("second RP repeated password authentication")
	}
	if aTokens["access_token"] == bTokens["access_token"] || aTokens["refresh_token"] == bTokens["refresh_token"] {
		t.Fatal("RPs shared credentials")
	}
	aClaims, err := h.issuer.Validate(context.Background(), aTokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	bClaims, err := h.issuer.Validate(context.Background(), bTokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if aClaims.ClientID != "rp-a" || bClaims.ClientID != "rp-b" || strings.Join(bClaims.Audience, " ") != "rp-b-api" || strings.Join(bClaims.Scopes, " ") != "openid rp-b:read" {
		t.Fatal("RP authorization binding leaked")
	}
	if aClaims.SID == "" || bClaims.SID == "" || aClaims.SID == bClaims.SID {
		t.Fatal("RP scope ceilings shared a session")
	}
	if !aClaims.AuthTime.Equal(bClaims.AuthTime) || bClaims.ACR != "urn:test:pwd" || strings.Join(bClaims.AMR, " ") != "pwd" {
		t.Fatal("resume changed authentication context")
	}
	if browserCookie(t, h).Value != cookieBefore {
		t.Fatal("resume rolled OP authentication lifetime")
	}
	if _, err := h.server.ValidateToken(context.Background(), cookieBefore); err == nil {
		t.Fatal("identity cookie accepted as API bearer")
	}
}

func TestE2E_BrowserSSO_NewRPConsentResumesWithoutPassword(t *testing.T) {
	h := newBrowserHarness(t, true, true)
	_, a, _ := browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	if a["code"] == nil {
		t.Fatal("first RP failed")
	}
	_, pending, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if pending["error"] != "consent_required" || pending["login_transaction_id"] == nil || pending["consent_challenge_id"] == nil {
		t.Fatal("new RP skipped independent consent")
	}
	status, approved, _ := browserPost(t, h, "/auth/login", map[string]any{"client_id": "rp-b", "login_transaction_id": pending["login_transaction_id"], "consent_challenge_id": pending["consent_challenge_id"], "consent_decision": "allow"})
	if status != 200 || approved["code"] == nil || h.passwordCalls.Load() != 1 {
		t.Fatalf("consent resume failed: %d error=%v", status, approved["error"])
	}
}

func TestE2E_BrowserSSO_AuthenticationAndAuthorizationGuards(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		value     any
		want      string
	}{
		{"forced login", "prompt", "login", "login_required"}, {"account selection", "prompt", "select_account", "login_required"},
		{"fresh authentication", "max_age", 0, "login_required"}, {"stronger ACR", "acr_values", "urn:test:mfa", "unmet_authentication_requirements"},
		{"wrong login hint", "login_hint", "other@example.test", "login_required"},
		{"scope expansion", "scope", []string{"openid", "rp-a:read"}, "invalid_scope"}, {"resource expansion", "resource", []string{"rp-a-api"}, "invalid_target"},
		{"redirect substitution", "redirect_uri", "https://attacker.test/callback", "invalid_redirect_uri"},
		{"mixed prompt", "prompt", "none login", "invalid_request"}, {"bad PKCE", "code_challenge", "bad", "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBrowserHarness(t, true, false)
			browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
			request := browserRequest("rp-b", true)
			request[tc.key] = tc.value
			_, out, _ := browserPost(t, h, "/auth/login", request)
			if out["error"] != tc.want || out["code"] != nil || h.passwordCalls.Load() != 1 {
				t.Fatalf("guard failed: error=%v want=%s", out["error"], tc.want)
			}
		})
	}
}

func TestE2E_BrowserSSO_RevocationAndCookieIsolation(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	cookie := browserCookie(t, h)
	cookieClaims, err := h.issuer.ValidateBrowserSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sessions.Destroy(context.Background(), cookieClaims.SID); err != nil {
		t.Fatal(err)
	}
	_, out, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if out["error"] != "login_required" {
		t.Fatal("revoked OP session authenticated")
	}
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	sharedJar := h.browser.Jar
	h.browser.Jar, _ = cookiejar.New(nil)
	_, isolated, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if isolated["error"] != "login_required" {
		t.Fatal("isolated browser shared identity")
	}
	h.browser.Jar = sharedJar
	status, resumed, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if status != 200 || resumed["code"] == nil {
		t.Fatal("shared browser did not restore identity")
	}
}

func TestE2E_BrowserSSO_DefaultOffAndOpaqueRequestsRemainOneShot(t *testing.T) {
	h := newBrowserHarness(t, false, false)
	_, a, headers := browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	if a["code"] == nil || headers.Get("Set-Cookie") != "" {
		t.Fatal("feature-off login changed")
	}
	_, discovery, _ := browserPost(t, h, "/auth/login", map[string]any{"client_id": "rp-b"})
	if discovery[browsersso.KeySupported] != nil {
		t.Fatal("disabled feature advertised")
	}
	par := defaultimpl.NewMemoryPARStore()
	h = newBrowserHarness(t, true, false, sso.WithPARStore(par, time.Minute))
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	uri, err := par.Issue(context.Background(), &oauth.PARRequest{ClientID: "rp-b", ResponseType: "code", RedirectURI: "https://rp-b.example/callback", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest("rp-b", true)
	request["request_uri"] = uri
	_, out, _ := browserPost(t, h, "/auth/login", request)
	if out["error"] != "invalid_request" {
		t.Fatal("automatic resume accepted opaque authorization")
	}
	stored, err := par.Consume(context.Background(), uri)
	if err != nil || stored.ClientID != "rp-b" {
		t.Fatal("automatic resume burned one-use PAR")
	}
}

func TestE2E_BrowserSSO_LogoutClearsIdentityCookie(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	_, a, _ := browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	tokens := browserExchange(t, h, "rp-a", a["code"])
	request, _ := http.NewRequest(http.MethodGet, h.http.URL+"/end_session?id_token_hint="+url.QueryEscape(tokens["id_token"].(string)), nil)
	response, err := h.browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 204 || !strings.Contains(response.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatal("logout did not expire OP cookie")
	}
	_, out, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if out["error"] != "login_required" {
		t.Fatal("logout retained reusable identity")
	}
}
