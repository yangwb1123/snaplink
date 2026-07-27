package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJK"

func TestAuthorizationCodePKCEFlow(t *testing.T) {
	server, cfg := testServer(t)
	discovery := getJSON(t, server.URL+"/.well-known/openid-configuration", "")
	if discovery["issuer"] != cfg.Issuer {
		t.Fatalf("discovery issuer = %v, want %s", discovery["issuer"], cfg.Issuer)
	}
	assertStringList(t, discovery[keyGrantTypes], []string{"authorization_code"})
	assertStringList(t, discovery[keyResponseTypes], []string{"code"})
	if discovery["device_authorization_endpoint"] != nil {
		t.Fatalf("prototype discovery advertises device flow: %v", discovery)
	}
	jwks := getJSON(t, server.URL+"/.well-known/jwks.json", "")
	if keys, ok := jwks["keys"].([]any); !ok || len(keys) == 0 {
		t.Fatalf("JWKS has no keys: %v", jwks)
	}
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	access, _ := tokens["access_token"].(string)
	if access == "" || tokens["id_token"] == nil {
		t.Fatalf("token response missing OIDC tokens: %v", tokens)
	}
	info := getJSON(t, server.URL+"/userinfo", access)
	if info["sub"] != cfg.User.ID {
		t.Fatalf("userinfo sub = %v, want %s", info["sub"], cfg.User.ID)
	}
}

func TestPrototypeHidesUnselectedRoutes(t *testing.T) {
	server, _ := testServer(t)
	for _, path := range []string{"/device/code", "/metrics", "/register"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestPrototypeRejectsClientCredentialsGrant(t *testing.T) {
	server, cfg := testServer(t)
	raw, err := json.Marshal(map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     cfg.Client.ID,
		"client_secret": cfg.Client.Secret,
	})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	resp, err := http.Post(
		server.URL+sso.PathToken,
		"application/json",
		bytes.NewReader(raw),
	)
	if err != nil {
		t.Fatalf("client_credentials request: %v", err)
	}
	defer resp.Body.Close()
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode rejection: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest ||
		body[sso.KeyError] != sso.ErrUnsupportedGrantType {
		t.Fatalf("client_credentials = %d %v", resp.StatusCode, body)
	}
	if resp.Header.Get(headerCacheControl) != valueNoStore {
		t.Fatalf("cache control = %q, want no-store", resp.Header.Get(headerCacheControl))
	}
}

func TestPKCEIsRequired(t *testing.T) {
	server, cfg := testServer(t)
	status, body := postJSON(t, server.URL+"/auth/login", loginPayload(cfg, "", ""))
	if status != http.StatusBadRequest || body["error"] != "pkce_required" {
		t.Fatalf("login without PKCE = %d %v, want 400 pkce_required", status, body)
	}
}

func TestWrongAndUnknownCredentialsAreIndistinguishable(t *testing.T) {
	server, cfg := testServer(t)
	known := loginPayload(cfg, pkceChallenge(testVerifier), "S256")
	known["credential"] = map[string]string{"username": cfg.User.Username, "password": "wrong"}
	unknown := loginPayload(cfg, pkceChallenge(testVerifier), "S256")
	unknown["credential"] = map[string]string{"username": "unknown", "password": "wrong"}
	knownStatus, knownBody := postRawJSON(t, server.URL+"/auth/login", known)
	unknownStatus, unknownBody := postRawJSON(t, server.URL+"/auth/login", unknown)
	if knownStatus != http.StatusUnauthorized || unknownStatus != knownStatus {
		t.Fatalf("credential statuses = known %d, unknown %d", knownStatus, unknownStatus)
	}
	knownEnvelope, unknownEnvelope := map[string]string{}, map[string]string{}
	if json.Unmarshal(knownBody, &knownEnvelope) != nil ||
		json.Unmarshal(unknownBody, &unknownEnvelope) != nil {
		t.Fatalf("decode credential failures: known=%s unknown=%s", knownBody, unknownBody)
	}
	if knownEnvelope["trace_id"] == "" || unknownEnvelope["trace_id"] == "" {
		t.Fatalf("credential failures lack trace IDs: known=%s unknown=%s", knownBody, unknownBody)
	}
	delete(knownEnvelope, "trace_id")
	delete(unknownEnvelope, "trace_id")
	if !maps.Equal(knownEnvelope, unknownEnvelope) {
		t.Fatalf("credential bodies differ:\nknown: %s\nunknown: %s", knownBody, unknownBody)
	}
}

func TestOPSessionSignsIntoSecondRPWithoutPassword(t *testing.T) {
	cfg := defaultsFromEnv(func(string) string { return "" })
	cfg.Issuer = "http://issuer.example"
	rpB := cfg.Second
	server, client, sessions := prototypeServerWithSessions(t, cfg)
	codeA := loginForCodeWithClient(t, client, server.URL, cfg, cfg.Client, true)
	exchangeForClient(t, client, server.URL, cfg.Client, codeA)
	originalAuthTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	setOPSessionAuthTime(t, sessions, originalAuthTime)
	codeB := loginForCodeWithClient(t, client, server.URL, cfg, rpB, false)
	tokens := exchangeForClient(t, client, server.URL, rpB, codeB)
	if tokens["id_token"] == nil {
		t.Fatalf("RP-B exchange returned no id_token: %v", tokens)
	}
	if got := jwtTimeClaim(t, tokens["id_token"], "auth_time"); got != originalAuthTime.Unix() {
		t.Fatalf("RP-B auth_time = %d, want original %d", got, originalAuthTime.Unix())
	}
}

func TestOPSessionSupportsPromptNoneAcrossRPs(t *testing.T) {
	cfg := defaultsFromEnv(func(string) string { return "" })
	cfg.Issuer = "http://issuer.example"
	rpB := clientSeed{
		ID: "rp-b", Secret: "rp-b-secret",
		RedirectURI: "http://127.0.0.1:3001/callback",
		Scopes:      []string{"openid"},
	}
	server, client := twoRPServer(t, cfg, rpB)
	loginForCodeWithClient(t, client, server.URL, cfg, cfg.Client, true)
	payload := loginPayloadForClient(cfg, rpB)
	delete(payload, "provider")
	delete(payload, "credential")
	payload["prompt"] = "none"
	status, body := postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if status != http.StatusOK || body["code"] == nil {
		t.Fatalf("RP-B prompt=none = %d %v, want authorization code", status, body)
	}
}

func TestOPSessionHonorsPromptLogin(t *testing.T) {
	cfg := defaultsFromEnv(func(string) string { return "" })
	cfg.Issuer = "http://issuer.example"
	rpB := clientSeed{
		ID: "rp-b", Secret: "rp-b-secret",
		RedirectURI: "http://127.0.0.1:3001/callback",
		Scopes:      []string{"openid"},
	}
	server, client := twoRPServer(t, cfg, rpB)
	loginForCodeWithClient(t, client, server.URL, cfg, cfg.Client, true)
	payload := loginPayloadForClient(cfg, rpB)
	delete(payload, "provider")
	delete(payload, "credential")
	payload["prompt"] = "login"
	_, body := postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if body["code"] != nil {
		t.Fatalf("prompt=login reused OP session: %v", body)
	}
}

func testServer(t *testing.T) (*httptest.Server, runtimeConfig) {
	t.Helper()
	cfg := defaultsFromEnv(func(string) string { return "" })
	cfg.Issuer = "https://issuer.example"
	app, err := buildHandler(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	return server, cfg
}

func twoRPServer(
	t *testing.T,
	cfg runtimeConfig,
	rpB clientSeed,
) (*httptest.Server, *http.Client) {
	t.Helper()
	app, err := buildHandlerWithClients(cfg, []clientSeed{rpB})
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return serverWithCookieJar(t, app)
}

func prototypeServer(
	t *testing.T,
	cfg runtimeConfig,
) (*httptest.Server, *http.Client) {
	t.Helper()
	server, client, _ := prototypeServerWithSessions(t, cfg)
	return server, client
}

func prototypeServerWithSessions(
	t *testing.T,
	cfg runtimeConfig,
) (*httptest.Server, *http.Client, *opSessionStore) {
	t.Helper()
	sessions := newOPSessionStore(cfg.User)
	app, err := buildHandlerWithSessions(cfg, []clientSeed{cfg.Second}, sessions)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server, client := serverWithCookieJar(t, app)
	return server, client, sessions
}

func serverWithCookieJar(
	t *testing.T,
	app http.Handler,
) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return server, &http.Client{Jar: jar}
}

func loginForCode(t *testing.T, base string, cfg runtimeConfig, verifier string) string {
	t.Helper()
	status, body := postJSON(t, base+"/auth/login",
		loginPayload(cfg, pkceChallenge(verifier), "S256"))
	if status != http.StatusOK {
		t.Fatalf("login = %d %v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("login returned no code: %v", body)
	}
	return code
}

func exchangeCode(
	t *testing.T,
	base string,
	cfg runtimeConfig,
	code, verifier string,
) map[string]any {
	t.Helper()
	status, body := postJSON(t, base+"/token", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     cfg.Client.ID,
		"client_secret": cfg.Client.Secret,
		"redirect_uri":  cfg.Client.RedirectURI,
		"code_verifier": verifier,
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange = %d %v", status, body)
	}
	return body
}

func loginForCodeWithClient(
	t *testing.T,
	httpClient *http.Client,
	base string,
	cfg runtimeConfig,
	client clientSeed,
	withPassword bool,
) string {
	t.Helper()
	payload := loginPayloadForClient(cfg, client)
	if !withPassword {
		delete(payload, "provider")
		delete(payload, "credential")
	}
	status, body := postJSONWithClient(t, httpClient, base+"/auth/login", payload)
	if status != http.StatusOK {
		t.Fatalf("%s login = %d %v", client.ID, status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("%s login returned no code: %v", client.ID, body)
	}
	return code
}

func exchangeForClient(
	t *testing.T,
	httpClient *http.Client,
	base string,
	client clientSeed,
	code string,
) map[string]any {
	t.Helper()
	status, body := postJSONWithClient(t, httpClient, base+"/token", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     client.ID,
		"client_secret": client.Secret,
		"redirect_uri":  client.RedirectURI,
		"code_verifier": testVerifier,
	})
	if status != http.StatusOK {
		t.Fatalf("%s exchange = %d %v", client.ID, status, body)
	}
	return body
}

func loginPayloadForClient(cfg runtimeConfig, client clientSeed) map[string]any {
	payload := loginPayload(cfg, pkceChallenge(testVerifier), "S256")
	payload["client_id"] = client.ID
	payload["redirect_uri"] = client.RedirectURI
	payload["scope"] = client.Scopes
	return payload
}

func loginPayload(cfg runtimeConfig, challenge, method string) map[string]any {
	return map[string]any{
		"provider":              "password",
		"client_id":             cfg.Client.ID,
		"credential":            map[string]string{"username": cfg.User.Username, "password": cfg.User.Password},
		"response_type":         "code",
		"redirect_uri":          cfg.Client.RedirectURI,
		"scope":                 cfg.Client.Scopes,
		"code_challenge":        challenge,
		"code_challenge_method": method,
	}
}

func postJSON(t *testing.T, endpoint string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	return postJSONWithClient(t, http.DefaultClient, endpoint, payload)
}

func postJSONWithClient(
	t *testing.T,
	client *http.Client,
	endpoint string,
	payload map[string]any,
) (int, map[string]any) {
	t.Helper()
	status, raw := postRawJSONWithClient(t, client, endpoint, payload)
	body := map[string]any{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode response: %v body=%s", err, raw)
	}
	return status, body
}

func postRawJSON(t *testing.T, endpoint string, payload map[string]any) (int, []byte) {
	t.Helper()
	return postRawJSONWithClient(t, http.DefaultClient, endpoint, payload)
}

func postRawJSONWithClient(
	t *testing.T,
	client *http.Client,
	endpoint string,
	payload map[string]any,
) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, body
}

func getJSON(t *testing.T, endpoint, bearer string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func assertStringList(t *testing.T, value any, want []string) {
	t.Helper()
	raw, ok := value.([]any)
	if !ok || len(raw) != len(want) {
		t.Fatalf("list = %#v, want %v", value, want)
	}
	for index, expected := range want {
		if raw[index] != expected {
			t.Fatalf("list = %#v, want %v", value, want)
		}
	}
}

func setOPSessionAuthTime(t *testing.T, sessions *opSessionStore, authTime time.Time) {
	t.Helper()
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	if len(sessions.sessions) != 1 {
		t.Fatalf("OP sessions = %d, want 1", len(sessions.sessions))
	}
	for key, session := range sessions.sessions {
		session.authenticatedAt = authTime
		sessions.sessions[key] = session
	}
}

func jwtTimeClaim(t *testing.T, raw any, name string) int64 {
	t.Helper()
	token, ok := raw.(string)
	if !ok {
		t.Fatalf("%s token = %T, want string", name, raw)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%s token has %d parts", name, len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode %s payload: %v", name, err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode %s claims: %v", name, err)
	}
	value, ok := claims[name].(float64)
	if !ok {
		t.Fatalf("%s claim = %v", name, claims[name])
	}
	return int64(value)
}
