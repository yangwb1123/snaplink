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
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
)

const testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJK"

func TestAuthorizationCodePKCEFlow(t *testing.T) {
	server, cfg := testServer(t)
	discovery := getJSON(t, server.URL+sso.PathOAuthAuthorizationServerMetadata, "")
	if discovery["issuer"] != cfg.Issuer {
		t.Fatalf("discovery issuer = %v, want %s", discovery["issuer"], cfg.Issuer)
	}
	assertStringList(t, discovery[composition.KeyGrantTypes], []string{"authorization_code"})
	assertStringList(t, discovery[composition.KeyResponseTypes], []string{"code"})
	if discovery["device_authorization_endpoint"] != nil {
		t.Fatalf("prototype discovery advertises device flow: %v", discovery)
	}
	if discovery["userinfo_endpoint"] != nil {
		t.Fatalf("prototype discovery advertises the OIDC surface: %v", discovery)
	}
	jwks := getJSON(t, server.URL+"/.well-known/jwks.json", "")
	if keys, ok := jwks["keys"].([]any); !ok || len(keys) == 0 {
		t.Fatalf("JWKS has no keys: %v", jwks)
	}
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatalf("token response missing access token: %v", tokens)
	}
	if tokens["id_token"] != nil {
		t.Fatalf("prototype token response carries an id_token: %v", tokens)
	}
}

func TestPrototypeHidesUnselectedRoutes(t *testing.T) {
	server, _ := testServer(t)
	for _, path := range []string{
		"/device/code",
		"/metrics",
		"/register",
		sso.PathOIDCDiscovery,
		sso.PathUserInfo,
		sso.PathEndSession,
	} {
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
	if resp.Header.Get(composition.HeaderCacheControl) != composition.ValueNoStore {
		t.Fatalf("cache control = %q, want no-store", resp.Header.Get(composition.HeaderCacheControl))
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
	knownEnvelope, unknownEnvelope := map[string]any{}, map[string]any{}
	if json.Unmarshal(knownBody, &knownEnvelope) != nil ||
		json.Unmarshal(unknownBody, &unknownEnvelope) != nil {
		t.Fatalf("decode credential failures: known=%s unknown=%s", knownBody, unknownBody)
	}
	// The prototype edition wires no tracing middleware, so the failure
	// envelopes must be byte-identical without any trace_id decoration.
	if !maps.Equal(knownEnvelope, unknownEnvelope) {
		t.Fatalf("credential bodies differ:\nknown: %s\nunknown: %s", knownBody, unknownBody)
	}
}

// TestOPSessionResumesAcrossRPsWithoutOIDC is the prototype-flavored
// canonical-lifecycle regression: the OP session created at password login
// flows as session_id in the code response, resumes for a second RP without
// credentials, and dies on logout. There is no id_token in the prototype
// edition, so the sid-claim assertions stay in cmd/sso-minimal.
func TestOPSessionResumesAcrossRPsWithoutOIDC(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "http://issuer.example"
	rpB := cfg.Second
	server, client, _ := prototypeServerWithSessions(t, cfg)

	status, body := postJSONWithClient(t, client, server.URL+"/auth/login",
		loginPayloadForClient(cfg, cfg.Client))
	if status != http.StatusOK || body["code"] == nil {
		t.Fatalf("login = %d %v, want code", status, body)
	}
	sessionID, _ := body["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("login response has no session_id: %v", body)
	}
	exchangeForClient(t, client, server.URL, cfg.Client, body["code"].(string))

	// Resume for RP-B without credentials: same canonical session. The code
	// response of the resumed login must carry the SAME canonical session_id
	// (the prototype edition has no id_token, so the sid-claim assertions
	// stay in cmd/sso-minimal).
	payload := loginPayloadForClient(cfg, rpB)
	delete(payload, "provider")
	delete(payload, "credential")
	status, resumed := postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if status != http.StatusOK || resumed["code"] == nil {
		t.Fatalf("RP-B resume = %d %v, want authorization code", status, resumed)
	}
	resumedSession, _ := resumed["session_id"].(string)
	if resumedSession != sessionID {
		t.Fatalf("resumed session_id = %q, want %q", resumedSession, sessionID)
	}

	// Logout destroys the canonical session; a stale cookie cannot resume.
	_, body = postJSONWithClient(t, client, server.URL+"/logout", map[string]any{
		"session_id": sessionID,
	})
	if body["status"] != "logged_out" {
		t.Fatalf("logout = %v, want logged_out", body)
	}
	payload = loginPayloadForClient(cfg, rpB)
	delete(payload, "provider")
	delete(payload, "credential")
	payload["prompt"] = "none"
	_, body = postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if body["code"] != nil {
		t.Fatalf("prompt=none resumed after logout: %v", body)
	}
}

func TestOPSessionHonorsPromptLogin(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "http://issuer.example"
	rpB := composition.ClientSeed{
		ID: "rp-b", Secret: "rp-b-secret",
		RedirectURI: "http://127.0.0.1:3001/callback",
		Scopes:      []string{"profile"},
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

func testServer(t *testing.T) (*httptest.Server, composition.RuntimeConfig) {
	t.Helper()
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
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
	cfg composition.RuntimeConfig,
	rpB composition.ClientSeed,
) (*httptest.Server, *http.Client) {
	t.Helper()
	app, err := buildHandlerWithClients(cfg, []composition.ClientSeed{rpB})
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return serverWithCookieJar(t, app)
}

func prototypeServerWithSessions(
	t *testing.T,
	cfg composition.RuntimeConfig,
) (*httptest.Server, *http.Client, *composition.OpSessionGate) {
	t.Helper()
	sessions := composition.NewOPSessionGate()
	app, err := buildHandlerWithSessions(cfg, []composition.ClientSeed{cfg.Second}, sessions)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server, client := serverWithCookieJar(t, app)
	return server, client, sessions
}

func buildHandlerWithClients(
	cfg composition.RuntimeConfig,
	extraClients []composition.ClientSeed,
) (http.Handler, error) {
	return buildHandlerWithSessions(cfg, extraClients, composition.NewOPSessionGate())
}

func buildHandlerWithSessions(
	cfg composition.RuntimeConfig,
	extraClients []composition.ClientSeed,
	sessions *composition.OpSessionGate,
) (http.Handler, error) {
	return composition.BuildHandler(cfg, composition.BuildOptions{
		ExtraClients: extraClients,
		SessionGate:  sessions,
		ExtraOptions: prototypeExtraOptions,
		Surface: composition.SurfaceHooks{
			IsMetadata: prototypeMetadataPath,
			Allowed:    prototypeRouteAllowed,
			Narrow:     prototypeNarrowMetadata,
		},
	})
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

func loginForCode(t *testing.T, base string, cfg composition.RuntimeConfig, verifier string) string {
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
	cfg composition.RuntimeConfig,
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
	cfg composition.RuntimeConfig,
	client composition.ClientSeed,
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
	client composition.ClientSeed,
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

func loginPayloadForClient(cfg composition.RuntimeConfig, client composition.ClientSeed) map[string]any {
	payload := loginPayload(cfg, pkceChallenge(testVerifier), "S256")
	payload["client_id"] = client.ID
	payload["redirect_uri"] = client.RedirectURI
	payload["scope"] = client.Scopes
	return payload
}

func loginPayload(cfg composition.RuntimeConfig, challenge, method string) map[string]any {
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
