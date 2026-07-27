package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	ibsUser   = "u-ibs"
	ibsClient = "ibs-client"
	ibsSecret = "ibs-secret"
)

// newIntrospectBatchSignedHarness builds a server with a real Ed25519 issuer
// (used for both token issuance and, when signIntrospection is true, as the
// introspection signer — the "reuse the existing signing-key infrastructure"
// contract) and the given batch max size (0 = batch capability disabled).
func newIntrospectBatchSignedHarness(t *testing.T, signIntrospection bool, batchMaxSize int) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: ibsUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: ibsClient, Secret: ibsSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: ibsUser}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if signIntrospection {
		opts = append(opts, sso.WithIntrospectionSigner(issuer))
	}
	if batchMaxSize > 0 {
		opts = append(opts, sso.WithIntrospectionBatch(batchMaxSize))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func ibsLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  ibsClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"read"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %v", out)
	}
	return tok
}

// ---------- batch introspection ----------

// TestIntrospectBatch_ReturnsResultsInOrder proves a batch request resolves
// every listed token (mixing an active token with an unknown/garbage one)
// and returns them as one array, in request order.
func TestIntrospectBatch_ReturnsResultsInOrder(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, false, 10)
	active := ibsLogin(t, srv)

	reqBody, _ := json.Marshal(map[string]any{
		"tokens":        []string{active, "not-a-real-token"},
		"client_id":     ibsClient,
		"client_secret": ibsSecret,
	})
	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("batch introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2: %v", len(out.Results), out.Results)
	}
	if out.Results[0]["active"] != true {
		t.Errorf("results[0].active=%v want true (the real token)", out.Results[0]["active"])
	}
	if out.Results[1]["active"] != false {
		t.Errorf("results[1].active=%v want false (the garbage token)", out.Results[1]["active"])
	}
}

// TestIntrospectBatch_OverCapRejected proves a batch larger than the
// configured cap is refused outright (invalid_request) rather than silently
// truncated.
func TestIntrospectBatch_OverCapRejected(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, false, 1)
	active := ibsLogin(t, srv)

	reqBody, _ := json.Marshal(map[string]any{
		"tokens":        []string{active, active},
		"client_id":     ibsClient,
		"client_secret": ibsSecret,
	})
	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("batch introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s (want 400 invalid_request)", resp.StatusCode, raw)
	}
}

// TestIntrospectBatch_DisabledByDefaultIgnoresTokensField proves an
// unconfigured server ignores an inbound `tokens` field entirely and falls
// through to the single-token behavior (empty `token` -> invalid_request),
// byte-identical to a build without this feature.
func TestIntrospectBatch_DisabledByDefaultIgnoresTokensField(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, false, 0)
	active := ibsLogin(t, srv)

	reqBody, _ := json.Marshal(map[string]any{
		"tokens":        []string{active},
		"client_id":     ibsClient,
		"client_secret": ibsSecret,
	})
	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s (want 400 invalid_request — tokens field ignored, token field empty)", resp.StatusCode, raw)
	}
}

// ---------- signed introspection response ----------
//
// decodeJWTPayload (splits a compact JWT and base64url-decodes+unmarshals
// the payload segment) already exists in oidc_test.go — reused here.

// TestIntrospectSigned_AcceptHeaderOptsIntoJWTResponse proves a wired signer
// + the RFC 9701 Accept opt-in together produce a JWT response nesting the
// RFC 7662 result under `token_introspection` (the substitution-attack
// defense) rather than at the top level.
func TestIntrospectSigned_AcceptHeaderOptsIntoJWTResponse(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, true, 0)
	active := ibsLogin(t, srv)

	form := strings.NewReader(`token=` + active + `&client_id=` + ibsClient + `&client_secret=` + ibsSecret)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/introspect", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/token-introspection+jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/token-introspection+jwt" {
		t.Errorf("Content-Type=%q want application/token-introspection+jwt", ct)
	}
	claims := decodeJWTPayload(t, string(raw))
	nested, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("no nested token_introspection claim in %v", claims)
	}
	if nested["active"] != true {
		t.Errorf("token_introspection.active=%v want true", nested["active"])
	}
	if claims["active"] != nil || claims["sub"] != nil {
		t.Errorf("top-level sub/active must be ABSENT (substitution defense): %v", claims)
	}
}

// TestIntrospectSigned_NoAcceptHeaderStaysPlainJSON proves a wired-but-
// unrequested signer is a no-op: without the Accept opt-in the response is
// still plain RFC 7662 JSON.
func TestIntrospectSigned_NoAcceptHeaderStaysPlainJSON(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, true, 0)
	active := ibsLogin(t, srv)

	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", jsonBody(t, map[string]any{
		"token": active, "client_id": ibsClient, "client_secret": ibsSecret,
	}))
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode plain JSON: %v", err)
	}
	if out["active"] != true {
		t.Errorf("active=%v want true (plain JSON body)", out["active"])
	}
}

// TestIntrospectSigned_UnwiredSignerStaysPlainJSON proves the Accept header
// alone (no signer wired) does not change the response — default-off.
func TestIntrospectSigned_UnwiredSignerStaysPlainJSON(t *testing.T) {
	srv := newIntrospectBatchSignedHarness(t, false, 0)
	active := ibsLogin(t, srv)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/introspect", jsonBody(t, map[string]any{
		"token": active, "client_id": ibsClient, "client_secret": ibsSecret,
	}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/token-introspection+jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "token-introspection") {
		t.Errorf("Content-Type=%q — signer unwired, must stay plain JSON", ct)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode plain JSON: %v", err)
	}
	if out["active"] != true {
		t.Errorf("active=%v want true", out["active"])
	}
}

func jsonBody(t *testing.T, v map[string]any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(b)
}
