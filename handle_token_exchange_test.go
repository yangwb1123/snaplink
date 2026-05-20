package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	txClientID = "tx-client"
	txSecret   = "tx-secret"
	txUserID   = "u-tx"
	txAPI      = "https://api.example/v1"
	txBilling  = "https://billing.example/v1"
)

func newTokenExchangeHarness(t *testing.T, allowedResources []string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: txUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: txClientID, Secret: txSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedResources:      allowedResources,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: txUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func txLogin(t *testing.T, srv *httptest.Server, scope []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  txClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      scope,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", raw)
	}
	return access
}

func postExchange(t *testing.T, srv *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestTokenExchange_HappyPath(t *testing.T) {
	srv := newTokenExchangeHarness(t, []string{txAPI})
	subject := txLogin(t, srv, []string{"read", "write"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Errorf("missing access_token: %v", body)
	}
	if body["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %v", body["issued_token_type"])
	}
	// New token's aud should be the exchanged-for resource.
	if aud := jwtPayloadField(t, body["access_token"].(string), "aud"); aud != txAPI {
		t.Errorf("aud = %v want %q", aud, txAPI)
	}
}

func TestTokenExchange_ScopeNarrowing(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	subject := txLogin(t, srv, []string{"read", "write", "admin"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"read"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if got := body["scope"]; got != "read" {
		t.Errorf("scope = %v want 'read'", got)
	}
}

func TestTokenExchange_ScopeExpansionRejected(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	subject := txLogin(t, srv, []string{"read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"read write admin"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (expansion forbidden)", status)
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %v want invalid_scope", body["error"])
	}
}

func TestTokenExchange_ResourceAllowlistEnforced(t *testing.T) {
	srv := newTokenExchangeHarness(t, []string{txAPI})
	subject := txLogin(t, srv, nil)

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"https://forbidden.example/x"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", status)
	}
	if body["error"] != "invalid_target" {
		t.Errorf("error = %v want invalid_target", body["error"])
	}
}

func TestTokenExchange_BadSubjectTokenRejected(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {"not-a-real-jwt"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant", body["error"])
	}
}

func TestTokenExchange_MissingSubjectTokenIsInvalidRequest(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusBadRequest {
		t.Errorf("status=%d want 400", status)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
}

func TestTokenExchange_UnsupportedRequestedTokenTypeRejected(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	subject := txLogin(t, srv, nil)
	status, body := postExchange(t, srv, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {txClientID},
		"client_secret":        {txSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
	})
	if status != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (refresh output unsupported in v1)", status)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
}

func TestTokenExchange_MergesResourceAndAudience(t *testing.T) {
	srv := newTokenExchangeHarness(t, []string{txAPI, txBilling})
	subject := txLogin(t, srv, nil)

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
		"audience":           {txBilling},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	access, _ := body["access_token"].(string)
	aud := jwtPayloadField(t, access, "aud")
	asArr, ok := aud.([]any)
	if !ok {
		t.Fatalf("aud not array: %v", aud)
	}
	if len(asArr) != 2 || asArr[0] != txAPI || asArr[1] != txBilling {
		t.Errorf("merged aud = %v want [%q %q]", asArr, txAPI, txBilling)
	}
}

func TestTokenExchange_ActorTokenStampsActClaim(t *testing.T) {
	// RFC 8693 §4.1 delegation: when actor_token is supplied,
	// the new access token carries `act: {sub: <actor.sub>}` so
	// downstream services can audit who acted on behalf of whom.
	srv := newTokenExchangeHarness(t, []string{txAPI})
	// Subject token = the end user.
	subject := txLogin(t, srv, []string{"read"})
	// Actor token = same user is fine for the test — what we
	// care about is that the actor_token's subject lands in act.
	// In a real scenario the actor is a different identity
	// (e.g. a service account); the wire shape is identical.
	actor := txLogin(t, srv, []string{"read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {actor},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	newTok, _ := body["access_token"].(string)
	if newTok == "" {
		t.Fatalf("no access_token in response: %v", body)
	}
	parts := strings.Split(newTok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", newTok)
	}
	rawPayload, err := decodeRawURL(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var p map[string]any
	_ = json.Unmarshal(rawPayload, &p)
	act, ok := p["act"].(map[string]any)
	if !ok {
		t.Fatalf("act claim missing on delegated token: %v", p)
	}
	if act["sub"] != txUserID {
		t.Errorf("act.sub = %v want %q", act["sub"], txUserID)
	}
}

func TestTokenExchange_NoActorTokenNoActClaim(t *testing.T) {
	// Direct (non-delegated) exchange: `act` claim MUST be
	// absent so legacy tokens stay byte-identical and downstream
	// services can use `act` presence as the delegation signal.
	srv := newTokenExchangeHarness(t, []string{txAPI})
	subject := txLogin(t, srv, []string{"read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
		// no actor_token / actor_token_type
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	newTok, _ := body["access_token"].(string)
	parts := strings.Split(newTok, ".")
	rawPayload, _ := decodeRawURL(parts[1])
	var p map[string]any
	_ = json.Unmarshal(rawPayload, &p)
	if _, present := p["act"]; present {
		t.Errorf("act claim must be absent on non-delegated exchange: %v", p["act"])
	}
}

func TestTokenExchange_ActorTokenWithoutTypeRejected(t *testing.T) {
	// RFC 8693 §2.1: actor_token MUST be paired with
	// actor_token_type. One without the other is invalid_request.
	srv := newTokenExchangeHarness(t, []string{txAPI})
	subject := txLogin(t, srv, []string{"read"})
	actor := txLogin(t, srv, []string{"read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {actor},
		// no actor_token_type
		"resource": {txAPI},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v want invalid_request", body["error"])
	}
}

func TestTokenExchange_BadActorTokenRejectedAsInvalidGrant(t *testing.T) {
	srv := newTokenExchangeHarness(t, []string{txAPI})
	subject := txLogin(t, srv, []string{"read"})

	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {"not-a-valid-jwt"},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant (actor token validation failure)", body["error"])
	}
}

// decodeRawURL is the test-side base64url decoder for JWT segments.
func decodeRawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func TestTokenExchange_DiscoveryAdvertisesGrant(t *testing.T) {
	srv := newTokenExchangeHarness(t, nil)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	grants, _ := out["grant_types_supported"].([]any)
	found := false
	for _, g := range grants {
		if g == "urn:ietf:params:oauth:grant-type:token-exchange" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("token-exchange grant not advertised in discovery: %v", grants)
	}
}
