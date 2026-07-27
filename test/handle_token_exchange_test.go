package ssotest

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

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
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

// TestTokenExchange_PropagatesSIDToAccessToken locks AGENTS.md §3 (RFC 9068
// Claims): token-exchange propagates AuthTime+ACR+AMR+SID from the inbound
// subject_token. The sibling refresh token (tokExIssueRefresh) and id_token
// (tokExMintIDToken) outputs already carried the inbound sid; the primary
// access token — always returned per RFC 8693 §2.2.1 — must carry the SAME
// sid so a resource server correlating tokens by session sees one consistent
// identifier across everything minted from this subject_token.
func TestTokenExchange_PropagatesSIDToAccessToken(t *testing.T) {
	srv := newTokenExchangeHarness(t, []string{txAPI})

	loginBody, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  txClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"read"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(loginBody)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var lo map[string]any
	_ = json.Unmarshal(raw, &lo)
	subject, _ := lo["access_token"].(string)
	if subject == "" {
		t.Fatalf("no subject token: %s", raw)
	}
	sessionID, _ := lo["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("no session_id in login response (precondition): %s", raw)
	}
	if sid, _ := decodeAccessTokenPayload(t, subject)["sid"].(string); sid != sessionID {
		t.Fatalf("precondition failed: subject token sid=%q want %q", sid, sessionID)
	}

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
	exchanged, _ := body["access_token"].(string)
	if exchanged == "" {
		t.Fatalf("no access_token in exchange response: %v", body)
	}
	if sid, _ := decodeAccessTokenPayload(t, exchanged)["sid"].(string); sid != sessionID {
		t.Errorf("exchanged access token sid = %q, want %q (propagated from subject_token)", sid, sessionID)
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

// TestTokenExchange_EmptyScopeDoesNotWidenToAllowlist guards RFC 8693 §2.1: the
// exchanged token MUST NOT exceed the subject. A genuinely scope-less subject
// token exchanged by a DIFFERENT client that has an allowlist must yield a
// scope-less token — it must NOT default to that client's full AllowedScopes
// (the GrantedScopes rule-4 default), which would escalate the scope-less
// subject to e.g. accounts:admin bound to the subject's identity.
//
// Two clients are required because logging in via the allowlisted client would
// itself default the subject token's scope to the allowlist at login time.
func TestTokenExchange_EmptyScopeDoesNotWidenToAllowlist(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: txUserID})
	clients := defaultimpl.NewMemoryClientStore()
	// subjClient has NO allowlist -> a no-scope login mints a scope-less token.
	clients.AddSeed(&sso.Client{
		ID: "tx-subj", Secret: "subj-secret", Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	// downClient HAS an allowlist and performs the exchange.
	clients.AddSeed(&sso.Client{
		ID: "tx-down", Secret: "down-secret", Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		AllowedScopes: []string{"payments:write", "accounts:admin"},
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

	// Scope-less subject token minted by the allowlist-free client.
	loginBody, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "tx-subj",
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", strings.NewReader(string(loginBody)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var lo map[string]any
	_ = json.Unmarshal(raw, &lo)
	subject, _ := lo["access_token"].(string)
	if subject == "" {
		t.Fatalf("no subject token: %s", raw)
	}
	if sc, _ := lo["scope"].(string); sc != "" {
		t.Fatalf("precondition: subject token must be scope-less, got scope=%q", sc)
	}

	status, body := postExchange(t, httpSrv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {"tx-down"},
		"client_secret":      {"down-secret"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		// NO scope param.
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if got, _ := body["scope"].(string); got != "" {
		t.Errorf("exchanged scope = %q, want empty (a scope-less subject must NOT widen to the client allowlist)", got)
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
	// SAML2 token output is unsupported (only access_token + refresh_token +
	// id_token are wired today).
	status, body := postExchange(t, srv, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {txClientID},
		"client_secret":        {txSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:saml2"},
	})
	if status != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (SAML2 output unsupported)", status)
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

// newTokenExchangeHarnessWithIssuer is a variant that exposes the
// signing issuer so multi-hop chain tests can mint actor tokens
// for arbitrary subjects without going through /auth/login (the
// password authenticator returns one fixed UserID per server).
func newTokenExchangeHarnessWithIssuer(t *testing.T, allowedResources []string) (*httptest.Server, *defaultimpl.Ed25519JWTIssuer) {
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
	return httpSrv, issuer
}

func TestTokenExchange_ActorChainNestsAcrossMultipleHops(t *testing.T) {
	// RFC 8693 §4.1.1: when the subject_token already carries an
	// `act` claim (it was itself the result of a prior exchange),
	// the new act prepends the current actor and nests the old
	// chain underneath. Outside-in reads the chain in time-order:
	// outermost = most recent actor, deepest = first to delegate.
	//
	//   end-user A (sub) delegates to service B → token has act={sub:B}
	//   B delegates to service C using that token → act={sub:C, act:{sub:B}}
	//
	// This is the load-bearing audit guarantee for multi-tier
	// delegation: a resource server in tier 3 can walk the chain
	// to see every party that touched the request.
	srv, issuer := newTokenExchangeHarnessWithIssuer(t, []string{txAPI})

	// Mint actor tokens for distinct service identities.
	tokenB, err := issuer.Issue(context.Background(), &sso.Subject{ID: "svc-b", ClientID: txClientID}, []string{"act"})
	if err != nil {
		t.Fatalf("mint actor B: %v", err)
	}
	tokenC, err := issuer.Issue(context.Background(), &sso.Subject{ID: "svc-c", ClientID: txClientID}, []string{"act"})
	if err != nil {
		t.Fatalf("mint actor C: %v", err)
	}

	// Subject token = end user A.
	subjectA := txLogin(t, srv, []string{"read"})

	// First hop: A → B. New token should carry act={sub:B} with no nesting.
	status, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subjectA},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {tokenB.AccessToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	if status != http.StatusOK {
		t.Fatalf("first hop status=%d body=%v", status, body)
	}
	hopOneToken, _ := body["access_token"].(string)
	if hopOneToken == "" {
		t.Fatalf("no token after first hop: %v", body)
	}

	// Second hop: A→B→C. subject_token is the hop-one token (already
	// has act={sub:B}); the new act must be {sub:C, act:{sub:B}}.
	status2, body2 := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {hopOneToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {tokenC.AccessToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	if status2 != http.StatusOK {
		t.Fatalf("second hop status=%d body=%v", status2, body2)
	}
	hopTwoToken, _ := body2["access_token"].(string)

	// Decode the final token; assert sub is still A (unchanged) and
	// act is the nested chain.
	parts := strings.Split(hopTwoToken, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", hopTwoToken)
	}
	rawPayload, _ := decodeRawURL(parts[1])
	var p map[string]any
	_ = json.Unmarshal(rawPayload, &p)

	if p["sub"] != txUserID {
		t.Errorf("sub mutated across delegation: got %v want %s (subject MUST be the end user A through every hop)", p["sub"], txUserID)
	}

	act, ok := p["act"].(map[string]any)
	if !ok {
		t.Fatalf("outer act missing on multi-hop token: %v", p)
	}
	if act["sub"] != "svc-c" {
		t.Errorf("outer act.sub = %v want svc-c (most-recent actor goes on top)", act["sub"])
	}
	nested, ok := act["act"].(map[string]any)
	if !ok {
		t.Fatalf("nested act missing — chain not preserved: %v", act)
	}
	if nested["sub"] != "svc-b" {
		t.Errorf("nested act.sub = %v want svc-b (earlier actor goes underneath)", nested["sub"])
	}
	if _, present := nested["act"]; present {
		t.Errorf("third-level nesting unexpectedly present (only 2 hops): %v", nested["act"])
	}
}

func TestTokenExchange_ActorChainSurvivesValidate(t *testing.T) {
	// Reflexive check: the chain that Issue stamps must round-trip
	// through Validate intact. Without this, downstream services
	// using TokenClaims.Actor see only the outermost layer and
	// lose audit history.
	srv, issuer := newTokenExchangeHarnessWithIssuer(t, []string{txAPI})

	tokenB, _ := issuer.Issue(context.Background(), &sso.Subject{ID: "svc-b", ClientID: txClientID}, []string{"act"})
	tokenC, _ := issuer.Issue(context.Background(), &sso.Subject{ID: "svc-c", ClientID: txClientID}, []string{"act"})

	subjectA := txLogin(t, srv, []string{"read"})

	// Two hops via the wire.
	_, body := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {subjectA},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {tokenB.AccessToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	hop1, _ := body["access_token"].(string)
	_, body2 := postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txClientID},
		"client_secret":      {txSecret},
		"subject_token":      {hop1},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {tokenC.AccessToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txAPI},
	})
	hop2, _ := body2["access_token"].(string)

	// Validate through the issuer (the public Validate API).
	claims, err := issuer.Validate(context.Background(), hop2)
	if err != nil {
		t.Fatalf("validate hop2: %v", err)
	}
	if claims.Actor == nil {
		t.Fatalf("Actor not populated on validated claims")
	}
	if claims.Actor.Subject != "svc-c" {
		t.Errorf("Actor.Subject = %q want svc-c", claims.Actor.Subject)
	}
	if claims.Actor.Actor == nil {
		t.Fatalf("nested Actor not populated — chain lost in Validate")
	}
	if claims.Actor.Actor.Subject != "svc-b" {
		t.Errorf("Actor.Actor.Subject = %q want svc-b", claims.Actor.Actor.Subject)
	}
	if claims.Actor.Actor.Actor != nil {
		t.Errorf("third-level Actor unexpectedly present: %v", claims.Actor.Actor.Actor)
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
	defer func() { _ = resp.Body.Close() }()
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

// TestTokenExchange_DPoPBoundSubject_NoProofRejected locks RFC 8693 §2.1 +
// RFC 9449 §5: exchanging a DPoP-bound subject_token without a DPoP proof MUST
// be rejected with invalid_grant. Issuing an unbound (bearer) token from a
// cnf-bound one would silently reduce the protection level.
func TestTokenExchange_DPoPBoundSubject_NoProofRejected(t *testing.T) {
	srv := newDPoPHarness(t)
	priv, x := dpopGenKey(t)

	// Obtain a DPoP-bound access token via client_credentials.
	proof := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token")
	_, ccBody := callTokenWithDPoP(t, srv, proof)
	subjectToken, _ := ccBody["access_token"].(string)
	if subjectToken == "" {
		t.Fatalf("no access_token from DPoP client_credentials: %v", ccBody)
	}

	// Exchange the DPoP-bound token WITHOUT presenting a DPoP proof — must fail.
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {dpopClient},
		"client_secret":      {dpopSecret},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no-proof exchange: status=%d want 400; body=%s", resp.StatusCode, raw)
	}
	var errBody map[string]any
	_ = json.Unmarshal(raw, &errBody)
	if errBody["error"] != "invalid_grant" {
		t.Errorf("no-proof exchange: error=%q want invalid_grant; body=%s", errBody["error"], raw)
	}
}

// TestTokenExchange_DPoPBoundSubject_WithProofSucceeds locks that a valid DPoP
// proof satisfies the RFC 9449 protection-level requirement and the exchange
// proceeds to issue a new access token.
func TestTokenExchange_DPoPBoundSubject_WithProofSucceeds(t *testing.T) {
	srv := newDPoPHarness(t)
	priv, x := dpopGenKey(t)

	// Obtain a DPoP-bound access token.
	proof1 := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token")
	_, ccBody := callTokenWithDPoP(t, srv, proof1)
	subjectToken, _ := ccBody["access_token"].(string)
	if subjectToken == "" {
		t.Fatalf("no access_token from DPoP client_credentials: %v", ccBody)
	}

	// Exchange it WITH a DPoP proof — must proceed (protection level preserved).
	proof2 := signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token")
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {dpopClient},
		"client_secret":      {dpopSecret},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof2)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with-proof exchange: status=%d want 200; body=%s", resp.StatusCode, raw)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if body["access_token"] == nil {
		t.Errorf("with-proof exchange: no access_token in response; body=%s", raw)
	}
}
