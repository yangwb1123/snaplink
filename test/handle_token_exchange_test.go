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
	// SAML2 token output is unsupported (only access_token + refresh_token
	// are wired today).
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
