package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// RFC 9396 Rich Authorization Requests:
// - authorization_details accepted on /auth/login (direct mint + code flow)
// - per-client type allowlist enforced (invalid_authorization_details on miss)
// - empty allowlist = parameter accepted but unconstrained
// - stamped into access token JWT verbatim (extension fields preserved)
// - persists across code-flow exchange (login → code → /token → token has it)
// - discovery advertises union of client allowlists

const (
	rarClient   = "rar-client"
	rarSecret   = "rar-secret"
	rarRedirect = "https://app.example.com/cb"
	rarUser     = "u-rar"
	rarPassword = "pw"
)

func newRARServer(t *testing.T, allowedTypes []string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rarUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                               rarClient,
		Secret:                           rarSecret,
		Name:                             "RAR Test",
		RedirectURIs:                     []string{rarRedirect},
		AllowedAuthenticators:            []string{"password"},
		TokenStrategy:                    "jwt",
		Active:                           true,
		AllowedAuthorizationDetailsTypes: allowedTypes,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rarUser && p == rarPassword {
				return &sso.AuthResult{UserID: rarUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// rarLogin drives /auth/login with the given authorization_details
// (raw JSON) and returns (status, body).
func rarLogin(t *testing.T, srv *httptest.Server, authzDetails string, codeFlow bool) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"provider":   "password",
		"client_id":  rarClient,
		"credential": map[string]string{"username": rarUser, "password": rarPassword},
	}
	if authzDetails != "" {
		body["authorization_details"] = json.RawMessage(authzDetails)
	}
	if codeFlow {
		body["response_type"] = "code"
		body["redirect_uri"] = rarRedirect
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	rbody, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(rbody, &out)
	return resp.StatusCode, out
}

// decodeAccessTokenPayload returns the JWT payload as a JSON map.
// Used to assert the authorization_details claim shape.
func decodeAccessTokenPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	return out
}

func TestRAR_DirectMintStampsClaim(t *testing.T) {
	srv := newRARServer(t, nil)
	const details = `[{"type":"payment_initiation","amount":"100","currency":"EUR"}]`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token in response: %v", body)
	}
	payload := decodeAccessTokenPayload(t, tok)
	ad, ok := payload["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details missing or wrong type in JWT: %v", payload)
	}
	if len(ad) != 1 {
		t.Fatalf("expected 1 element, got %d: %v", len(ad), ad)
	}
	elem, _ := ad[0].(map[string]any)
	if elem["type"] != "payment_initiation" {
		t.Errorf("type = %v want payment_initiation", elem["type"])
	}
	// Extension fields MUST pass through unmodified.
	if elem["amount"] != "100" {
		t.Errorf("amount = %v want \"100\"", elem["amount"])
	}
	if elem["currency"] != "EUR" {
		t.Errorf("currency = %v want \"EUR\"", elem["currency"])
	}
}

func TestRAR_TypeAllowlistEnforced(t *testing.T) {
	srv := newRARServer(t, []string{"payment_initiation", "account_information"})
	const details = `[{"type":"forbidden_type","action":"steal"}]`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_authorization_details" {
		t.Errorf("error = %v want invalid_authorization_details", body["error"])
	}
}

func TestRAR_TypeAllowlistAllowsRegisteredTypes(t *testing.T) {
	srv := newRARServer(t, []string{"payment_initiation"})
	const details = `[{"type":"payment_initiation","amount":"50"}]`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	tok, _ := body["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	if _, ok := payload["authorization_details"]; !ok {
		t.Errorf("authorization_details missing on allowlist-passing token")
	}
}

func TestRAR_EmptyAllowlistAcceptsAnyType(t *testing.T) {
	srv := newRARServer(t, nil)
	// Two elements with different types: legacy clients with no
	// type allowlist see both pass through unchanged.
	const details = `[
		{"type":"payment_initiation","amount":"100"},
		{"type":"custom_extension","whatever":true}
	]`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	tok, _ := body["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	ad, _ := payload["authorization_details"].([]any)
	if len(ad) != 2 {
		t.Errorf("expected 2 elements, got %d", len(ad))
	}
}

func TestRAR_RejectsMissingType(t *testing.T) {
	srv := newRARServer(t, nil)
	// `type` is REQUIRED on every element per RFC 9396 §2.
	const details = `[{"amount":"100"}]`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_authorization_details" {
		t.Errorf("error = %v want invalid_authorization_details", body["error"])
	}
}

func TestRAR_RejectsNonArray(t *testing.T) {
	srv := newRARServer(t, nil)
	// authorization_details MUST be a JSON array per RFC 9396 §2.
	const details = `{"type":"payment_initiation"}`
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
}

func TestRAR_NoParamPreservesLegacyBehavior(t *testing.T) {
	srv := newRARServer(t, nil)
	// Login WITHOUT authorization_details — token must not carry
	// the claim at all (empty omitempty path on the JWT issuer).
	status, body := rarLogin(t, srv, "", false)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	tok, _ := body["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	if _, ok := payload["authorization_details"]; ok {
		t.Errorf("authorization_details unexpectedly present on legacy token: %v", payload["authorization_details"])
	}
}

func TestRAR_CodeFlowPersistsToken(t *testing.T) {
	// Drive the full code flow: /auth/login response_type=code →
	// /token grant=authorization_code → assert the exchanged
	// access token carries authorization_details preserved from
	// the original /auth/login.
	srv := newRARServer(t, nil)
	const details = `[{"type":"document_access","document_id":"doc-42","actions":["read","comment"]}]`

	status, body := rarLogin(t, srv, details, true)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no code in response: %v", body)
	}

	// Exchange.
	exchangeBody, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     rarClient,
		"client_secret": rarSecret,
		"redirect_uri":  rarRedirect,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(exchangeBody))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", resp.StatusCode, raw)
	}
	var ex map[string]any
	_ = json.Unmarshal(raw, &ex)
	tok, _ := ex["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token after exchange: %s", raw)
	}
	payload := decodeAccessTokenPayload(t, tok)
	ad, ok := payload["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details missing after code-flow exchange: %v", payload)
	}
	elem, _ := ad[0].(map[string]any)
	if elem["type"] != "document_access" {
		t.Errorf("type = %v want document_access", elem["type"])
	}
	if elem["document_id"] != "doc-42" {
		t.Errorf("document_id = %v want doc-42", elem["document_id"])
	}
	actions, _ := elem["actions"].([]any)
	if len(actions) != 2 || actions[0] != "read" || actions[1] != "comment" {
		t.Errorf("actions = %v want [read comment]", actions)
	}
}

func TestRAR_DiscoveryAdvertisesUnion(t *testing.T) {
	// Two clients with different declared types: the discovery
	// doc surfaces the SORTED UNION of both lists. Clients
	// without any declared types contribute nothing.
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "c1", Active: true,
		AllowedAuthorizationDetailsTypes: []string{"payment_initiation", "account_information"},
	})
	clients.AddSeed(&sso.Client{
		ID: "c2", Active: true,
		AllowedAuthorizationDetailsTypes: []string{"document_access"},
	})
	clients.AddSeed(&sso.Client{
		ID: "c3", Active: true,
		// no AllowedAuthorizationDetailsTypes — contributes nothing
	})
	_ = users
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	doc := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &doc)

	got, ok := doc["authorization_details_types_supported"].([]any)
	if !ok {
		t.Fatalf("authorization_details_types_supported missing: %s", raw)
	}
	want := []string{"account_information", "document_access", "payment_initiation"}
	if len(got) != len(want) {
		t.Fatalf("count = %d want %d, got %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] = %v want %q (sorted union)", i, got[i], w)
		}
	}
}

func TestRAR_DiscoveryOmittedWhenNoClientDeclaresTypes(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	if _, present := doc["authorization_details_types_supported"]; present {
		t.Errorf("authorization_details_types_supported should be omitted when no client declares it; got %v",
			doc["authorization_details_types_supported"])
	}
}

// newRARServerWithRefresh wires the same harness as newRARServer
// but adds a refresh-token store so the rotation path is exercisable.
func newRARServerWithRefresh(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rarUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rarClient, Secret: rarSecret, Active: true,
		Name:                  "RAR Refresh Test",
		RedirectURIs:          []string{rarRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rarUser && p == rarPassword {
				return &sso.AuthResult{UserID: rarUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	rt := defaultimpl.NewMemoryRefreshTokenStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(rt, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, rt
}

func TestRAR_SurvivesRefreshRotation(t *testing.T) {
	// Closes the documented gap from the RFC 9396 commit: a
	// refreshed access token MUST carry the same
	// authorization_details the user originally consented to. The
	// rotation grant doesn't accept authorization_details on the
	// wire (caller can only narrow it; expansion would let the
	// client fabricate consent) — instead the refresh token
	// captures the original grant and re-stamps it on every
	// rotation.
	srv, _ := newRARServerWithRefresh(t)
	const details = `[{"type":"payment_initiation","amount":"42.50","currency":"USD","payee":"acme-corp"}]`

	// Login with authorization_details + capture the refresh
	// token (login wires refresh issuance because we configured
	// WithRefreshTokenStore).
	status, body := rarLogin(t, srv, details, false)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token in login response: %v", body)
	}

	// Rotate.
	exchangeBody, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     rarClient,
		"client_secret": rarSecret,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(exchangeBody))
	if err != nil {
		t.Fatalf("refresh exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh exchange status=%d body=%s", resp.StatusCode, raw)
	}
	var ex map[string]any
	_ = json.Unmarshal(raw, &ex)

	// The rotated access token MUST carry the same
	// authorization_details as the original.
	tok, _ := ex["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token after rotation: %s", raw)
	}
	payload := decodeAccessTokenPayload(t, tok)
	ad, ok := payload["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details lost on rotation: %v", payload)
	}
	if len(ad) != 1 {
		t.Fatalf("expected 1 element after rotation, got %d: %v", len(ad), ad)
	}
	elem, _ := ad[0].(map[string]any)
	if elem["type"] != "payment_initiation" {
		t.Errorf("type = %v want payment_initiation", elem["type"])
	}
	if elem["amount"] != "42.50" {
		t.Errorf("amount lost on rotation: %v", elem["amount"])
	}
	if elem["payee"] != "acme-corp" {
		t.Errorf("extension field lost on rotation: %v", elem["payee"])
	}

	// Now rotate AGAIN — the binding should survive multi-hop chains,
	// not just the first rotation. This catches a bug where the
	// rotation handler reads from info but forgets to re-issue with
	// authorization_details, breaking the second hop.
	refresh2, _ := ex["refresh_token"].(string)
	if refresh2 == "" {
		t.Fatalf("no refresh_token after first rotation")
	}
	exchangeBody2, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh2,
		"client_id":     rarClient,
		"client_secret": rarSecret,
	})
	resp2, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(exchangeBody2))
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	raw2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second rotation status=%d body=%s", resp2.StatusCode, raw2)
	}
	var ex2 map[string]any
	_ = json.Unmarshal(raw2, &ex2)
	tok2, _ := ex2["access_token"].(string)
	payload2 := decodeAccessTokenPayload(t, tok2)
	ad2, ok := payload2["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details lost on second rotation: %v", payload2)
	}
	elem2, _ := ad2[0].(map[string]any)
	if elem2["amount"] != "42.50" || elem2["payee"] != "acme-corp" {
		t.Errorf("binding mutated across multi-hop rotation: %v", elem2)
	}
}

func TestRAR_RefreshWithoutOriginalGrantStaysClean(t *testing.T) {
	// Inverse of the survival test: a login WITHOUT
	// authorization_details must produce a refresh chain whose
	// rotated tokens ALSO lack the claim. Catches a regression
	// where the rotation accidentally fabricates a synthetic
	// empty array (which would change the wire shape and confuse
	// resource servers branching on presence).
	srv, _ := newRARServerWithRefresh(t)

	status, body := rarLogin(t, srv, "", false)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token in login response: %v", body)
	}

	exchangeBody, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     rarClient,
		"client_secret": rarSecret,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(exchangeBody))
	if err != nil {
		t.Fatalf("refresh exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh exchange status=%d body=%s", resp.StatusCode, raw)
	}
	var ex map[string]any
	_ = json.Unmarshal(raw, &ex)
	tok, _ := ex["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	if _, present := payload["authorization_details"]; present {
		t.Errorf("rotated token unexpectedly carries authorization_details: %v",
			payload["authorization_details"])
	}
}
