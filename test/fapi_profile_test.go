package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	fapiClientID = "fapi-client"
	fapiUserID   = "u-fapi"
	fapiPassword = "pw"
)

var errPW = errors.New("bad password")

// fapiFixture builds a server in the given FAPI mode with an audit sink
// so tests can assert both the wire behavior and the
// fapi_compliance_violation events. The seeded client + plain-JSON
// login are intentionally NON-compliant (no PAR, no signed request, no
// S256 PKCE, non-code response_type) so every authorization-side rule
// fires.
func fapiFixture(t *testing.T, mode sso.FAPIMode) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: fapiUserID, Name: "Fapi"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: fapiClientID, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         sso.TokenStrategySession,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != fapiPassword {
				return nil, errPW
			}
			return &sso.AuthResult{UserID: fapiUserID, Provider: "password"}, nil
		},
	))
	sink := audit.NewMemorySink(50)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithDefaultTokenStrategy(sso.TokenStrategySession),
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithFAPIProfile(mode),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

func fapiPlainLogin(t *testing.T, srv *httptest.Server) (*http.Response, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  fapiClientID,
		"credential": map[string]string{"username": fapiUserID, "password": fapiPassword},
		"scope":      []string{"openid"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, rb
}

func fapiViolationRules(t *testing.T, sink *audit.MemorySink) map[string]bool {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	rules := map[string]bool{}
	for _, e := range events {
		if e.Type == audit.EventFAPIComplianceViolation {
			rules[e.Reason] = true
		}
	}
	return rules
}

// TestFAPI_Inspection_AuditsButProceeds is the ramp-up contract: a
// non-compliant request still succeeds (response unchanged) while every
// violated rule is recorded for the operator's compliance-gap list.
func TestFAPI_Inspection_AuditsButProceeds(t *testing.T) {
	srv, sink := fapiFixture(t, sso.FAPIModeInspection)
	resp, rb := fapiPlainLogin(t, srv)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspection mode must not block login, got %d: %s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["access_token"] == nil {
		t.Errorf("inspection login should still mint a token, got %s", rb)
	}
	rules := fapiViolationRules(t, sink)
	for _, want := range []string{"fapi:par_required", "fapi:signed_request", "fapi:no_implicit", "fapi:pkce_s256"} {
		if !rules[want] {
			t.Errorf("expected inspection violation %q in audit, got %v", want, rules)
		}
	}
}

// TestFAPI_Enforce_Rejects proves enforce mode rejects the
// non-compliant request with invalid_request (and still audits).
func TestFAPI_Enforce_Rejects(t *testing.T) {
	srv, sink := fapiFixture(t, sso.FAPIModeEnforce)
	resp, rb := fapiPlainLogin(t, srv)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enforce mode must reject, got %d: %s", resp.StatusCode, rb)
	}
	var out map[string]string
	_ = json.Unmarshal(rb, &out)
	if out["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", out["error"])
	}
	if out["access_token"] != "" {
		t.Error("enforce rejection must not mint a token")
	}
	if rules := fapiViolationRules(t, sink); len(rules) == 0 {
		t.Error("enforce rejection must still emit a fapi_compliance_violation audit event")
	}
}

// TestFAPI_Off_NoViolations confirms the zero-overhead default: no FAPI
// profile means no checks, no audit events, login unchanged.
func TestFAPI_Off_NoViolations(t *testing.T) {
	srv, sink := fapiFixture(t, sso.FAPIModeOff)
	resp, rb := fapiPlainLogin(t, srv)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FAPI off must not block login, got %d: %s", resp.StatusCode, rb)
	}
	if rules := fapiViolationRules(t, sink); len(rules) != 0 {
		t.Errorf("FAPI off must emit no violations, got %v", rules)
	}
}

// TestFAPI_Enforce_ClientAuthRejectsSharedSecret proves a token
// request authenticated with HTTP Basic (client_secret_basic) violates
// the FAPI client-auth rule under enforce mode: rejected with
// invalid_request and a fapi:client_auth audit event. FAPI 2.0
// prohibits shared-secret client authentication.
func TestFAPI_Enforce_ClientAuthRejectsSharedSecret(t *testing.T) {
	srv, sink := fapiFixture(t, sso.FAPIModeEnforce)
	form := "grant_type=client_credentials&scope=openid"
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", bytes.NewReader([]byte(form)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(fapiClientID, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enforce mode must reject shared-secret client auth, got %d: %s", resp.StatusCode, rb)
	}
	var out map[string]string
	_ = json.Unmarshal(rb, &out)
	if out["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", out["error"])
	}
	if rules := fapiViolationRules(t, sink); !rules["fapi:client_auth"] {
		t.Errorf("expected fapi:client_auth violation, got %v", rules)
	}
}

// TestFAPI_Enforce_DiscoveryReflectsConstraints checks the enforce-mode
// discovery doc advertises the hard requirements; inspection leaves it
// unchanged.
func TestFAPI_Enforce_DiscoveryReflectsConstraints(t *testing.T) {
	srv, _ := fapiFixture(t, sso.FAPIModeEnforce)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["require_pushed_authorization_requests"] != true {
		t.Errorf("enforce discovery must require PAR, got %v", doc["require_pushed_authorization_requests"])
	}
	if doc["require_signed_request_object"] != true {
		t.Errorf("enforce discovery must require signed request object, got %v", doc["require_signed_request_object"])
	}
	rt, _ := doc["response_types_supported"].([]any)
	if len(rt) != 1 || rt[0] != "code" {
		t.Errorf("enforce discovery response_types_supported = %v, want [code]", doc["response_types_supported"])
	}
	cm, _ := doc["code_challenge_methods_supported"].([]any)
	if len(cm) != 1 || cm[0] != "S256" {
		t.Errorf("enforce discovery code_challenge_methods_supported = %v, want [S256]", doc["code_challenge_methods_supported"])
	}
}
