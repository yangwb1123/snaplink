package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/domains/tokenexchange/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	txcpSubjectUser = "u-txcp-subject"
	txcpActorAUser  = "u-txcp-actor-a"
	txcpActorBUser  = "u-txcp-actor-b"
	txcpClient      = "txcp-client"
	txcpSecret      = "txcp-secret"
	txcpAPI         = "https://api.txcp.example.com"
)

// txcpOpt lets each test add its own exchange-governance Option (chain
// lifetime cap / hop policy) on top of the shared harness, without a
// JTIReplayStore — the cycle test deliberately re-presents the SAME
// actor_token twice, which a wired replay store would ALSO reject,
// confounding the assertion that CYCLE detection (not replay detection)
// produced the denial.
func newTokenExchangeChainPolicyHarness(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	for _, u := range []string{txcpSubjectUser, txcpActorAUser, txcpActorBUser} {
		_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: u})
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: txcpClient, Secret: txcpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedResources:      []string{txcpAPI},
	})
	// The stub password verifier's "username" IS the subject to authenticate
	// as, so each helper below logs in as a distinct principal by passing a
	// different username.
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: username, Provider: "password"}, nil
		},
	))
	opts := append([]sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}, extra...)
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func txcpLoginAs(t *testing.T, srv *httptest.Server, username string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  txcpClient,
		"credential": map[string]string{"username": username, "password": "y"},
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
		t.Fatalf("no token: %v (status=%d)", out, resp.StatusCode)
	}
	return tok
}

func txcpExchange(t *testing.T, srv *httptest.Server, subject, actor string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txcpClient},
		"client_secret":      {txcpSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txcpAPI},
	}
	if actor != "" {
		form.Set("actor_token", actor)
		form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	body := map[string]any{}
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

// TestTokenExchange_ActorChainCycleRejected builds an A -> B -> A delegation
// chain and asserts the THIRD hop (re-introducing actor A, already present
// deeper in the chain from hop 1) is refused — the cycle-detection gate
// added alongside the existing MaxActChainDepth cap.
func TestTokenExchange_ActorChainCycleRejected(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t)
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)
	actorB := txcpLoginAs(t, srv, txcpActorBUser)

	// Hop 1: subject exchanged with actor A. act = {sub: A}.
	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusOK {
		t.Fatalf("hop1 status=%d body=%v", status, body)
	}
	hop1, _ := body["access_token"].(string)
	if hop1 == "" {
		t.Fatalf("hop1: no access_token in %v", body)
	}

	// Hop 2: hop1 exchanged with actor B. act = {sub: B, act: {sub: A}}.
	status, body = txcpExchange(t, srv, hop1, actorB)
	if status != http.StatusOK {
		t.Fatalf("hop2 status=%d body=%v", status, body)
	}
	hop2, _ := body["access_token"].(string)
	if hop2 == "" {
		t.Fatalf("hop2: no access_token in %v", body)
	}

	// Hop 3: hop2 exchanged with actor A AGAIN — A already appears deeper in
	// the chain (hop 1), so this is a cycle: A -> B -> A.
	status, body = txcpExchange(t, srv, hop2, actorA)
	if status != http.StatusBadRequest {
		t.Fatalf("cyclic hop3 status=%d body=%v (want 400 invalid_grant)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestTokenExchange_ActorChainNoCycleWhenDistinct proves a legitimate
// 2-distinct-actor chain (no repeat) is NOT flagged as cyclic — the cycle
// gate must not false-positive on ordinary multi-hop delegation.
func TestTokenExchange_ActorChainNoCycleWhenDistinct(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t)
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)
	actorB := txcpLoginAs(t, srv, txcpActorBUser)

	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusOK {
		t.Fatalf("hop1 status=%d body=%v", status, body)
	}
	hop1, _ := body["access_token"].(string)

	status, body = txcpExchange(t, srv, hop1, actorB)
	if status != http.StatusOK {
		t.Fatalf("hop2 status=%d body=%v (distinct actors must not cycle-fault)", status, body)
	}
}

// TestTokenExchange_MaxChainLifetimeDeniesStaleChain proves the OPTIONAL
// chain-lifetime cap fires once the subject_token's AuthTime (the original
// login moment, propagated unchanged) is older than the configured ceiling —
// independent of the access token's own (1-minute) TTL, which has not
// expired.
func TestTokenExchange_MaxChainLifetimeDeniesStaleChain(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t, sso.WithMaxTokenExchangeChainLifetime(5*time.Millisecond))
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	time.Sleep(25 * time.Millisecond)

	status, body := txcpExchange(t, srv, subjectTok, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v (want 400 invalid_grant — chain older than the 5ms cap)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestTokenExchange_MaxChainLifetimeDisabledByDefault proves the cap is a
// pure no-op when unconfigured, even after a delay that would trip a small
// configured cap.
func TestTokenExchange_MaxChainLifetimeDisabledByDefault(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t)
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	time.Sleep(25 * time.Millisecond)

	status, body := txcpExchange(t, srv, subjectTok, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — cap disabled by default)", status, body)
	}
}

// TestTokenExchange_PolicyDeniesSpecificHop wires a MemoryPolicy that denies
// exactly one (subject, actor) pairing and asserts: the denied pairing is
// rejected while a different actor for the SAME subject is still allowed —
// proving the SPI targets the specific hop, not the whole grant.
func TestTokenExchange_PolicyDeniesSpecificHop(t *testing.T) {
	policy := memory.New(true, tokenexchange.Rule{
		Name:         "block-actor-a-for-subject",
		SubjectID:    txcpSubjectUser,
		ActorSubject: txcpActorAUser,
		Deny:         true,
	})
	srv := newTokenExchangeChainPolicyHarness(t, sso.WithTokenExchangePolicy(policy))
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)
	actorB := txcpLoginAs(t, srv, txcpActorBUser)

	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusBadRequest {
		t.Fatalf("actorA status=%d body=%v (want 400 invalid_grant — denied by policy)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}

	status, body = txcpExchange(t, srv, subjectTok, actorB)
	if status != http.StatusOK {
		t.Fatalf("actorB status=%d body=%v (want 200 — this hop was not denied)", status, body)
	}
}

// TestTokenExchange_PolicyUnwiredByDefault proves nil Policy is a no-op.
func TestTokenExchange_PolicyUnwiredByDefault(t *testing.T) {
	srv := newTokenExchangeChainPolicyHarness(t)
	subjectTok := txcpLoginAs(t, srv, txcpSubjectUser)
	actorA := txcpLoginAs(t, srv, txcpActorAUser)

	status, body := txcpExchange(t, srv, subjectTok, actorA)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (want 200 — no policy wired)", status, body)
	}
}
