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
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// newConsentAuditHarness wires a consent-enforced server with an in-memory
// audit sink so the user-initiated consent-lifecycle events (granted / revoked
// / denied) can be asserted. Returns the server, the consent store (to pre-seed
// grants), and the sink.
func newConsentAuditHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryConsentStore, *audit.MemorySink) {
	t.Helper()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-ca"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "ca-app",
		Secret:                "s",
		Active:                true,
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != "pw" {
				return nil, errors.New("bad credentials")
			}
			return &sso.AuthResult{UserID: "u-ca", Provider: "password"}, nil
		},
	))

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("consent-audit-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	cs := defaultimpl.NewMemoryConsentStore()
	sink := audit.NewMemorySink(50)

	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithConsentStore(cs),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	hs := httptest.NewServer(server.Handler())
	t.Cleanup(hs.Close)
	return hs, cs, sink
}

// caLogin posts to /auth/login as u-ca with the given scopes and optional
// consent challenge id. Returns status + decoded JSON body.
func caLogin(t *testing.T, srv *httptest.Server, scopes []string, challengeID string) (int, map[string]any) {
	t.Helper()
	req := map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  "ca-app",
		"credential": map[string]string{"username": "u-ca", "password": "pw"},
	}
	if len(scopes) > 0 {
		req["scope"] = scopes
	}
	if challengeID != "" {
		req[sso.KeyConsentChallengeID] = challengeID
	}
	raw, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func caEvents(t *testing.T, sink *audit.MemorySink, typ audit.EventType) []*audit.Event {
	t.Helper()
	evs, err := sink.Query(context.Background(), audit.Query{Type: typ})
	if err != nil {
		t.Fatalf("query %s: %v", typ, err)
	}
	return evs
}

// TestConsentAudit_GrantedEmittedOnChallengeApproval verifies a consent_granted
// event fires only when the user actively approves via a valid challenge — not
// on the first-time prompt itself.
func TestConsentAudit_GrantedEmittedOnChallengeApproval(t *testing.T) {
	srv, _, sink := newConsentAuditHarness(t)
	scopes := []string{"openid", "profile"}

	// Step 1: first login -> consent_required + challenge. No grant recorded yet.
	_, body1 := caLogin(t, srv, scopes, "")
	challengeID, _ := body1[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Fatalf("step 1: missing challenge id, body=%v", body1)
	}
	if got := caEvents(t, sink, audit.EventConsentGranted); len(got) != 0 {
		t.Fatalf("no consent_granted expected on first prompt, got %d", len(got))
	}

	// Step 2: approve via the challenge -> token + consent_granted.
	status2, body2 := caLogin(t, srv, scopes, challengeID)
	if status2 != http.StatusOK {
		t.Fatalf("step 2: status=%d body=%v", status2, body2)
	}
	granted := caEvents(t, sink, audit.EventConsentGranted)
	if len(granted) != 1 {
		t.Fatalf("want 1 consent_granted, got %d", len(granted))
	}
	g := granted[0]
	if g.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome=%q want success", g.Outcome)
	}
	if g.ActorID != "u-ca" {
		t.Errorf("actor=%q want u-ca", g.ActorID)
	}
	if g.Metadata[sso.KeyClientID] != "ca-app" {
		t.Errorf("client_id meta=%q want ca-app", g.Metadata[sso.KeyClientID])
	}
	if g.Metadata["scopes"] != "openid profile" {
		t.Errorf("scopes meta=%q want 'openid profile'", g.Metadata["scopes"])
	}
}

// TestConsentAudit_DeniedOnInvalidChallenge verifies a consent_denied event
// fires when a fabricated/invalid challenge is presented, but NOT on a
// first-time prompt (empty challenge), which is not a denial.
func TestConsentAudit_DeniedOnInvalidChallenge(t *testing.T) {
	srv, _, sink := newConsentAuditHarness(t)

	// Fabricated challenge on a login that needs consent -> consent_denied.
	_, body := caLogin(t, srv, []string{"openid"}, "fabricated-challenge")
	if body["error"] != sso.ErrConsentRequired {
		t.Fatalf("want consent_required, got %v", body)
	}
	denied := caEvents(t, sink, audit.EventConsentDenied)
	if len(denied) != 1 {
		t.Fatalf("want 1 consent_denied, got %d", len(denied))
	}
	if denied[0].Outcome != audit.OutcomeFailure {
		t.Errorf("outcome=%q want failure", denied[0].Outcome)
	}
	if denied[0].ActorID != "u-ca" {
		t.Errorf("actor=%q want u-ca", denied[0].ActorID)
	}

	// A first-time prompt (no challenge presented) must NOT record a denial.
	_, _ = caLogin(t, srv, []string{"email"}, "")
	if got := caEvents(t, sink, audit.EventConsentDenied); len(got) != 1 {
		t.Errorf("first-time prompt must not emit consent_denied; total=%d", len(got))
	}
}

// TestConsentAudit_RevokedOnSelfService verifies that the self-service revoke
// path (DELETE /consents/me/:client_id) emits a consent_revoked event keyed on
// the subject — the parallel to admin_consent_revoked.
func TestConsentAudit_RevokedOnSelfService(t *testing.T) {
	srv, cs, sink := newConsentAuditHarness(t)

	// Pre-seed a grant for the login client so the gate passes silently (no
	// challenge, no granted event) and a token is minted.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{UserID: "u-ca", ClientID: "ca-app", Scopes: []string{"openid"}, GrantedAt: time.Now()})
	status, body := caLogin(t, srv, []string{"openid"}, "")
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token, body=%v", body)
	}

	// Seed a grant for a different client, then self-service revoke it.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{UserID: "u-ca", ClientID: "target-app", GrantedAt: time.Now()})
	code, _ := doReq(t, srv, http.MethodDelete, "/consents/me/target-app", tok)
	if code != http.StatusNoContent {
		t.Fatalf("DELETE /consents/me/target-app status=%d want 204", code)
	}
	revoked := caEvents(t, sink, audit.EventConsentRevoked)
	if len(revoked) != 1 {
		t.Fatalf("want 1 consent_revoked, got %d", len(revoked))
	}
	if revoked[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome=%q want success", revoked[0].Outcome)
	}
	if revoked[0].ActorID != "u-ca" {
		t.Errorf("actor=%q want u-ca", revoked[0].ActorID)
	}
	if revoked[0].Metadata[sso.KeyClientID] != "target-app" {
		t.Errorf("client_id meta=%q want target-app", revoked[0].Metadata[sso.KeyClientID])
	}
}

// TestConsent_RequiredResponseEnrichment verifies the consent_required response
// carries the client display name and per-scope descriptions for the UI.
func TestConsent_RequiredResponseEnrichment(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-ca"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "ca-app", Secret: "s", Name: "Acme Console", Active: true,
		AllowedScopes:         []string{"openid", "billing:read"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != "pw" {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: "u-ca"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithConsentStore(defaultimpl.NewMemoryConsentStore()),
		sso.WithScopeDescriptions(map[string]string{"billing:read": "View your billing history"}),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	body, _ := json.Marshal(map[string]any{
		"provider": authenticators.MethodPassword, "client_id": "ca-app",
		"credential": map[string]string{"username": "u-ca", "password": "pw"},
		"scope":      []string{"openid", "billing:read"},
	})
	resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	rb, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(rb, &out)

	if out["error"] != sso.ErrConsentRequired {
		t.Fatalf("want consent_required, got %v", out)
	}
	if out["client_name"] != "Acme Console" {
		t.Errorf("client_name = %v, want Acme Console", out["client_name"])
	}
	scopes, ok := out["scopes"].([]any)
	if !ok || len(scopes) != 2 {
		t.Fatalf("scopes = %v, want 2 entries", out["scopes"])
	}
	// billing:read carries the operator description; openid has none (UI falls back).
	var foundBilling bool
	for _, s := range scopes {
		m, _ := s.(map[string]any)
		if m["scope"] == "billing:read" && m["description"] == "View your billing history" {
			foundBilling = true
		}
	}
	if !foundBilling {
		t.Errorf("billing:read description missing from %v", scopes)
	}
}
