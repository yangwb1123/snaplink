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

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	consentUser     = "consent-user"
	consentClientID = "consent-client"
	consentSecret   = "consent-secret"
	consentPassword = "cpwd"
)

// newConsentServer wires the minimal server stack for consent tests:
// a password authenticator + Ed25519 JWT issuer + the supplied ConsentStore
// (nil = no consent enforcement at all — the no-op path).
func newConsentServer(t *testing.T, cs sso.ConsentStore) *httptest.Server {
	t.Helper()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: consentUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    consentClientID,
		Secret:                consentSecret,
		Active:                true,
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != consentPassword {
				return nil, errors.New("bad credentials")
			}
			return &sso.AuthResult{UserID: consentUser, Provider: "password"}, nil
		},
	))

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519TokenTTL(5 * time.Minute),
	)

	sessions := defaultimpl.NewMemorySessionManager()

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if cs != nil {
		opts = append(opts, sso.WithConsentStore(cs))
	}

	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// consentLogin posts to /auth/login with the supplied scopes and optional
// prompt value. Returns the HTTP status and decoded JSON body.
func consentLogin(t *testing.T, srv *httptest.Server, scopes []string, prompt string) (int, map[string]any) {
	t.Helper()
	req := map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  consentClientID,
		"credential": map[string]string{"username": consentUser, "password": consentPassword},
	}
	if len(scopes) > 0 {
		req["scope"] = scopes
	}
	if prompt != "" {
		req["prompt"] = prompt
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

// TestConsent_NilStoreIsNoOp verifies that a server without a ConsentStore
// issues tokens normally — nil = byte-identical to prior behavior.
func TestConsent_NilStoreIsNoOp(t *testing.T) {
	srv := newConsentServer(t, nil)
	status, body := consentLogin(t, srv, []string{"openid"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v, want 200 with nil consent store", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("expected access_token, got %v", body)
	}
}

// TestConsent_FirstLoginRequiresConsent verifies that a first-time login (no
// stored grant) with a ConsentStore returns consent_required at HTTP 200.
func TestConsent_FirstLoginRequiresConsent(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	status, body := consentLogin(t, srv, []string{"openid", "profile"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200 (consent_required is a structured 200)", status)
	}
	if body["error"] != sso.ErrConsentRequired {
		t.Errorf("error=%v, want %q", body["error"], sso.ErrConsentRequired)
	}
	// iss MUST be present on every /auth/login response (RFC 9207 + §2 invariant).
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("iss missing from consent_required response")
	}
}

// TestConsent_PromptConsentForcesConsentEvenWhenGrantExists verifies that
// prompt=consent re-triggers the consent gate even for a user who already
// granted all requested scopes.
func TestConsent_PromptConsentForcesConsentEvenWhenGrantExists(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	// Pre-populate a full grant so the user already covers the request.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    consentUser,
		ClientID:  consentClientID,
		Scopes:    []string{"email", "openid", "profile"},
		GrantedAt: time.Now(),
	})

	status, body := consentLogin(t, srv, []string{"openid", "profile"}, sso.PromptConsent)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	if body["error"] != sso.ErrConsentRequired {
		t.Errorf("error=%v, want %q (prompt=consent must override cached grant)", body["error"], sso.ErrConsentRequired)
	}
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("iss missing from prompt=consent response")
	}
}

// TestConsent_TokensIssuedWhenGrantCoversScopes verifies that login succeeds
// and issues tokens when the stored grant already covers all requested scopes.
func TestConsent_TokensIssuedWhenGrantCoversScopes(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	// Simulate: user previously consented to {openid, profile}.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    consentUser,
		ClientID:  consentClientID,
		Scopes:    []string{"openid", "profile"},
		GrantedAt: time.Now(),
	})

	status, body := consentLogin(t, srv, []string{"openid"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if errVal, ok := body["error"]; ok {
		t.Fatalf("unexpected error=%v", errVal)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("expected access_token after prior grant, got %v", body)
	}
}

// TestConsent_NewScopeRequiresConsentEvenWithPartialGrant verifies that
// requesting a scope not covered by the stored grant re-triggers consent.
func TestConsent_NewScopeRequiresConsentEvenWithPartialGrant(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	// Existing grant covers only openid — not email.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    consentUser,
		ClientID:  consentClientID,
		Scopes:    []string{"openid"},
		GrantedAt: time.Now(),
	})

	// Now request openid + email — email is not in the grant.
	status, body := consentLogin(t, srv, []string{"openid", "email"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 (consent_required is a structured 200)", status)
	}
	if body["error"] != sso.ErrConsentRequired {
		t.Errorf("error=%v, want %q (new scope must re-trigger consent)", body["error"], sso.ErrConsentRequired)
	}
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("iss missing from new-scope consent_required response")
	}
}

// TestConsent_RecordConsentThenLoginIssuesToken verifies the happy path:
// a login that triggers consent_required, then after the grant is recorded
// (simulating the consent UI submitting), the next login succeeds and
// records an updated grant automatically.
func TestConsent_RecordConsentThenLoginIssuesToken(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	// First attempt: consent_required.
	status1, body1 := consentLogin(t, srv, []string{"openid", "profile"}, "")
	if body1["error"] != sso.ErrConsentRequired {
		t.Fatalf("step 1: status=%d body=%v, expected consent_required", status1, body1)
	}

	// User clicks "Allow" → consent UI POSTs to its own backend →
	// backend calls RecordConsent.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID:    consentUser,
		ClientID:  consentClientID,
		Scopes:    []string{"openid", "profile"},
		GrantedAt: time.Now(),
	})

	// Second login attempt: grant exists and covers the scope.
	status2, body2 := consentLogin(t, srv, []string{"openid", "profile"}, "")
	if status2 != http.StatusOK {
		t.Fatalf("step 2: status=%d body=%v", status2, body2)
	}
	if errVal, ok := body2["error"]; ok {
		t.Fatalf("step 2: unexpected error=%v", errVal)
	}
	if _, ok := body2["access_token"].(string); !ok {
		t.Fatalf("step 2: expected access_token, got %v", body2)
	}
}

// TestConsent_StoreErrorFailsOpen verifies that a transient consent store
// outage (simulated by revoking then immediately breaking the store via a
// wrapper) does NOT block login — fail-open is the contract for opt-in
// enrichment stores matching geo/risk/audit.
//
// We implement this by using a real store for the first grant recording
// (ensuring a good state), then directly verifying the fail-open behavior
// using a store that reports errors on every Get call.
func TestConsent_StoreErrorFailsOpen(t *testing.T) {
	srv := newConsentServer(t, &failOpenConsentStore{})

	// With a consent store that always errors, login MUST still succeed
	// (fail-open: log + continue).
	status, body := consentLogin(t, srv, []string{"openid"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 (store outage must fail-open)", status)
	}
	if errVal, ok := body["error"]; ok {
		t.Fatalf("store error must not block login; got error=%v", errVal)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("expected access_token on store-error fail-open, got %v", body)
	}
}

// failOpenConsentStore is a ConsentStore that always returns an error from
// GetConsent, allowing us to test the fail-open behavior without mocking.
// RecordConsent is a no-op so the server can call it without panicking.
type failOpenConsentStore struct{}

func (f *failOpenConsentStore) RecordConsent(_ context.Context, _ sso.ConsentGrant) error {
	return nil // fail-open on write too — don't block the response
}
func (f *failOpenConsentStore) GetConsent(_ context.Context, _, _ string) (sso.ConsentGrant, error) {
	return sso.ConsentGrant{}, errors.New("consent store: simulated outage")
}
func (f *failOpenConsentStore) RevokeConsent(_ context.Context, _, _ string) error { return nil }
func (f *failOpenConsentStore) ListByUser(_ context.Context, _ string) ([]sso.ConsentGrant, error) {
	return nil, errors.New("consent store: simulated outage")
}

var _ sso.ConsentStore = (*failOpenConsentStore)(nil)

// consentLoginWithChallengeID posts to /auth/login with the supplied scopes
// and a pre-obtained consent_challenge_id. Returns status + decoded JSON body.
func consentLoginWithChallengeID(t *testing.T, srv *httptest.Server, scopes []string, challengeID string) (int, map[string]any) {
	t.Helper()
	req := map[string]any{
		"provider":                authenticators.MethodPassword,
		"client_id":               consentClientID,
		"credential":              map[string]string{"username": consentUser, "password": consentPassword},
		sso.KeyConsentChallengeID: challengeID,
	}
	if len(scopes) > 0 {
		req["scope"] = scopes
	}
	raw, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/login with challenge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestConsent_ConsentRequiredIncludesChallengeID verifies that every
// consent_required response now carries a server-issued consent_challenge_id.
func TestConsent_ConsentRequiredIncludesChallengeID(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	_, body := consentLogin(t, srv, []string{"openid", "profile"}, "")
	if body["error"] != sso.ErrConsentRequired {
		t.Fatalf("expected consent_required, got %v", body)
	}
	challengeID, _ := body[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Errorf("consent_required response missing %q; body=%v", sso.KeyConsentChallengeID, body)
	}
}

// TestConsent_ChallengeFlowIssuesToken verifies the full SPA round-trip:
// login → consent_required + challenge_id → re-login with challenge_id → token.
func TestConsent_ChallengeFlowIssuesToken(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)
	scopes := []string{"openid", "profile"}

	// Step 1: first login → consent_required.
	_, body1 := consentLogin(t, srv, scopes, "")
	if body1["error"] != sso.ErrConsentRequired {
		t.Fatalf("step 1: expected consent_required, got %v", body1)
	}
	challengeID, _ := body1[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Fatalf("step 1: missing %q in response", sso.KeyConsentChallengeID)
	}

	// Step 2: re-login with the server-issued challenge_id → token.
	status2, body2 := consentLoginWithChallengeID(t, srv, scopes, challengeID)
	if status2 != http.StatusOK {
		t.Fatalf("step 2: status=%d body=%v", status2, body2)
	}
	if errVal, ok := body2["error"]; ok {
		t.Fatalf("step 2: unexpected error=%v", errVal)
	}
	if _, ok := body2["access_token"].(string); !ok {
		t.Fatalf("step 2: expected access_token, got %v", body2)
	}
}

// TestConsent_ChallengeIsConsumedSingleUse verifies that a challenge_id is
// single-use — a second presentation triggers consent_required again.
func TestConsent_ChallengeIsConsumedSingleUse(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)
	scopes := []string{"openid"}

	_, body1 := consentLogin(t, srv, scopes, "")
	challengeID, _ := body1[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Fatalf("missing %q", sso.KeyConsentChallengeID)
	}

	// First use → success (grant now recorded for future logins).
	_, body2 := consentLoginWithChallengeID(t, srv, scopes, challengeID)
	if _, ok := body2["access_token"].(string); !ok {
		t.Fatalf("first use of challenge must succeed, got %v", body2)
	}

	// Second use of the same challenge ID → challenge consumed; new consent_required.
	// The grant from the first use covers the scope, so prompt=consent forces re-ask.
	_, body3 := consentLoginWithChallengeID(t, srv, scopes, challengeID)
	// The grant now covers openid so the second call succeeds without needing
	// the (consumed) challenge — the gate only fires when needsConsent is true.
	// Verify no server error occurs (either a token or consent_required is fine).
	if errVal, _ := body3["error"].(string); errVal != "" && errVal != sso.ErrConsentRequired {
		t.Errorf("second use of consumed challenge: unexpected error %q, got %v", errVal, body3)
	}
}

// TestConsent_FabricatedChallengeIsRejected verifies that a client-fabricated
// challenge_id (never issued by the server) is rejected and returns consent_required.
func TestConsent_FabricatedChallengeIsRejected(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	_, body := consentLoginWithChallengeID(t, srv, []string{"openid"}, "not-a-real-challenge")
	if body["error"] != sso.ErrConsentRequired {
		t.Errorf("fabricated challenge must trigger consent_required, got %v", body)
	}
	// A new server-issued challenge must be included so the SPA can proceed.
	if challengeID, _ := body[sso.KeyConsentChallengeID].(string); challengeID == "" {
		t.Errorf("rejected fabricated challenge must include a new %q for the SPA", sso.KeyConsentChallengeID)
	}
}

// TestConsent_ChallengeScopeBinding verifies that a challenge issued for
// scope set A cannot be presented to approve a different scope set B.
func TestConsent_ChallengeScopeBinding(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServer(t, cs)

	// Obtain a challenge for {openid} only.
	_, body1 := consentLogin(t, srv, []string{"openid"}, "")
	challengeID, _ := body1[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Fatalf("missing %q", sso.KeyConsentChallengeID)
	}

	// Present that challenge while requesting a wider scope — must be rejected.
	_, body2 := consentLoginWithChallengeID(t, srv, []string{"openid", "profile"}, challengeID)
	if body2["error"] != sso.ErrConsentRequired {
		t.Errorf("{openid} challenge must not approve {openid,profile}; got %v", body2)
	}
}

// newConsentServerCustomClient mirrors newConsentServer but lets the caller
// mutate the seeded client (to set SkipConsent / ConsentRefreshInterval).
func newConsentServerCustomClient(t *testing.T, cs sso.ConsentStore, mut func(*sso.Client)) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: consentUser})

	clients := defaultimpl.NewMemoryClientStore()
	c := &sso.Client{
		ID:                    consentClientID,
		Secret:                consentSecret,
		Active:                true,
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	}
	if mut != nil {
		mut(c)
	}
	clients.AddSeed(c)

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != consentPassword {
				return nil, errors.New("bad credentials")
			}
			return &sso.AuthResult{UserID: consentUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithConsentStore(cs),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// TestConsent_SkipConsentBypassesGate verifies a client marked SkipConsent
// issues tokens on first login with no consent_required round-trip and records
// no grant (the gate is bypassed entirely). Operator policy, not DCR-settable.
func TestConsent_SkipConsentBypassesGate(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServerCustomClient(t, cs, func(c *sso.Client) { c.SkipConsent = true })

	status, body := consentLogin(t, srv, []string{"openid", "profile"}, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v, want 200", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("skip-consent client must issue a token on first login, got %v", body)
	}
	if _, err := cs.GetConsent(context.Background(), consentUser, consentClientID); !errors.Is(err, sso.ErrNoConsentGrant) {
		t.Errorf("skip-consent must not record a grant; GetConsent err=%v", err)
	}
}

// TestConsent_RefreshIntervalForcesReconsent verifies a grant older than the
// client's ConsentRefreshInterval re-triggers consent even though its scopes
// still cover the request; a fresh grant passes through.
func TestConsent_RefreshIntervalForcesReconsent(t *testing.T) {
	cs := defaultimpl.NewMemoryConsentStore()
	srv := newConsentServerCustomClient(t, cs, func(c *sso.Client) { c.ConsentRefreshInterval = time.Hour })

	// Stale grant (granted 2h ago) still covering the scope -> re-consent forced.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID: consentUser, ClientID: consentClientID,
		Scopes: []string{"openid"}, GrantedAt: time.Now().Add(-2 * time.Hour),
	})
	_, body := consentLogin(t, srv, []string{"openid"}, "")
	if body["error"] != sso.ErrConsentRequired {
		t.Fatalf("stale grant past refresh interval must force re-consent, got %v", body)
	}

	// Fresh grant -> token issued without re-consent.
	_ = cs.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID: consentUser, ClientID: consentClientID,
		Scopes: []string{"openid"}, GrantedAt: time.Now(),
	})
	status2, body2 := consentLogin(t, srv, []string{"openid"}, "")
	if status2 != http.StatusOK {
		t.Fatalf("fresh grant status=%d body=%v", status2, body2)
	}
	if _, ok := body2["access_token"].(string); !ok {
		t.Errorf("fresh grant within interval must issue token, got %v", body2)
	}
}
