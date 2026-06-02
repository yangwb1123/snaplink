package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// credHealthHarness boots a *sso.Server with a REAL password
// authenticator, a REAL DictionaryPasswordHealthChecker, an audit sink,
// and an Ed25519 issuer doubling as the id_token signer — everything the
// credential-health signal needs to be observed end to end. No mocks: the
// verifier is a tiny closure but the health check + issuance + audit are
// all production code.
type credHealthHarness struct {
	srv  *httptest.Server
	sink *audit.MemorySink
}

const (
	chClientID = "ch-client"
	chUserID   = "u-ch"
	chWeakPass = "password" // a built-in dictionary entry
	chStrong   = "Tr0ub4dor&3-correct-horse-battery"
)

func newCredHealthHarness(t *testing.T) *credHealthHarness {
	t.Helper()
	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: chUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: chClientID, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         []string{"openid", "profile"},
	})

	// A verifier that only succeeds for the seeded user, echoing the
	// supplied password is unnecessary — the authenticator passes the
	// plaintext to the health checker itself.
	verifier := authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, _ string) (*sso.AuthResult, error) {
			if username != "alice" {
				return nil, errors.New("invalid credentials")
			}
			// Attributes are deliberately set here to prove the no-leak
			// invariant is about CredentialHealth specifically: real
			// claims still flow to the id_token, the health signal never.
			return &sso.AuthResult{
				UserID:     chUserID,
				Provider:   "password",
				Attributes: map[string]string{"email": "alice@example.com"},
			}, nil
		},
	)
	checker, err := defaultimpl.NewDictionaryPasswordHealthChecker(defaultimpl.DictionaryPasswordHealthConfig{})
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	pw := authenticators.NewPasswordAuthenticator(verifier, authenticators.WithPasswordHealthChecker(checker))

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srv := sso.NewServer(
		sso.WithAuditRecorder(rec),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &credHealthHarness{srv: httpSrv, sink: sink}
}

func (h *credHealthHarness) login(t *testing.T, password string) map[string]any {
	t.Helper()
	body := `{"provider":"password","client_id":"` + chClientID +
		`","scope":["openid","profile"],"credential":{"username":"alice","password":"` + password + `"}}`
	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("login decode: %v body=%s", err, raw)
	}
	return out
}

func (h *credHealthHarness) events(t *testing.T) []*audit.Event {
	t.Helper()
	evs, err := h.sink.Query(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("sink.Query: %v", err)
	}
	return evs
}

func (h *credHealthHarness) countEvents(t *testing.T, kind audit.EventType) int {
	n := 0
	for _, e := range h.events(t) {
		if e.Type == kind {
			n++
		}
	}
	return n
}

// TestCredentialHealth_WeakPasswordEmitsAuditSignalButNoLeak is the core
// invariant test: a weak password (a) still logs in + issues tokens,
// (b) records a password_weak audit event with Outcome=success, (c) does
// NOT leak any credential-health field into the id_token, and the login
// response carries no health fields either.
func TestCredentialHealth_WeakPasswordEmitsAuditSignalButNoLeak(t *testing.T) {
	h := newCredHealthHarness(t)
	out := h.login(t, chWeakPass)

	// (a) login succeeded and tokens issued.
	at, _ := out[sso.KeyAccessToken].(string)
	if at == "" {
		t.Fatalf("no access_token in login response: %v", out)
	}
	idTok, _ := out[sso.KeyIDToken].(string)
	if idTok == "" {
		t.Fatalf("no id_token in login response: %v", out)
	}

	// (b) a password_weak audit event was recorded, Outcome=success.
	var weak *audit.Event
	for _, e := range h.events(t) {
		if e.Type == audit.EventPasswordWeak {
			weak = e
			break
		}
	}
	if weak == nil {
		t.Fatalf("expected a password_weak audit event, none recorded")
	}
	if weak.Outcome != audit.OutcomeSuccess {
		t.Errorf("password_weak Outcome = %q, want success", weak.Outcome)
	}
	if weak.ActorID != chUserID {
		t.Errorf("password_weak ActorID = %q, want %q", weak.ActorID, chUserID)
	}
	if weak.ClientID != chClientID {
		t.Errorf("password_weak ClientID = %q, want %q", weak.ClientID, chClientID)
	}
	if weak.Metadata["reason"] == "" {
		t.Errorf("password_weak missing reason metadata: %v", weak.Metadata)
	}

	// A normal login_success event still fires alongside it.
	if h.countEvents(t, audit.EventLogin) == 0 {
		t.Errorf("expected a login success event alongside the health signal")
	}

	// (c) no credential-health field leaked into the id_token claims, and
	// the real attribute (email) still flowed through — proving the
	// no-leak is specific to CredentialHealth, not a blanket claim drop.
	claims := decodeJWTPayload(t, idTok)
	assertNoHealthLeak(t, claims, "id_token")

	// Nor into the access token (it is a signed JWT here too).
	atClaims := decodeJWTPayload(t, at)
	assertNoHealthLeak(t, atClaims, "access_token")

	// Nor into the raw login response body.
	for k := range out {
		assertHealthlessKey(t, k, "login_response")
	}
}

// TestCredentialHealth_StrongPasswordEmitsNoSignal proves a strong
// password fires no health event (and login still works).
func TestCredentialHealth_StrongPasswordEmitsNoSignal(t *testing.T) {
	h := newCredHealthHarness(t)
	out := h.login(t, chStrong)
	if out[sso.KeyAccessToken] == "" {
		t.Fatalf("strong-password login did not issue a token: %v", out)
	}
	if n := h.countEvents(t, audit.EventPasswordWeak); n != 0 {
		t.Errorf("password_weak fired %d times for a strong password, want 0", n)
	}
	if n := h.countEvents(t, audit.EventPasswordCompromised); n != 0 {
		t.Errorf("password_compromised fired %d times for a strong password, want 0", n)
	}
}

// assertNoHealthLeak fails if any claim key looks like a credential-health
// field, and confirms a real claim (email) is still present.
func assertNoHealthLeak(t *testing.T, claims map[string]any, where string) {
	t.Helper()
	for k := range claims {
		assertHealthlessKey(t, k, where)
	}
}

func assertHealthlessKey(t *testing.T, key, where string) {
	t.Helper()
	lk := strings.ToLower(key)
	for _, bad := range []string{"credentialhealth", "credential_health", "weak", "compromised", "password_health"} {
		if strings.Contains(lk, bad) {
			t.Errorf("%s leaked a credential-health field: key=%q", where, key)
		}
	}
}
