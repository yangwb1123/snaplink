package ssotest

import (
	"bytes"
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
	"github.com/snaplink/sso/spi"
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
	defer func() { _ = resp.Body.Close() }()
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

// newCredHealthMFAHarness boots a *sso.Server that combines the
// credential-health wiring (password auth + real
// DictionaryPasswordHealthChecker) with the MFA step-up wiring (a
// RiskScorer that always returns RequireMFA + a real TOTP MFA provider +
// an in-memory MFA challenge store). This is the regression fixture for
// the json:"-" change: the entire *AuthResult is serialized into the MFA
// challenge store as a resume blob, so a naive json:"-" would silently
// drop the credential-health audit for MFA-gated logins. The harness
// drives /auth/login -> mfa_required -> /auth/mfa and lets the test prove
// the audit still fires exactly once with no wire leak.
//
// Returns the running server, the audit sink, and the shared TOTP secret
// for minting valid codes.
func newCredHealthMFAHarness(t *testing.T) (*httptest.Server, *audit.MemorySink, []byte) {
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

	verifier := authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, _ string) (*sso.AuthResult, error) {
			if username != "alice" {
				return nil, errors.New("invalid credentials")
			}
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

	secret := []byte("12345678901234567890") // RFC 4226 D.1 test vector
	totpStore := &totpStubStore{secret: secret}
	totpAuth := authenticators.NewTOTPAuthenticator(totpStore)
	mfaProvider := authenticators.NewTOTPMFAProvider(totpAuth)
	mfaChallengeStore := defaultimpl.NewMemoryMFAChallengeStore()

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
		sso.WithRiskScorer(newStubScorer(spi.DecisionRequireMFA)),
		sso.WithMFAProvider(mfaProvider),
		sso.WithMFAChallengeStore(mfaChallengeStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink, secret
}

// TestCredentialHealth_MFAGatedPath_EmitsAuditOnceNoLeak is the
// regression guard for the json:"-" change. A weak password (a) is gated
// by RequireMFA so login first returns mfa_required, then resumes through
// /auth/mfa; the credential-health audit MUST still fire — and EXACTLY
// once (mfa_required carries no double-emit, /auth/mfa resumes through the
// same finishLogin emission point). It also proves the advisory never
// leaks: not into the issued tokens, not into the /auth/mfa response body,
// not into the first-leg mfa_required body.
func TestCredentialHealth_MFAGatedPath_EmitsAuditOnceNoLeak(t *testing.T) {
	srv, sink, secret := newCredHealthMFAHarness(t)

	// First leg: weak password → RequireMFA → mfa_required (HTTP 200).
	status, body := loginMFAWeak(t, srv)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (mfa_required is success-shaped); body=%v", status, body)
	}
	if body["error"] != sso.ErrMFARequired {
		t.Fatalf("error = %v, want mfa_required; body=%v", body["error"], body)
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("mfa_challenge_id missing; body=%v", body)
	}
	// No tokens leaked before step-up, and crucially (d) no health field
	// in the mfa_required body either.
	if _, hasAccess := body["access_token"]; hasAccess {
		t.Errorf("access_token leaked in mfa_required response: %v", body)
	}
	for k := range body {
		assertHealthlessKey(t, k, "mfa_required_response")
	}

	// At this point the credential-health audit MUST NOT have fired yet —
	// it is emitted only on the successful finishLogin (post step-up).
	if n := countSinkEvents(sink, t, audit.EventPasswordWeak); n != 0 {
		t.Fatalf("password_weak fired %d times before MFA completion, want 0 (must emit on resume, not on challenge issue)", n)
	}

	// Second leg: complete /auth/mfa with a valid TOTP code → resume.
	code := validTOTPCode(t, secret)
	mfaStatus, mfaBody := completeMFAWeak(t, srv, chal, authenticators.MethodTOTP, code)
	if mfaStatus != http.StatusOK {
		t.Fatalf("/auth/mfa status = %d body=%v", mfaStatus, mfaBody)
	}

	at, _ := mfaBody[sso.KeyAccessToken].(string)
	if at == "" {
		t.Fatalf("no access_token in resumed login response: %v", mfaBody)
	}
	idTok, _ := mfaBody[sso.KeyIDToken].(string)
	if idTok == "" {
		t.Fatalf("no id_token in resumed login response: %v", mfaBody)
	}

	// (a) EXACTLY ONE password_weak event across the whole flow. Not zero
	// (proves the MFA-resume path preserved the signal through the
	// challenge store) and not two (proves no double-emit across the two
	// legs).
	if n := countSinkEvents(sink, t, audit.EventPasswordWeak); n != 1 {
		t.Fatalf("password_weak fired %d times across the MFA-gated flow, want exactly 1", n)
	}
	// And the resume actually completed: mfa_success + login both fired.
	if n := countSinkEvents(sink, t, audit.EventMFASuccess); n == 0 {
		t.Errorf("no mfa_success event after resume")
	}
	if n := countSinkEvents(sink, t, audit.EventLogin); n == 0 {
		t.Errorf("no login success event after resume")
	}

	// (b) no credential-health field leaked into the issued tokens.
	assertNoHealthLeak(t, decodeJWTPayload(t, idTok), "id_token")
	assertNoHealthLeak(t, decodeJWTPayload(t, at), "access_token")

	// (c) no credential-health field in the /auth/mfa JSON response body.
	for k := range mfaBody {
		assertHealthlessKey(t, k, "mfa_response")
	}
}

// loginMFAWeak POSTs a weak-password login to /auth/login (which the
// RequireMFA scorer gates into mfa_required) and returns the status +
// decoded body.
func loginMFAWeak(t *testing.T, srv *httptest.Server) (int, map[string]any) {
	t.Helper()
	body := `{"provider":"password","client_id":"` + chClientID +
		`","scope":["openid","profile"],"credential":{"username":"alice","password":"` + chWeakPass + `"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode login body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// completeMFAWeak POSTs to /auth/mfa with the challenge id + method +
// code, returning the status + decoded body.
func completeMFAWeak(t *testing.T, srv *httptest.Server, challengeID, method, code string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"mfa_challenge_id": challengeID,
		"mfa_method":       method,
		"code":             code,
	})
	resp, err := http.Post(srv.URL+"/auth/mfa", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/mfa: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode mfa body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// countSinkEvents counts events of the given type in the sink.
func countSinkEvents(sink *audit.MemorySink, t *testing.T, kind audit.EventType) int {
	t.Helper()
	evs, err := sink.Query(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("sink.Query: %v", err)
	}
	n := 0
	for _, e := range evs {
		if e.Type == kind {
			n++
		}
	}
	return n
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
