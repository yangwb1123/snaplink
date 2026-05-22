package sso_test

// MFA orchestration end-to-end. Exercises:
//   - RiskScorer DecisionRequireMFA + MFAProvider wired → /auth/login
//     returns mfa_required (no tokens, no session)
//   - POST /auth/mfa with the matching challenge ID + valid TOTP code
//     resumes the login and mints tokens with the same response shape
//     as a non-MFA-gated login
//   - Audit events (mfa_required, mfa_success) are emitted on the
//     happy path
//   - Failure paths (wrong code, wrong challenge ID, replay of an
//     already-consumed challenge, unsupported method) all collapse to
//     the same mfa_invalid wire response (oracle-leak hardening)
//
// Reuses the buildRiskHarness pattern from risk_test.go but plugs in
// an MFAProvider + MFAChallengeStore so DecisionRequireMFA actually
// gates the flow.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
)

// totpStubStore is an in-memory authenticators.TOTPStore for the
// fixture user. Real deployments wire a SQLite/Redis peer; tests get
// away with a one-line struct.
type totpStubStore struct{ secret []byte }

func (s *totpStubStore) GetSecret(_ context.Context, _ string) ([]byte, error) {
	return s.secret, nil
}

// hotpCode is a minimal RFC 4226 HOTP — duplicated here (not pulled
// out of authenticators/totp.go where it's lowercase) so the test
// stays self-contained and doesn't have to import unexported helpers.
func hotpCode(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

// validTOTPCode returns a fresh TOTP code for the supplied secret at
// the current clock step.
func validTOTPCode(t *testing.T, secret []byte) string {
	t.Helper()
	counter := time.Now().Unix() / 30
	return hotpCode(secret, counter)
}

// buildMFAHarness wires the same primary-credential setup risk_test.go
// uses, then plugs in:
//   - a stub RiskScorer that always returns DecisionRequireMFA
//   - a TOTPMFAProvider with one enrolled user (subject "alice", same
//     secret as the totpStubStore)
//   - an in-memory MFAChallengeStore
//
// Returns the running httptest server, the audit sink for assertions,
// and the shared TOTP secret so callers can mint valid codes.
func buildMFAHarness(t *testing.T) (*httptest.Server, *audit.MemorySink, []byte) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("mfa-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "mfa-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)

	secret := []byte("12345678901234567890") // RFC 4226 §D.1 test vector
	totpStore := &totpStubStore{secret: secret}
	totpAuth := authenticators.NewTOTPAuthenticator(totpStore)
	mfaProvider := authenticators.NewTOTPMFAProvider(totpAuth)
	mfaChallengeStore := defaultimpl.NewMemoryMFAChallengeStore()

	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(50)
	recorder := audit.New(sink)

	scorer := newStubScorer(sso.DecisionRequireMFA)

	srv := sso.NewServer(
		sso.WithIssuer("mfa-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithAuditRecorder(recorder),
		sso.WithRiskScorer(scorer),
		sso.WithMFAProvider(mfaProvider),
		sso.WithMFAChallengeStore(mfaChallengeStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink, secret
}

// loginMFA POSTs to /auth/login and returns the (status, decoded body).
func loginMFA(t *testing.T, srv *httptest.Server) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "mfa-app",
		"credential": map[string]string{"username": "alice", "password": "s3cret"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// completeMFA POSTs to /auth/mfa with the supplied challenge id +
// method + code, returns (status, body).
func completeMFA(t *testing.T, srv *httptest.Server, challengeID, method, code string) (int, map[string]any) {
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
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// TestMFA_HappyPath — RiskScorer says RequireMFA → /auth/login returns
// mfa_required + challenge id; /auth/mfa with a valid TOTP code resumes
// the flow and mints tokens with the standard direct-mint response.
func TestMFA_HappyPath(t *testing.T) {
	srv, sink, secret := buildMFAHarness(t)

	status, body := loginMFA(t, srv)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (mfa_required is success-shaped)", status)
	}
	if body["error"] != sso.ErrMFARequired {
		t.Errorf("error = %v, want mfa_required", body["error"])
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("mfa_challenge_id missing; body=%v", body)
	}
	methods, _ := body["mfa_methods"].([]any)
	if len(methods) == 0 || methods[0] != authenticators.MethodTOTP {
		t.Errorf("mfa_methods = %v, want [totp]", methods)
	}
	if _, hasAccess := body["access_token"]; hasAccess {
		t.Errorf("access_token leaked in mfa_required response: %v", body)
	}

	code := validTOTPCode(t, secret)
	status, body = completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusOK {
		t.Fatalf("/auth/mfa status = %d body=%v", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("access_token missing from resumed login; body=%v", body)
	}
	if _, ok := body["session_id"].(string); !ok {
		t.Errorf("session_id missing from resumed login; body=%v", body)
	}

	// Audit: mfa_required + mfa_success + login_success (the last
	// emitted by finishLogin via recordLoginSuccess).
	events := sinkEvents(t, sink)
	seen := map[audit.EventType]int{}
	for _, e := range events {
		seen[e.Type]++
	}
	if seen[audit.EventMFARequired] == 0 {
		t.Errorf("no mfa_required event in audit log; events=%v", eventNames(events))
	}
	if seen[audit.EventMFASuccess] == 0 {
		t.Errorf("no mfa_success event in audit log; events=%v", eventNames(events))
	}
	if seen[audit.EventLogin] == 0 {
		t.Errorf("no login (success) event after mfa resume; events=%v", eventNames(events))
	}
}

// TestMFA_WrongCode_Returns_mfa_invalid — feeding a TOTP code that
// doesn't match the secret returns mfa_invalid + 400 + emits mfa_failure
// audit.
func TestMFA_WrongCode_Returns_mfa_invalid(t *testing.T) {
	srv, sink, _ := buildMFAHarness(t)

	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)

	status, mfaBody := completeMFA(t, srv, chal, authenticators.MethodTOTP, "000000")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if mfaBody["error"] != sso.ErrMFAInvalid {
		t.Errorf("error = %v, want mfa_invalid", mfaBody["error"])
	}
	if !hasEvent(sinkEvents(t, sink), audit.EventMFAFailure) {
		t.Errorf("missing mfa_failure audit event")
	}
}

// TestMFA_UnknownChallengeID — fabricated challenge id (e.g. someone
// guessing) collapses to mfa_invalid, same shape as wrong-code.
// Anti-enumeration: probe can't tell the cases apart.
func TestMFA_UnknownChallengeID(t *testing.T) {
	srv, _, _ := buildMFAHarness(t)
	status, body := completeMFA(t, srv, "fabricated-id-that-was-never-issued", authenticators.MethodTOTP, "123456")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != sso.ErrMFAInvalid {
		t.Errorf("error = %v, want mfa_invalid", body["error"])
	}
}

// TestMFA_Replay_AlreadyConsumed — a successful /auth/mfa burns the
// challenge; a second call with the same id MUST return mfa_invalid
// (single-use enforcement — same DELETE-and-return atomic pattern
// AuthCodeStore / DeviceCodeStore use).
func TestMFA_Replay_AlreadyConsumed(t *testing.T) {
	srv, _, secret := buildMFAHarness(t)
	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)
	code := validTOTPCode(t, secret)

	status, _ := completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusOK {
		t.Fatalf("first completion status = %d, want 200", status)
	}
	status, replayBody := completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", status)
	}
	if replayBody["error"] != sso.ErrMFAInvalid {
		t.Errorf("replay error = %v, want mfa_invalid", replayBody["error"])
	}
}

// TestMFA_UnsupportedMethod — caller supplies a method the provider
// doesn't expose. Same mfa_invalid response (anti-enumeration).
func TestMFA_UnsupportedMethod(t *testing.T) {
	srv, _, _ := buildMFAHarness(t)
	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)

	status, mfaBody := completeMFA(t, srv, chal, "smoke-signals", "ignored")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if mfaBody["error"] != sso.ErrMFAInvalid {
		t.Errorf("error = %v, want mfa_invalid", mfaBody["error"])
	}
}

// TestMFA_NoProviderWired_FallsThroughToAllow — when MFAProvider is
// not configured but the scorer returns DecisionRequireMFA, the
// historical no-op behavior (treat as Allow) MUST be preserved so
// callers wiring a forward-looking scorer aren't broken before MFA
// orchestration ships in their deployment.
func TestMFA_NoProviderWired_FallsThroughToAllow(t *testing.T) {
	// Reuse the risk_test.go harness which doesn't wire WithMFAProvider.
	stub := newStubScorer(sso.DecisionRequireMFA)
	srv, _ := buildRiskHarness(t, stub)

	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no-provider falls through to Allow)", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if _, ok := body["access_token"]; !ok {
		t.Errorf("access_token missing — RequireMFA without provider should issue tokens like Allow; body=%v", body)
	}
	if body["error"] == sso.ErrMFARequired {
		t.Errorf("response carried mfa_required despite no provider wired; body=%v", body)
	}
}

// sinkEvents fetches every event the MemorySink holds via the standard
// Query SPI (Snapshot doesn't exist on MemorySink; use Limit:0 → server
// default which is plenty for tests that only emit a handful).
func sinkEvents(t *testing.T, sink *audit.MemorySink) []*audit.Event {
	t.Helper()
	out, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return out
}

// hasEvent reports whether the audit slice contains an event of t.
func hasEvent(events []*audit.Event, t audit.EventType) bool {
	for _, e := range events {
		if e.Type == t {
			return true
		}
	}
	return false
}

// eventNames returns the Type field of each event, for failure messages.
func eventNames(events []*audit.Event) []audit.EventType {
	out := make([]audit.EventType, len(events))
	for i, e := range events {
		out[i] = e.Type
	}
	return out
}
