package ssotest

import "github.com/yangwb1123/snaplink/shared/spi"

// MFA orchestration end-to-end. Exercises:
//   - spi.RiskScorer spi.DecisionRequireMFA + spi.MFAProvider wired → /auth/login
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
// an spi.MFAProvider + spi.MFAChallengeStore so spi.DecisionRequireMFA actually
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
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
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
//   - a stub spi.RiskScorer that always returns spi.DecisionRequireMFA
//   - a TOTPMFAProvider with one enrolled user (subject "alice", same
//     secret as the totpStubStore)
//   - an in-memory spi.MFAChallengeStore
//
// Returns the running httptest server, the audit sink for assertions,
// and the shared TOTP secret so callers can mint valid codes.
func buildMFAHarness(t *testing.T, extra ...sso.Option) (*httptest.Server, *audit.MemorySink, []byte) {
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

	scorer := newStubScorer(spi.DecisionRequireMFA)

	opts := []sso.Option{
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
	}
	srv := sso.NewServer(append(opts, extra...)...)
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// completeMFATrust POSTs to /auth/mfa exactly like completeMFA but also sets
// trust_device on the wire, mirroring the login UI's #mfa-trust-device
// checkbox (interfaces/web/login/app.js: `trust_device: trustDevice ||
// false`).
func completeMFATrust(t *testing.T, srv *httptest.Server, challengeID, method, code string, trustDevice bool) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"mfa_challenge_id": challengeID,
		"mfa_method":       method,
		"code":             code,
		"trust_device":     trustDevice,
	})
	resp, err := http.Post(srv.URL+"/auth/mfa", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/mfa: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body: %v (raw=%s)", err, raw)
	}
	return resp.StatusCode, out
}

// TestMFA_HappyPath — spi.RiskScorer says RequireMFA → /auth/login returns
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
// oauth.AuthCodeStore / oauth.DeviceCodeStore use).
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

// TestMFA_TrustDevice_MintsGrantAndReturnsToken — trust_device=true with a
// wired core.TrustedDeviceStore, on a SUCCESSFUL MFA completion, mints a
// grant for the RIGHT (userID, clientID) pair and returns the token under
// "device_token" — the SAME field name POST /me/devices/trust already
// returns (protocols/selfservice/selfserviceaccount/trusted_devices.go), so
// client code has one field to look for across both endpoints. It also
// proves the minted token is the real thing: a follow-up /auth/login
// presenting it as device_token skips the MFA challenge entirely, exactly
// like a token minted via the self-service endpoint (server_login_client.go
// trustedDeviceAllowsSkip).
func TestMFA_TrustDevice_MintsGrantAndReturnsToken(t *testing.T) {
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	srv, _, secret := buildMFAHarness(t, sso.WithTrustedDeviceStore(tds, 30*24*time.Hour))

	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)
	code := validTOTPCode(t, secret)

	status, mfaBody := completeMFATrust(t, srv, chal, authenticators.MethodTOTP, code, true)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", status, mfaBody)
	}
	token, ok := mfaBody["device_token"].(string)
	if !ok || token == "" {
		t.Fatalf("device_token missing/empty from successful trust_device response; body=%v", mfaBody)
	}

	devices, err := tds.ListByUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].UserID != "alice" {
		t.Errorf("UserID = %q, want alice", devices[0].UserID)
	}
	if devices[0].ClientID != "mfa-app" {
		t.Errorf("ClientID = %q, want mfa-app", devices[0].ClientID)
	}

	// The minted token must actually skip a later MFA challenge for the SAME
	// (user, client) — proves it rides the identical store.Verify path
	// trustedDeviceAllowsSkip consumes on /auth/login, not a look-alike.
	loginReq, _ := json.Marshal(map[string]any{
		"provider":     "password",
		"client_id":    "mfa-app",
		"credential":   map[string]string{"username": "alice", "password": "s3cret"},
		"device_token": token,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(loginReq))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with freshly-trusted device_token status=%d body=%v, want 200", resp.StatusCode, out)
	}
	if _, hasAccess := out["access_token"]; !hasAccess {
		t.Errorf("login with freshly-trusted device_token didn't skip MFA: %v", out)
	}
}

// TestMFA_TrustDevice_FalseDoesNotCallStore — trust_device omitted from the
// request entirely (the zero value / historical wire shape, matching every
// pre-existing caller) must never invoke the store, even when one is wired.
func TestMFA_TrustDevice_FalseDoesNotCallStore(t *testing.T) {
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	srv, _, secret := buildMFAHarness(t, sso.WithTrustedDeviceStore(tds, 30*24*time.Hour))

	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)
	code := validTOTPCode(t, secret)

	// completeMFA never sets trust_device at all — the pre-existing wire
	// shape every caller before this feature used.
	status, mfaBody := completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", status, mfaBody)
	}
	if _, leaked := mfaBody["device_token"]; leaked {
		t.Errorf("device_token present despite trust_device omitted: %v", mfaBody)
	}
	devices, err := tds.ListByUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("len(devices) = %d, want 0 — trust_device omitted must never call Trust", len(devices))
	}
}

// TestMFA_TrustDevice_NoStoreWiredIsSafeNoOp — trust_device=true with NO
// core.TrustedDeviceStore wired must be a silent, safe no-op: no panic,
// the MFA completion still succeeds exactly like the pre-feature response
// (no device_token key at all), same as every other optional-store pattern
// in this repo (nil store = feature not wired).
func TestMFA_TrustDevice_NoStoreWiredIsSafeNoOp(t *testing.T) {
	srv, _, secret := buildMFAHarness(t) // no WithTrustedDeviceStore
	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)
	code := validTOTPCode(t, secret)

	status, mfaBody := completeMFATrust(t, srv, chal, authenticators.MethodTOTP, code, true)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (trust_device with no store wired must be a safe no-op); body=%v", status, mfaBody)
	}
	if _, ok := mfaBody["access_token"]; !ok {
		t.Errorf("access_token missing; trust_device with no store wired must not block the login: %v", mfaBody)
	}
	if _, leaked := mfaBody["device_token"]; leaked {
		t.Errorf("device_token present despite no TrustedDeviceStore wired: %v", mfaBody)
	}
}

// TestMFA_TrustDevice_FailedAttemptNeverTouchesStoreOrChangesResponse is the
// critical anti-regression check: a FAILED MFA attempt (wrong code) with
// trust_device=true must (1) NEVER call the store, and (2) produce the
// EXACT SAME 400 mfa_invalid response — status AND body — as an otherwise
// identical failed attempt that never mentions trust_device at all. The
// field is only ever consulted deep inside resumeLoginAfterMFA, strictly
// after verifyMFAFactor has already returned ok=true; a failed verify
// returns before trust_device is read at all, so this proves the
// Anti-Enumeration invariant ("MFA /auth/mfa: all failures → 400
// mfa_invalid") is unchanged byte-for-byte by this feature.
func TestMFA_TrustDevice_FailedAttemptNeverTouchesStoreOrChangesResponse(t *testing.T) {
	tds := defaultimpl.NewMemoryTrustedDeviceStore()
	srv, _, _ := buildMFAHarness(t, sso.WithTrustedDeviceStore(tds, 30*24*time.Hour))

	// Each failed attempt consumes its own single-use challenge (verifyMFAFactor
	// calls Consume before checking the code), so each needs a fresh challenge.
	_, body1 := loginMFA(t, srv)
	chal1 := body1["mfa_challenge_id"].(string)
	statusPlain, bodyPlain := completeMFA(t, srv, chal1, authenticators.MethodTOTP, "000000")

	_, body2 := loginMFA(t, srv)
	chal2 := body2["mfa_challenge_id"].(string)
	statusTrust, bodyTrust := completeMFATrust(t, srv, chal2, authenticators.MethodTOTP, "000000", true)

	if statusPlain != http.StatusBadRequest {
		t.Fatalf("plain status = %d, want 400", statusPlain)
	}
	if statusTrust != statusPlain {
		t.Fatalf("trust_device=true changed the failure status: plain=%d trust=%d", statusPlain, statusTrust)
	}
	if !reflect.DeepEqual(bodyPlain, bodyTrust) {
		t.Errorf("trust_device=true altered the mfa_invalid failure response body:\n  plain=%v\n  trust=%v", bodyPlain, bodyTrust)
	}
	if bodyTrust["error"] != sso.ErrMFAInvalid {
		t.Errorf("error = %v, want mfa_invalid", bodyTrust["error"])
	}

	devices, err := tds.ListByUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("len(devices) = %d, want 0 — a FAILED MFA attempt must never call Trust", len(devices))
	}
}

// TestMFA_NoProviderWired_FallsThroughToAllow — when spi.MFAProvider is
// not configured but the scorer returns spi.DecisionRequireMFA, the
// historical no-op behavior (treat as Allow) MUST be preserved so
// callers wiring a forward-looking scorer aren't broken before MFA
// orchestration ships in their deployment.
func TestMFA_NoProviderWired_FallsThroughToAllow(t *testing.T) {
	// Reuse the risk_test.go harness which doesn't wire WithMFAProvider.
	stub := newStubScorer(spi.DecisionRequireMFA)
	srv, _ := buildRiskHarness(t, stub)

	resp := loginRisk(t, srv)
	defer func() { _ = resp.Body.Close() }()
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

// stubBeginnerProvider implements both spi.MFAProvider and
// spi.MFABeginner so the dispatch path can be exercised without
// pulling in WebAuthn's go-jose dependency tree. methods is the
// SupportedMethods return; beginErr controls whether Begin succeeds
// (returns the data map) or errors (skipped non-fatally per the SPI
// contract). verifyErr drives Verify the same way.
type stubBeginnerProvider struct {
	methods   []string
	beginData map[string]map[string]string // method → key/value blob
	beginErr  map[string]error             // method → forced Begin error
	verifyErr error                        // forced Verify error
}

func (s *stubBeginnerProvider) SupportedMethods() []string { return s.methods }
func (s *stubBeginnerProvider) Verify(_ context.Context, _, _ string, _ map[string]string) error {
	return s.verifyErr
}
func (s *stubBeginnerProvider) Begin(_ context.Context, _, method string) (map[string]string, error) {
	if err, ok := s.beginErr[method]; ok {
		return nil, err
	}
	return s.beginData[method], nil
}

// buildMFAHarnessWithProvider mirrors buildMFAHarness but lets the
// caller supply a custom spi.MFAProvider — exercises Beginner dispatch
// + multi-method paths without inheriting buildMFAHarness's hard-
// coded TOTP wiring.
func buildMFAHarnessWithProvider(t *testing.T, provider spi.MFAProvider) (*httptest.Server, *audit.MemorySink) {
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

	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(50)
	recorder := audit.New(sink)
	scorer := newStubScorer(spi.DecisionRequireMFA)
	store := defaultimpl.NewMemoryMFAChallengeStore()

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
		sso.WithMFAProvider(provider),
		sso.WithMFAChallengeStore(store, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

// TestMFA_BeginnerDispatch_PopulatesMethodData proves that when a
// provider implements spi.MFABeginner, the mfa_required response carries
// the per-method server-issued challenge data under mfa_method_data.
// This is what unblocks two-call factors like WebAuthn — the client
// needs the assertion options + session id before it can sign.
func TestMFA_BeginnerDispatch_PopulatesMethodData(t *testing.T) {
	provider := &stubBeginnerProvider{
		methods: []string{"factor-a", "factor-b"},
		beginData: map[string]map[string]string{
			"factor-a": {"challenge": "ch-a-base64", "session": "sess-a"},
			"factor-b": {"challenge": "ch-b-base64", "session": "sess-b"},
		},
	}
	srv, _ := buildMFAHarnessWithProvider(t, provider)

	_, body := loginMFA(t, srv)
	if body["error"] != sso.ErrMFARequired {
		t.Fatalf("error = %v want mfa_required", body["error"])
	}
	raw, ok := body["mfa_method_data"].(map[string]any)
	if !ok {
		t.Fatalf("mfa_method_data missing or wrong type; body=%v", body)
	}
	for _, method := range []string{"factor-a", "factor-b"} {
		bucket, ok := raw[method].(map[string]any)
		if !ok {
			t.Errorf("mfa_method_data[%q] missing or wrong type: %v", method, raw[method])
			continue
		}
		if bucket["challenge"] != "ch-"+method[len(method)-1:]+"-base64" {
			t.Errorf("mfa_method_data[%q][challenge] = %v, want ch-%s-base64", method, bucket["challenge"], method[len(method)-1:])
		}
		if bucket["session"] != "sess-"+method[len(method)-1:] {
			t.Errorf("mfa_method_data[%q][session] = %v, want sess-%s", method, bucket["session"], method[len(method)-1:])
		}
	}
}

// TestMFA_BeginnerOptional_TOTPHasNoMethodData proves the dispatch is
// strictly opt-in via interface assertion — the shipped TOTPMFAProvider
// doesn't need Begin (codes are computed client-side from the shared
// secret) and the response intentionally omits mfa_method_data.
// Back-compat: existing TOTP-only deployments see no wire change.
func TestMFA_BeginnerOptional_TOTPHasNoMethodData(t *testing.T) {
	srv, _, _ := buildMFAHarness(t)
	_, body := loginMFA(t, srv)
	if body["error"] != sso.ErrMFARequired {
		t.Fatalf("error = %v want mfa_required", body["error"])
	}
	if _, present := body["mfa_method_data"]; present {
		t.Errorf("mfa_method_data should be absent for TOTP-only provider; body=%v", body)
	}
}

// TestMFA_BeginnerError_NonFatal_MethodStillListed proves a Begin
// failure for one method doesn't fault the whole mfa_required
// response — the method stays in mfa_methods, just without an
// attached method_data entry. The client can retry the begin path
// out-of-band or pick a different factor.
func TestMFA_BeginnerError_NonFatal_MethodStillListed(t *testing.T) {
	provider := &stubBeginnerProvider{
		methods:   []string{"good", "broken"},
		beginData: map[string]map[string]string{"good": {"k": "v"}},
		beginErr:  map[string]error{"broken": errors.New("boom")},
	}
	srv, _ := buildMFAHarnessWithProvider(t, provider)

	_, body := loginMFA(t, srv)
	methods, _ := body["mfa_methods"].([]any)
	if len(methods) != 2 {
		t.Fatalf("mfa_methods = %v want both methods listed even when one Begin fails", methods)
	}
	data, _ := body["mfa_method_data"].(map[string]any)
	if data == nil {
		t.Fatal("mfa_method_data missing — Begin failure shouldn't suppress the good method's data")
	}
	if _, ok := data["good"]; !ok {
		t.Errorf("mfa_method_data[good] missing despite successful Begin")
	}
	if _, ok := data["broken"]; ok {
		t.Errorf("mfa_method_data[broken] unexpectedly present despite Begin failure: %v", data["broken"])
	}
}

// TestMFA_BeginnerAllErrors_OmitsMethodDataKey proves the harness
// doesn't emit an empty mfa_method_data object when every method's
// Begin fails — the key should be absent (smaller response, simpler
// client parsing).
func TestMFA_BeginnerAllErrors_OmitsMethodDataKey(t *testing.T) {
	provider := &stubBeginnerProvider{
		methods:  []string{"a"},
		beginErr: map[string]error{"a": errors.New("nope")},
	}
	srv, _ := buildMFAHarnessWithProvider(t, provider)

	_, body := loginMFA(t, srv)
	if _, present := body["mfa_method_data"]; present {
		t.Errorf("mfa_method_data unexpectedly present when every Begin failed: %v", body["mfa_method_data"])
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

// countingLockout is a minimal security.AccountLockout for tests: it locks a key
// once its failure count reaches threshold. Single-threaded test use (no mutex).
type countingLockout struct {
	failures  map[string]int
	threshold int
}

func (c *countingLockout) IsLocked(_ context.Context, key string) (bool, time.Time, error) {
	if c.failures[key] >= c.threshold {
		return true, time.Now().Add(time.Hour), nil
	}
	return false, time.Time{}, nil
}

func (c *countingLockout) RegisterFailure(_ context.Context, key string) (bool, time.Time, error) {
	c.failures[key]++
	if c.failures[key] >= c.threshold {
		return true, time.Now().Add(time.Hour), nil
	}
	return false, time.Time{}, nil
}

func (c *countingLockout) RegisterSuccess(_ context.Context, key string) error {
	delete(c.failures, key)
	return nil
}

// TestMFA_SecondFactorLockout guards that the MFA second factor is throttled:
// without it, an attacker who knows the password could brute-force a 6-digit OTP
// by minting a fresh single-use challenge per guess. After the threshold of
// wrong codes the subject is locked, and even a CORRECT code is rejected.
func TestMFA_SecondFactorLockout(t *testing.T) {
	lock := &countingLockout{failures: map[string]int{}, threshold: 3}
	srv, _, secret := buildMFAHarness(t, sso.WithAccountLockout(lock))

	valid := validTOTPCode(t, secret)
	wrong := "000000"
	if wrong == valid {
		wrong = "111111"
	}

	// Each guess needs a fresh challenge (single-use), so re-login each time.
	for i := 0; i < 3; i++ {
		_, body := loginMFA(t, srv)
		chal, _ := body["mfa_challenge_id"].(string)
		if chal == "" {
			t.Fatalf("attempt %d: no challenge: %v", i, body)
		}
		status, mbody := completeMFA(t, srv, chal, authenticators.MethodTOTP, wrong)
		if status != http.StatusBadRequest || mbody["error"] != sso.ErrMFAInvalid {
			t.Fatalf("attempt %d: status=%d body=%v, want 400 mfa_invalid", i, status, mbody)
		}
	}

	// Locked now (3 failures on mfa:alice). A CORRECT code MUST still be rejected.
	_, body := loginMFA(t, srv)
	chal, _ := body["mfa_challenge_id"].(string)
	status, mbody := completeMFA(t, srv, chal, authenticators.MethodTOTP, validTOTPCode(t, secret))
	if status != http.StatusBadRequest || mbody["error"] != sso.ErrMFAInvalid {
		t.Errorf("locked subject + correct code: status=%d body=%v, want 400 mfa_invalid (brute-force not throttled)", status, mbody)
	}
	if lock.failures["mfa lockout:alice"] < 3 {
		t.Errorf("MFA failures not registered on the namespaced key: %d", lock.failures["mfa lockout:alice"])
	}
}

// TestMFA_EmailVerificationGate_BlocksUnverified is a regression test for the
// MFA step-up bypass that existed before the rejectUnverifiedEmail call was
// added to resumeLoginAfterMFA. When signupRequireVerification is true, a user
// who has NOT set email_verified="true" must be blocked at MFA completion —
// not at /auth/login (where the gate cannot fire, because MFA completion hasn't
// happened yet) but at POST /auth/mfa. buildMFAHarness creates alice without
// email_verified, so no special setup is required.
func TestMFA_EmailVerificationGate_BlocksUnverified(t *testing.T) {
	srv, _, secret := buildMFAHarness(t, sso.WithSignupRequireVerification(true))

	status, body := loginMFA(t, srv)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (mfa_required is success-shaped); body=%v", status, body)
	}
	if body["error"] != sso.ErrMFARequired {
		t.Errorf("error = %v, want mfa_required", body["error"])
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("mfa_challenge_id missing; body=%v", body)
	}

	code := validTOTPCode(t, secret)
	status, body = completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusForbidden {
		t.Errorf("MFA completion for unverified user: status = %d, want 403; body=%v", status, body)
	}
	if body["error"] != sso.ErrEmailNotVerified {
		t.Errorf("error = %v, want %v", body["error"], sso.ErrEmailNotVerified)
	}
}

// TestMFA_EmailVerificationGate_FailClosedOnMissingUser proves the
// fail-closed branch of rejectUnverifiedEmail: when the user is deleted
// from the UserProvider between MFA challenge issuance and completion,
// GetByID returns (nil, nil) — the gate must reject with 403
// email_not_verified, NOT pass through (which was the pre-R24 behavior).
func TestMFA_EmailVerificationGate_FailClosedOnMissingUser(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	srv, _, secret := buildMFAHarness(t,
		sso.WithSignupRequireVerification(true),
		sso.WithUserProvider(users), // override default provider so we can delete alice
	)

	status, body := loginMFA(t, srv)
	if status != http.StatusOK {
		t.Fatalf("login status = %d want 200; body=%v", status, body)
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("mfa_challenge_id missing; body=%v", body)
	}

	// Delete alice between challenge issuance and completion.
	if err := users.Delete(context.Background(), "alice"); err != nil {
		t.Fatalf("delete alice: %v", err)
	}

	code := validTOTPCode(t, secret)
	status, body = completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusForbidden {
		t.Errorf("MFA for deleted user: status = %d, want 403 (fail-closed); body=%v", status, body)
	}
	if body["error"] != sso.ErrEmailNotVerified {
		t.Errorf("error = %v, want %v", body["error"], sso.ErrEmailNotVerified)
	}
}

// TestMFA_DeactivatedUserDuringChallenge_Blocks is a regression test for a
// TOCTOU gap: resumeLoginAfterMFA re-validates the CLIENT (deactivated /
// tenant-suspended) between challenge issuance and completion, but never
// re-checked the USER's SCIM active flag. An admin/SCIM connector that
// PATCHes a user to active=false in the window between the primary
// credential leg (/auth/login, which DOES call rejectDeactivatedUser) and
// the completed MFA challenge (/auth/mfa, a separate request, possibly
// minutes later per the challenge TTL) must still have that revocation
// honored — tokens must not be minted for a user who is no longer active
// by the time the second factor completes.
func TestMFA_DeactivatedUserDuringChallenge_Blocks(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	srv, _, secret := buildMFAHarness(t, sso.WithUserProvider(users))

	status, body := loginMFA(t, srv)
	if status != http.StatusOK {
		t.Fatalf("login status = %d want 200; body=%v", status, body)
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("mfa_challenge_id missing; body=%v", body)
	}

	// Deactivate alice (SCIM active=false) between challenge issuance and
	// completion -- simulates an admin/connector revoking access mid-flow.
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID:         "alice",
		Attributes: map[string]string{core.UserAttrActive: core.UserAttrInactive},
	})

	code := validTOTPCode(t, secret)
	status, body = completeMFA(t, srv, chal, authenticators.MethodTOTP, code)
	if status != http.StatusForbidden {
		t.Fatalf("MFA completion for deactivated user: status = %d, want 403 (account_locked); body=%v", status, body)
	}
	if body["error"] != sso.ErrAccountLocked {
		t.Errorf("error = %v, want %v", body["error"], sso.ErrAccountLocked)
	}
	if body["access_token"] != nil {
		t.Errorf("deactivated user obtained a token via MFA resume: %v", body)
	}
}
