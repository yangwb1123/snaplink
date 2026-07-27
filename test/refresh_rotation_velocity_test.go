package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const (
	rvClientID = "rv-client"
	rvSecret   = "rv-secret"
	rvUser     = "u-rv"
)

// failingRotationLimiter wraps the real MemoryRefreshTokenStore and makes
// RecordRotation always return an error — to prove the handler's FAIL-OPEN
// contract (a limiter store error must NOT block a legitimate refresh nor
// kill the family). It is NOT a mock of an existing impl: there is no
// in-memory store that errors on RecordRotation, so this thin decorator over
// the real store is the only way to exercise the availability path (§8
// permits this — every storage method below delegates to the real store).
type failingRotationLimiter struct {
	*defaultimpl.MemoryRefreshTokenStore
}

func (f *failingRotationLimiter) RecordRotation(context.Context, string) (int, bool, error) {
	return 0, false, errors.New("simulated limiter store outage")
}

var _ oauth.RefreshTokenRotationLimiter = (*failingRotationLimiter)(nil)

// newRotationVelocityHarness builds a /token server whose refresh-token
// store is `store`. Pass a *MemoryRefreshTokenStore with the velocity cap
// pre-configured, or a failingRotationLimiter, or a plain store (no limiter).
func newRotationVelocityHarness(t *testing.T, store oauth.RefreshTokenStore) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rvUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rvClientID, Secret: rvSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rvUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srv := sso.NewServer(
		sso.WithAuditRecorder(rec),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func rvLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body := `{"provider":"password","client_id":"` + rvClientID +
		`","credential":{"username":"x","password":"y"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := jsonDecodeRespBody(resp)
	r, _ := out["refresh_token"].(string)
	if r == "" {
		t.Fatalf("no refresh_token: %v", out)
	}
	return r
}

// rvRotateRaw rotates `refresh` and returns the status + RAW response body
// bytes (so callers can assert byte-identical wire shapes).
func rvRotateRaw(t *testing.T, srv *httptest.Server, refresh string) (int, []byte) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {rvClientID},
		"client_secret": {rvSecret},
		"refresh_token": {refresh},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func rvRefreshFrom(t *testing.T, status int, raw []byte) string {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("rotation status=%d body=%s", status, raw)
	}
	out := decodeJSONBytes(t, raw)
	r, _ := out["refresh_token"].(string)
	if r == "" {
		t.Fatalf("no refresh_token in rotation body: %s", raw)
	}
	return r
}

// ---------- under the cap: normal rotation, no kill ----------

func TestRotationVelocity_UnderCap_NormalRotation(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	store.MaxRotationsPerWindow = 5
	store.RotationWindow = time.Hour
	srv, sink := newRotationVelocityHarness(t, store)

	refresh := rvLogin(t, srv)
	// Rotate 4 times (under the cap of 5) — each succeeds, no family kill.
	for i := 0; i < 4; i++ {
		status, raw := rvRotateRaw(t, srv, refresh)
		refresh = rvRefreshFrom(t, status, raw)
	}
	// No velocity audit event must have fired.
	if hasVelocityEvent(sink) {
		t.Error("velocity event fired under the cap")
	}
	// The latest token still works.
	status, raw := rvRotateRaw(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("5th rotation should still work: status=%d body=%s", status, raw)
	}
}

// ---------- over the cap: oracle-leak collapse + family kill ----------

func TestRotationVelocity_OverCap_KillsFamily_OracleSafe(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	store.MaxRotationsPerWindow = 2
	store.RotationWindow = time.Hour
	srv, sink := newRotationVelocityHarness(t, store)

	refresh := rvLogin(t, srv)
	// Capture the rotated leaf at the cap boundary so we can prove the
	// whole family dies, not just the presented token.
	status, raw := rvRotateRaw(t, srv, refresh) // rotation #1 (count=1, ok)
	refresh = rvRefreshFrom(t, status, raw)
	status, raw = rvRotateRaw(t, srv, refresh) // rotation #2 (count=2, at cap, ok)
	survivor := rvRefreshFrom(t, status, raw)

	// rotation #3 (count=3 > cap=2) → velocity exceeded → family killed +
	// invalid_grant.
	velStatus, velBody := rvRotateRaw(t, srv, survivor)
	if velStatus != http.StatusBadRequest {
		t.Fatalf("velocity-exceeded status=%d want 400 (body=%s)", velStatus, velBody)
	}

	// ORACLE-LEAK GATE: the velocity-exceeded body MUST be byte-identical
	// to a vanilla bad-refresh invalid_grant. Build a control on a fresh
	// server (so its store is untouched) and compare raw bytes.
	ctrlStore := defaultimpl.NewMemoryRefreshTokenStore()
	ctrlSrv, _ := newRotationVelocityHarness(t, ctrlStore)
	ctrlStatus, ctrlBody := rvRotateRaw(t, ctrlSrv, "this-token-was-never-issued")
	if ctrlStatus != velStatus {
		t.Errorf("status mismatch: velocity=%d bad-refresh=%d", velStatus, ctrlStatus)
	}
	if string(velBody) != string(ctrlBody) {
		t.Errorf("ORACLE LEAK: velocity body %q != bad-refresh body %q", velBody, ctrlBody)
	}
	// And the body must not leak any rate/velocity/family hint.
	for _, banned := range []string{"rate", "velocity", "family", "Retry-After", "window"} {
		if strings.Contains(strings.ToLower(string(velBody)), strings.ToLower(banned)) {
			t.Errorf("velocity body leaks %q: %s", banned, velBody)
		}
	}

	// FAMILY KILLED: the survivor (the descendant the attacker held) must
	// now be dead — Consume returns not-found, not the rotation grant.
	if _, err := store.Consume(context.Background(), survivor); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("family survived velocity revocation: err=%v", err)
	}

	// AUDIT: the velocity event fired with Outcome=failure + count metadata.
	ev := findVelocityEvent(sink)
	if ev == nil {
		t.Fatal("expected refresh_rotation_velocity_exceeded audit event")
	}
	if ev.Outcome != audit.OutcomeFailure {
		t.Errorf("velocity event outcome=%q want failure", ev.Outcome)
	}
	if ev.Metadata["count"] == "" {
		t.Error("expected count in velocity event metadata")
	}
}

// ---------- fail-open: a limiter store error must not block the refresh ----------

func TestRotationVelocity_LimiterError_FailsOpen(t *testing.T) {
	inner := defaultimpl.NewMemoryRefreshTokenStore()
	// Configure a cap so the handler WOULD act on an exceed — but the
	// limiter errors before it can, and the rotation must still succeed.
	inner.MaxRotationsPerWindow = 1
	inner.RotationWindow = time.Hour
	store := &failingRotationLimiter{MemoryRefreshTokenStore: inner}
	srv, sink := newRotationVelocityHarness(t, store)

	refresh := rvLogin(t, srv)
	// Rotate several times past the configured cap — every rotation must
	// succeed because RecordRotation errors (fail-open), so the family is
	// never killed.
	for i := 0; i < 5; i++ {
		status, raw := rvRotateRaw(t, srv, refresh)
		if status != http.StatusOK {
			t.Fatalf("rotation %d blocked despite fail-open: status=%d body=%s", i, status, raw)
		}
		refresh = rvRefreshFrom(t, status, raw)
	}
	// No velocity event — the cap was never enforced.
	if hasVelocityEvent(sink) {
		t.Error("velocity event fired despite limiter error (should fail-open)")
	}
	// The family is alive: the latest token still rotates.
	status, _ := rvRotateRaw(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("family was killed on a fail-open path: status=%d", status)
	}
}

// ---------- nil/unconfigured limiter: byte-identical to today ----------

func TestRotationVelocity_NoLimit_ByteIdentical(t *testing.T) {
	// A store WITHOUT the velocity cap configured must behave exactly like
	// the pre-feature build: unlimited rotations, no velocity event.
	store := defaultimpl.NewMemoryRefreshTokenStore() // no cap/window
	srv, sink := newRotationVelocityHarness(t, store)

	refresh := rvLogin(t, srv)
	for i := 0; i < 20; i++ {
		status, raw := rvRotateRaw(t, srv, refresh)
		if status != http.StatusOK {
			t.Fatalf("rotation %d failed on an unconfigured limiter: status=%d body=%s", i, status, raw)
		}
		refresh = rvRefreshFrom(t, status, raw)
	}
	if hasVelocityEvent(sink) {
		t.Error("velocity event fired with no cap configured")
	}
}

// ---------- helpers ----------

func decodeJSONBytes(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode json %q: %v", raw, err)
	}
	return out
}

func findVelocityEvent(sink *audit.MemorySink) *audit.Event {
	events, _ := sink.Query(context.Background(), audit.Query{})
	for _, e := range events {
		if e.Type == audit.EventRefreshRotationVelocityExceeded {
			return e
		}
	}
	return nil
}

func hasVelocityEvent(sink *audit.MemorySink) bool {
	return findVelocityEvent(sink) != nil
}
