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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

// Per-account lockout: distributed-credential-stuffing defense
// that complements the IP-level rate limit. Wired via
// WithAccountLockout; off by default for backward compatibility.

const (
	lkUser     = "u-lk"
	lkClient   = "lk-client"
	lkBadPass  = "wrong"
	lkGoodPass = "right"
)

// pkgLevelLockout: exercise the security.MemoryAccountLockout impl
// directly to lock in the threshold + sliding-window semantics
// independent of the server wire-up.

func TestMemoryAccountLockout_LocksAtThreshold(t *testing.T) {
	a := security.NewMemoryAccountLockout()
	a.MaxFailures = 3
	a.LockoutDuration = 50 * time.Millisecond

	ctx := context.Background()
	// First 2 failures stay unlocked.
	for i := 0; i < a.MaxFailures-1; i++ {
		locked, _, err := a.RegisterFailure(ctx, "k")
		if err != nil {
			t.Fatalf("RegisterFailure[%d]: %v", i, err)
		}
		if locked {
			t.Errorf("locked too early at attempt %d", i+1)
		}
	}
	// Threshold-crossing failure engages the lock.
	locked, until, _ := a.RegisterFailure(ctx, "k")
	if !locked {
		t.Fatal("expected lock at threshold")
	}
	if until.IsZero() || time.Until(until) <= 0 {
		t.Errorf("until = %v should be in the future", until)
	}

	// IsLocked agrees.
	if l, _, _ := a.IsLocked(ctx, "k"); !l {
		t.Error("IsLocked should report true while engaged")
	}
}

func TestMemoryAccountLockout_AutoUnlocksAfterDuration(t *testing.T) {
	a := security.NewMemoryAccountLockout()
	a.MaxFailures = 2
	a.LockoutDuration = 20 * time.Millisecond

	ctx := context.Background()
	_, _, _ = a.RegisterFailure(ctx, "k")
	locked, _, _ := a.RegisterFailure(ctx, "k")
	if !locked {
		t.Fatal("expected lock")
	}
	time.Sleep(30 * time.Millisecond)
	if l, _, _ := a.IsLocked(ctx, "k"); l {
		t.Error("lock should have auto-expired")
	}
}

func TestMemoryAccountLockout_SuccessResets(t *testing.T) {
	a := security.NewMemoryAccountLockout()
	a.MaxFailures = 3

	ctx := context.Background()
	_, _, _ = a.RegisterFailure(ctx, "k")
	_, _, _ = a.RegisterFailure(ctx, "k")

	// One success → counter back to 0.
	if err := a.RegisterSuccess(ctx, "k"); err != nil {
		t.Fatalf("RegisterSuccess: %v", err)
	}

	// Now we should be able to fail 2 more times without lock.
	for i := 0; i < 2; i++ {
		if locked, _, _ := a.RegisterFailure(ctx, "k"); locked {
			t.Errorf("locked after success-reset at attempt %d", i+1)
		}
	}
}

func TestMemoryAccountLockout_EmptyKeyNoop(t *testing.T) {
	// Empty key = "unkeyable" — server should fall back to the
	// other defenses (rate limit). The lockout impl returns
	// not-locked + no-counter-increment.
	a := security.NewMemoryAccountLockout()
	ctx := context.Background()
	locked, _, _ := a.RegisterFailure(ctx, "")
	if locked {
		t.Errorf("empty key should not lock")
	}
	if l, _, _ := a.IsLocked(ctx, ""); l {
		t.Errorf("empty key should not be locked")
	}
}

func TestMemoryAccountLockout_DistinctKeysIsolated(t *testing.T) {
	// Two different keys MUST maintain independent counters —
	// otherwise a single attacker target could lock out unrelated
	// accounts.
	a := security.NewMemoryAccountLockout()
	a.MaxFailures = 2
	ctx := context.Background()
	_, _, _ = a.RegisterFailure(ctx, "alice")
	_, _, _ = a.RegisterFailure(ctx, "alice")
	if l, _, _ := a.IsLocked(ctx, "alice"); !l {
		t.Fatal("alice should be locked")
	}
	if l, _, _ := a.IsLocked(ctx, "bob"); l {
		t.Error("bob must NOT be locked just because alice is")
	}
}

// Server wire-up tests: drive /auth/login against a real Server
// with WithAccountLockout enabled and assert the wire behavior.

type lockoutHarness struct {
	srv *httptest.Server
	a   *security.MemoryAccountLockout
	rec *audit.MemorySink
}

func newLockoutHarness(t *testing.T) *lockoutHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: lkUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: lkClient, Secret: "lk-secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p == lkGoodPass {
				return &sso.AuthResult{UserID: lkUser}, nil
			}
			return nil, errors.New("bad")
		},
	))
	a := security.NewMemoryAccountLockout()
	a.MaxFailures = 3
	a.LockoutDuration = time.Minute
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAccountLockout(a),
		sso.WithAuditRecorder(rec),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &lockoutHarness{srv: httpSrv, a: a, rec: sink}
}

func (h *lockoutHarness) attempt(t *testing.T, username, password string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  lkClient,
		"credential": map[string]string{"username": username, "password": password},
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestLockout_ThirdBadLoginLocksAccount(t *testing.T) {
	h := newLockoutHarness(t)
	// 2 failures, still invalid_credentials.
	for i := 0; i < 2; i++ {
		status, body := h.attempt(t, "alice", lkBadPass)
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%v want 401", i+1, status, body)
		}
		if body["error"] != "invalid_credentials" {
			t.Errorf("attempt %d error = %v", i+1, body["error"])
		}
	}
	// 3rd failure crosses MaxFailures=3 and engages lock.
	status, body := h.attempt(t, "alice", lkBadPass)
	if status != http.StatusForbidden {
		t.Fatalf("3rd attempt status=%d body=%v want 403", status, body)
	}
	if body["error"] != "account_locked" {
		t.Errorf("3rd attempt error = %v want account_locked", body["error"])
	}
}

func TestLockout_BlocksLegitLoginWhileLocked(t *testing.T) {
	h := newLockoutHarness(t)
	// Burn through threshold with bad password.
	for i := 0; i < 3; i++ {
		_, _ = h.attempt(t, "alice", lkBadPass)
	}
	// Even with the right password now, account is locked.
	status, body := h.attempt(t, "alice", lkGoodPass)
	if status != http.StatusForbidden {
		t.Fatalf("status=%d body=%v want 403 (locked must override valid credential)", status, body)
	}
	if body["error"] != "account_locked" {
		t.Errorf("error = %v want account_locked", body["error"])
	}
}

func TestLockout_SuccessfulLoginClearsCounter(t *testing.T) {
	h := newLockoutHarness(t)
	// 2 failures (one below threshold).
	for i := 0; i < 2; i++ {
		_, _ = h.attempt(t, "alice", lkBadPass)
	}
	// A successful login resets the counter.
	status, _ := h.attempt(t, "alice", lkGoodPass)
	if status != http.StatusOK {
		t.Fatalf("good login status=%d want 200", status)
	}
	// 2 more failures (would have crossed the old counter to
	// 4 = locked, but counter was reset, so we're back at 2).
	for i := 0; i < 2; i++ {
		status, body := h.attempt(t, "alice", lkBadPass)
		if status != http.StatusUnauthorized {
			t.Fatalf("post-reset failure status=%d body=%v want 401 (still under threshold)", status, body)
		}
	}
}

func TestLockout_DifferentUsersIsolated(t *testing.T) {
	h := newLockoutHarness(t)
	// Burn through alice.
	for i := 0; i < 3; i++ {
		_, _ = h.attempt(t, "alice", lkBadPass)
	}
	// bob should be untouched.
	status, body := h.attempt(t, "bob", lkGoodPass)
	if status != http.StatusOK {
		t.Fatalf("bob status=%d body=%v want 200", status, body)
	}
}

func TestLockout_AuditEventEmitted(t *testing.T) {
	h := newLockoutHarness(t)
	for i := 0; i < 3; i++ {
		_, _ = h.attempt(t, "alice", lkBadPass)
	}
	events, _ := h.rec.Query(context.Background(), audit.Query{Type: audit.EventAccountLocked})
	if len(events) == 0 {
		t.Fatal("expected at least one account_locked audit event")
	}
	first := events[0]
	if first.Outcome != audit.OutcomeFailure {
		t.Errorf("Outcome = %v want failure", first.Outcome)
	}
	if first.ClientID != lkClient {
		t.Errorf("ClientID = %q want %q", first.ClientID, lkClient)
	}
	// Lockout key = clientID:identifier — both pivot axes for SIEM.
	if first.ActorID != lkClient+":alice" {
		t.Errorf("ActorID = %q want %q", first.ActorID, lkClient+":alice")
	}
	if first.Metadata["until"] == "" {
		t.Errorf("until metadata missing")
	}
}

func TestLockout_OffByDefault(t *testing.T) {
	// Without WithAccountLockout, repeated bad attempts must NOT
	// flip to 403/account_locked — pre-existing behavior.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: lkUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: lkClient, Secret: "x", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return nil, errors.New("bad")
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	for i := 0; i < 10; i++ {
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  lkClient,
			"credential": map[string]string{"username": "alice", "password": "x"},
		})
		resp, _ := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if resp.StatusCode != http.StatusUnauthorized {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("attempt %d status=%d body=%s want 401 (lockout off)", i+1, resp.StatusCode, raw)
		}
		resp.Body.Close()
	}
}
