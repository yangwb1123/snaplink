package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// slowNotifier sleeps `delay` before recording the call. Used to
// prove the multi-RP fan-out runs concurrently rather than serially.
type slowNotifier struct {
	mu              sync.Mutex
	calls           []string
	delay           time.Duration
	maxConcurrent   atomic.Int32
	currentInFlight atomic.Int32
}

func (s *slowNotifier) Notify(_ context.Context, uri string, _ string) error {
	cur := s.currentInFlight.Add(1)
	defer s.currentInFlight.Add(-1)
	for {
		hi := s.maxConcurrent.Load()
		if cur <= hi || s.maxConcurrent.CompareAndSwap(hi, cur) {
			break
		}
	}
	time.Sleep(s.delay)
	s.mu.Lock()
	s.calls = append(s.calls, uri)
	s.mu.Unlock()
	return nil
}

const (
	bclParUser   = "u-par"
	bclParSecret = "par-secret"
	bclParPasswd = "par-pw"
)

func newParallelBCLHarness(t *testing.T, numRPs int, notifier sso.LogoutNotifier) (*httptest.Server, string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: bclParUser})
	clients := defaultimpl.NewMemoryClientStore()
	for i := 0; i < numRPs; i++ {
		clients.AddSeed(&sso.Client{
			ID: fmt.Sprintf("par-client-%d", i), Secret: bclParSecret, Active: true,
			AllowedAuthenticators: []string{"password"},
			TokenStrategy:         "jwt",
			BackchannelLogoutURI:  fmt.Sprintf("https://rp-%d.example/bc-logout", i),
		})
	}
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != bclParPasswd {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: bclParUser}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	idx := defaultimpl.NewMemorySubjectClientIndex()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		sso.WithSubjectClientIndex(idx),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Log into every RP so the security.SubjectClientIndex has the full set.
	var firstTok string
	for i := 0; i < numRPs; i++ {
		clientID := fmt.Sprintf("par-client-%d", i)
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  clientID,
			"credential": map[string]string{"username": bclParUser, "password": bclParPasswd},
		})
		resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login %d empty token: %s", i, raw)
		}
		if i == 0 {
			firstTok = tok
		}
	}
	return httpSrv, firstTok
}

func TestBCLFanOut_RunsInParallel(t *testing.T) {
	// 8 RPs, each Notify sleeps 120ms. Serial: 8 × 120ms = 960ms.
	// Parallel (default cap 8): ~120ms. Threshold at 600ms catches
	// the serial regression without being flaky on slow CI.
	notifier := &slowNotifier{delay: 120 * time.Millisecond}
	srv, tok := newParallelBCLHarness(t, 8, notifier)

	start := time.Now()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	elapsed := time.Since(start)

	if elapsed > 600*time.Millisecond {
		t.Errorf("fan-out elapsed %v — likely serial; want < 600ms for 8 parallel RPs", elapsed)
	}
	if got := len(notifier.calls); got != 8 {
		t.Errorf("notified %d RPs, want 8", got)
	}
	if got := notifier.maxConcurrent.Load(); got < 2 {
		t.Errorf("max concurrent notify = %d, want >= 2 to prove parallelism", got)
	}
}

func TestBCLFanOut_BoundedConcurrency(t *testing.T) {
	// 12 RPs but cap at 3 — max in-flight notifications must stay <= 3.
	notifier := &slowNotifier{delay: 80 * time.Millisecond}
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: bclParUser})
	clients := defaultimpl.NewMemoryClientStore()
	for i := 0; i < 12; i++ {
		clients.AddSeed(&sso.Client{
			ID: fmt.Sprintf("bnd-client-%d", i), Secret: bclParSecret, Active: true,
			AllowedAuthenticators: []string{"password"},
			TokenStrategy:         "jwt",
			BackchannelLogoutURI:  fmt.Sprintf("https://bnd-%d.example/bc-logout", i),
		})
	}
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != bclParPasswd {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: bclParUser}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	idx := defaultimpl.NewMemorySubjectClientIndex()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		sso.WithSubjectClientIndex(idx),
		sso.WithBackchannelLogoutMaxConcurrent(3),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	var firstTok string
	for i := 0; i < 12; i++ {
		clientID := fmt.Sprintf("bnd-client-%d", i)
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  clientID,
			"credential": map[string]string{"username": bclParUser, "password": bclParPasswd},
		})
		resp, _ := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if i == 0 {
			firstTok = tok
		}
	}

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+firstTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()

	if got := len(notifier.calls); got != 12 {
		t.Errorf("notified %d RPs, want 12", got)
	}
	if got := notifier.maxConcurrent.Load(); got > 3 {
		t.Errorf("max concurrent = %d, want <= 3 (cap)", got)
	}
}
