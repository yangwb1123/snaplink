//go:build chaos

// Package chaostest hosts fault-injection scenarios gated behind the `chaos`
// build tag (docs/expansion-volume2-2026-07-01.md, Direction 5): storage-error
// fail-open/fail-closed paths, panic recovery, and clock-jump resilience.
//
// These scenarios exercise EXISTING seams only — decorator structs that wrap a
// real backend and inject one failure (the same "erroring*Store" pattern used
// throughout test/), or an explicit `now time.Time` parameter a production
// type already accepts. No interface mocks, no new production seams. The tag
// keeps this package (and the fault-injection decorators in it) out of the
// default `go build`/`go test ./...` and the production binary; run it via
// `make chaos-test`, which additionally applies `-race -count=2` so a flaky
// fault-injection ordering surfaces as a failure instead of quietly passing
// once.
package chaostest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security"
)

const (
	jrcClient      = "chaos-jar-client"
	jrcUser        = "u-chaos-jar"
	jrcPassword    = "pw"
	jrcKid         = "chaos-jar-kid"
	jrcASIssuer    = "https://sso.chaos.test"
	jrcRedirectURI = "https://app.example.com/cb"
)

// jrcHarness is a trimmed copy of test/jar_test.go's jarHarness: a full
// AS wired for the RFC 9101 JAR (request=<jwt>) flow. Kept local to this
// package (rather than imported) because test/ is `package ssotest` and its
// _test.go helpers are not importable from another package.
type jrcHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
}

// erroringJTIReplayStore models a transiently-down shared replay backend
// (Redis blip / etcd partition / DB outage): MarkSeen always returns a
// TRANSPORT error, distinct from the replay sentinel (false, nil), which is
// what lets the fail-open/fail-closed policy key on err != nil alone. Mirrors
// test/jti_replay_test.go's decorator of the same name.
type erroringJTIReplayStore struct{}

func (erroringJTIReplayStore) MarkSeen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("jti store: simulated transport failure")
}

var _ security.JTIReplayStore = erroringJTIReplayStore{}

func newJRCHarness(t *testing.T, store security.JTIReplayStore, failClosed bool) *jrcHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jrcUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    jrcClient,
		Secret:                "chaos-jar-secret",
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jrcRedirectURI},
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jrcKid,
			Alg: "EdDSA",
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pwAuth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == jrcUser && p == jrcPassword {
				return &sso.AuthResult{UserID: jrcUser}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))

	opts := []sso.Option{
		sso.WithIssuer(jrcASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithJTIReplayStore(store),
	}
	if failClosed {
		opts = append(opts, sso.WithJTIReplayFailClosed())
	}
	server := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(server.Handler())
	t.Cleanup(httpSrv.Close)
	return &jrcHarness{srv: httpSrv, signKey: priv}
}

func (h *jrcHarness) signJAR(claims map[string]any) string {
	header := map[string]any{"alg": "EdDSA", "typ": "oauth-authz-req+jwt", "kid": jrcKid}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (h *jrcHarness) loginJAR(t *testing.T, jti string) (int, map[string]any) {
	t.Helper()
	now := time.Now().Unix()
	jwt := h.signJAR(map[string]any{
		"iss":                   jrcClient,
		"aud":                   jrcASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"jti":                   jti,
		"client_id":             jrcClient,
		"response_type":         "code",
		"redirect_uri":          jrcRedirectURI,
		"code_challenge":        "chaos-pkce-challenge-0123456789012345678901234",
		"code_challenge_method": "plain",
	})
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jrcClient,
		"credential": map[string]string{"username": jrcUser, "password": jrcPassword},
		"request":    jwt,
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestChaos_JTIReplayStoreError_DefaultFailsOpen proves the AGENTS.md §3
// default (fail-open): while the shared replay backend is transiently down,
// a JAR-carrying login still PROCEEDS instead of locking every client out.
func TestChaos_JTIReplayStoreError_DefaultFailsOpen(t *testing.T) {
	h := newJRCHarness(t, erroringJTIReplayStore{}, false)
	status, body := h.loginJAR(t, "chaos-store-error-open")
	if status != http.StatusOK {
		t.Fatalf("fail-open should proceed despite a store outage; status=%d body=%v", status, body)
	}
}

// TestChaos_JTIReplayStoreError_OptInFailsClosed proves the opt-in policy:
// a store outage is treated AS a replay and rejected, so an attacker probing
// during the outage can't distinguish "store down" from "replay detected".
func TestChaos_JTIReplayStoreError_OptInFailsClosed(t *testing.T) {
	h := newJRCHarness(t, erroringJTIReplayStore{}, true)
	status, _ := h.loginJAR(t, "chaos-store-error-closed")
	if status != http.StatusBadRequest {
		t.Fatalf("fail-closed should reject during a store outage; status=%d want 400", status)
	}
}

// TestChaos_JTIReplayStoreError_ConcurrentFailOpen fires the fail-open
// scenario from many goroutines at once (run with `-race -count=2` via
// `make chaos-test`) — the shared *erroringJTIReplayStore{} carries no state,
// but the SERVER's replay-policy branch and the httptest server it drives
// through must survive concurrent access without a data race or a dropped
// request.
func TestChaos_JTIReplayStoreError_ConcurrentFailOpen(t *testing.T) {
	h := newJRCHarness(t, erroringJTIReplayStore{}, false)
	const n = 16
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			jti := "chaos-concurrent-" + string(rune('a'+i))
			status, _ := h.loginJAR(t, jti)
			statuses[i] = status
		}(i)
	}
	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Errorf("goroutine %d: fail-open should proceed under concurrency; status=%d", i, status)
		}
	}
}
