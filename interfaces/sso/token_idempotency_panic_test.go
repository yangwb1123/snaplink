package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

type panicOnceCache struct {
	core.IdempotentCache
	phase string
	once  atomic.Bool
}

func (c *panicOnceCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if c.phase == "get" && c.once.CompareAndSwap(false, true) {
		panic("test cache get failure")
	}
	return c.IdempotentCache.Get(ctx, key)
}

func (c *panicOnceCache) Set(ctx context.Context, key string, body []byte, ttl time.Duration) error {
	if c.phase == "set" && c.once.CompareAndSwap(false, true) {
		panic("test cache set failure")
	}
	return c.IdempotentCache.Set(ctx, key, body, ttl)
}

type panicOnceIssuer struct {
	core.TokenIssuer
	once atomic.Bool
}

func (i *panicOnceIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	if i.once.CompareAndSwap(false, true) {
		panic("test issuer failure")
	}
	return i.TokenIssuer.Issue(ctx, subject, scopes)
}

func TestClientCredentialsIdempotencyReleasesLockAfterRecoveredPanic(t *testing.T) {
	for _, phase := range []string{"get", "issue", "set"} {
		t.Run(phase, func(t *testing.T) {
			memory := defaultimpl.NewMemoryIdempotentCache(time.Minute)
			t.Cleanup(memory.Close)
			cache := &panicOnceCache{IdempotentCache: memory, phase: phase}
			opts := []sso.Option{sso.WithIdempotentStore(cache)}
			if phase == "issue" {
				issuer := &panicOnceIssuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
				opts = append(opts, sso.WithTokenIssuer("jwt", issuer))
			}
			s := rcovNewServer(t, opts...)
			body, err := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": rcovClient, "client_secret": rcovSecret, "scope": "read"})
			if err != nil {
				t.Fatal(err)
			}
			send := func() int {
				request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(string(body)))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Idempotency-Key", "panic-retry")
				response := httptest.NewRecorder()
				s.srv.Handler().ServeHTTP(response, request)
				return response.Code
			}
			if status := send(); phase != "set" && status != http.StatusInternalServerError {
				t.Fatalf("panic did not reach recovery: %d", status)
			}
			next := make(chan int, 1)
			go func() { next <- send() }()
			select {
			case status := <-next:
				if status != http.StatusOK {
					t.Fatalf("request after recovery = %d", status)
				}
			case <-time.After(time.Second):
				t.Fatal("recovered panic poisoned the idempotency lock")
			}
		})
	}
}
