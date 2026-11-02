package rs_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

type revocationContextKey struct{}

func TestRevocationCheck_CanceledBeforeValidation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%v", mode, deadline), func(t *testing.T) {
				token, cfg := revocationFixture(t, mode, nil)
				if _, err := validateRevocationFixture(context.Background(), token, cfg); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				}
				cancel()
				calls := 0
				cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
					calls++
					return false, nil
				}
				claims, err := validateRevocationFixture(ctx, token, cfg)
				if claims != nil || err == nil || calls != 0 {
					t.Fatalf("canceled context: claims present=%v, err=%v, calls=%d", claims != nil, err, calls)
				}
			})
		}
	}
}

func TestRevocationCheck_ContextAndCancellation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		for _, returnError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/backend_returns_error=%v", mode, returnError), func(t *testing.T) {
				token, cfg := revocationFixture(t, mode, nil)
				valueCtx := context.WithValue(context.Background(), revocationContextKey{}, "request-value")
				ctx, cancel := context.WithTimeout(valueCtx, time.Minute)
				defer cancel()
				calls := 0
				cfg.RevocationCheck = func(got context.Context, _ rs.RevocationToken) (bool, error) {
					calls++
					if got != ctx || got.Value(revocationContextKey{}) != "request-value" {
						t.Error("callback did not receive the caller's context and values")
					}
					wantDeadline, _ := ctx.Deadline()
					if deadline, ok := got.Deadline(); !ok || !deadline.Equal(wantDeadline) {
						t.Errorf("callback deadline = %v/%v, want %v", deadline, ok, wantDeadline)
					}
					cancel()
					if returnError {
						return false, got.Err()
					}
					return false, nil // A backend ignoring cancellation must not admit.
				}
				claims, err := validateRevocationFixture(ctx, token, cfg)
				if claims != nil || err != rs.ErrTokenInactive || calls != 1 {
					t.Fatalf("claims present=%v, err=%v, calls=%d; want nil/ErrTokenInactive/1", claims != nil, err, calls)
				}
			})
		}
	}
}

func TestRevocationCheck_BackendWaitsForContext(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			entered, finished := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(finished)
				select {
				case <-entered:
					cancel()
				case <-ctx.Done():
				}
			}()
			defer func() { cancel(); <-finished }()
			calls := 0
			cfg.RevocationCheck = func(got context.Context, _ rs.RevocationToken) (bool, error) {
				calls++
				close(entered)
				<-got.Done()
				return false, got.Err()
			}
			claims, err := validateRevocationFixture(ctx, token, cfg)
			if claims != nil || err != rs.ErrTokenInactive || calls != 1 {
				t.Fatalf("claims present=%v, err=%v, calls=%d; want canceled backend refusal", claims != nil, err, calls)
			}
		})
	}
}

func TestRevocationCheck_ConcurrentCalls(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, nil)
			if _, err := validateRevocationFixture(context.Background(), token, cfg); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			want := rs.RevocationToken{Issuer: cfg.Issuer, TenantID: "tenant-1", ClientID: "client-1", JTI: "token-1"}
			var calls atomic.Int64
			cfg.RevocationCheck = func(got context.Context, value rs.RevocationToken) (bool, error) {
				calls.Add(1)
				if got != ctx || value != want {
					return false, fmt.Errorf("unexpected context or namespace: %+v", value)
				}
				value.TenantID, value.ClientID, value.JTI = "changed", "changed", "changed"
				return false, nil
			}
			const workers = 24
			results := make(chan error, workers)
			var wg sync.WaitGroup
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					claims, err := validateRevocationFixture(ctx, token, cfg)
					if err == nil && (claims == nil || claims.TenantID != want.TenantID || claims.ClientID != want.ClientID || claims.JTI != want.JTI) {
						err = fmt.Errorf("callback changed claims: %+v", claims)
					}
					results <- err
				}()
			}
			wg.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Error(err)
				}
			}
			if got := calls.Load(); got != workers {
				t.Errorf("callback calls = %d, want %d (no callback verdict cache)", got, workers)
			}
		})
	}
}

func TestRevocationCheck_FullNamespaceIsolation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			iss := newTestIssuer(t)
			baseCfg := newTestConfig(t, iss, "api://orders")
			revoked := rs.RevocationToken{Issuer: iss.URL(), TenantID: "tenant-1", ClientID: "client-1", JTI: "same-jti"}
			namespaces := []rs.RevocationToken{
				revoked,
				{Issuer: revoked.Issuer, TenantID: "tenant-2", ClientID: revoked.ClientID, JTI: revoked.JTI},
				{Issuer: revoked.Issuer, TenantID: revoked.TenantID, ClientID: "client-2", JTI: revoked.JTI},
				{Issuer: "https://other-issuer.test", TenantID: revoked.TenantID, ClientID: revoked.ClientID, JTI: revoked.JTI},
				{Issuer: revoked.Issuer, TenantID: revoked.TenantID, ClientID: revoked.ClientID, JTI: "other-jti"},
			}
			for _, want := range namespaces {
				values := map[string]any{
					"active": true, "iss": want.Issuer, "tenant_id": want.TenantID,
					"client_id": want.ClientID, "jti": want.JTI,
					"aud": "api://orders", "exp": time.Now().Add(time.Hour).Unix(),
				}
				cfg := baseCfg
				cfg.Issuer = want.Issuer
				token := "opaque-token"
				if mode == "local" {
					var err error
					token, err = iss.MintAccessToken(values)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					srv := introspectServer(t, "rs-client", "rs-secret", values)
					cfg.IntrospectURL = srv.URL
					cfg.IntrospectCreds = &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"}
				}
				calls := 0
				cfg.RevocationCheck = func(_ context.Context, got rs.RevocationToken) (bool, error) {
					calls++
					if got != want {
						t.Errorf("namespace = %+v, want %+v", got, want)
					}
					return got == revoked, nil
				}
				claims, err := validateRevocationFixture(context.Background(), token, cfg)
				if want == revoked {
					if claims != nil || err != rs.ErrTokenInactive {
						t.Errorf("revoked namespace admitted: claims present=%v, err=%v", claims != nil, err)
					}
				} else if claims == nil || err != nil {
					t.Errorf("unrevoked namespace %+v refused: claims present=%v, err=%v", want, claims != nil, err)
				}
				if calls != 1 {
					t.Errorf("callback calls = %d, want 1", calls)
				}
			}
		})
	}
}
