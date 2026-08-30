package defaulttoken

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

type sweepTestEntry struct {
	expiresAt time.Time
}

func TestSweepExpired_StrictBoundary(t *testing.T) {
	now := time.Now()
	var tokens sync.Map
	tokens.Store("expired", &sweepTestEntry{expiresAt: now.Add(-time.Nanosecond)})
	tokens.Store("boundary", &sweepTestEntry{expiresAt: now})
	tokens.Store("live", &sweepTestEntry{expiresAt: now.Add(time.Nanosecond)})

	sweepExpired(&tokens, now, func(value any) time.Time {
		return value.(*sweepTestEntry).expiresAt
	})

	if _, ok := tokens.Load("expired"); ok {
		t.Error("strictly expired entry remains")
	}
	for _, key := range []string{"boundary", "live"} {
		if _, ok := tokens.Load(key); !ok {
			t.Errorf("entry %q was swept", key)
		}
	}
}

func TestIssuersConcurrentIssueValidateRevoke(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		issuer core.TokenIssuer
	}{
		{name: "jwt", issuer: NewJWTIssuer(WithJWTTokenTTL(time.Hour))},
		{name: "session", issuer: NewSessionTokenIssuer(WithSessionTokenTTL(time.Hour))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var wg sync.WaitGroup
			for worker := range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range 40 {
						subject := &core.Subject{ID: fmt.Sprintf("%s-%d-%d", tc.name, worker, i)}
						tok, err := tc.issuer.Issue(context.Background(), subject, nil)
						if err != nil {
							t.Errorf("Issue: %v", err)
							continue
						}
						if _, err := tc.issuer.Validate(context.Background(), tok.AccessToken); err != nil {
							t.Errorf("Validate: %v", err)
						}
						if err := tc.issuer.Revoke(context.Background(), tok.AccessToken); err != nil {
							t.Errorf("Revoke: %v", err)
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
