package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// rotatingIssuer is the rotation surface both the ECDSA and RSA issuers
// expose, so one test drives both.
type rotatingIssuer interface {
	KeyID() string
	JWKS(context.Context) ([]sso.JWK, error)
	StartRotation(context.Context, defaultimpl.RotationConfig) <-chan struct{}
}

// TestStartRotation_MultiAlg_RotatesAndRetires drives the ES256 and RSA
// schedulers: each must rotate (new kid != seed), invoke OnRotate, and
// retire the demoted key from JWKS after the grace period, then stop on
// ctx cancel. RSA uses longer intervals (key generation is slower).
func TestStartRotation_MultiAlg_RotatesAndRetires(t *testing.T) {
	cases := []struct {
		name            string
		issuer          rotatingIssuer
		interval, grace time.Duration
	}{
		{"ES256", defaultimpl.NewECDSAJWTIssuer(), 15 * time.Millisecond, 20 * time.Millisecond},
		{"RS256", defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("RS256")), 60 * time.Millisecond, 40 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seedKID := tc.issuer.KeyID()
			rotated := make(chan [2]string, 4)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := tc.issuer.StartRotation(ctx, defaultimpl.RotationConfig{
				Interval:    tc.interval,
				GracePeriod: tc.grace,
				OnRotate:    func(o, n string) { rotated <- [2]string{o, n} },
			})

			var first [2]string
			select {
			case first = <-rotated:
			case <-time.After(3 * time.Second):
				t.Fatal("no rotation observed")
			}
			if first[0] != seedKID {
				t.Errorf("first oldKID = %q, want seed %q", first[0], seedKID)
			}
			if first[0] == first[1] {
				t.Fatal("rotation produced identical kids")
			}

			deadline := time.Now().Add(3 * time.Second)
			for {
				jwks, _ := tc.issuer.JWKS(ctx)
				present := false
				for _, k := range jwks {
					if k.Kid == seedKID {
						present = true
					}
				}
				if !present {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("demoted seed key never retired from JWKS")
				}
				time.Sleep(5 * time.Millisecond)
			}

			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("rotation loop did not stop on ctx cancel")
			}
		})
	}
}

// TestStartRotation_MultiAlg_DisabledWhenIntervalZero proves a zero
// interval is a no-op returning an already-closed channel for both.
func TestStartRotation_MultiAlg_DisabledWhenIntervalZero(t *testing.T) {
	for name, iss := range map[string]rotatingIssuer{
		"ES256": defaultimpl.NewECDSAJWTIssuer(),
		"RS256": defaultimpl.NewRSAJWTIssuer(),
	} {
		done := iss.StartRotation(context.Background(), defaultimpl.RotationConfig{Interval: 0})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("%s: zero-interval StartRotation must return a closed channel", name)
		}
	}
}
