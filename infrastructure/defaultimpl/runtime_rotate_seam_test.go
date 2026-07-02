package defaultimpl_test

// Runtime rotate SEAM (RotateNow + ScheduleRetire) — the alg-uniform methods
// the admin runtime-rotation API drives. RotateKey's signature differs per alg
// (ed25519.PrivateKey vs *ecdsa.PrivateKey vs *rsa.PrivateKey), so no single Go
// interface can call it; RotateNow wraps RotateKey(nil) with a nullary shape all
// three built-in issuers share. ScheduleRetire is the grace-delayed local retire
// the scheduler does via the unexported scheduleRetire — exported so the runtime
// path arranges the SAME overlap-window drop.

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// runtimeRotatable is the structural seam the cmd orchestration closure asserts
// on the primary JWT issuer. All three built-in algs MUST satisfy it.
type runtimeRotatable interface {
	RotateNow() (string, error)
	ScheduleRetire(kid string, after time.Duration)
	KeyID() string
	RetireKey(kid string) error
	core.JWKSProvider
}

func seamHasKid(t *testing.T, jp core.JWKSProvider, kid string) bool {
	t.Helper()
	jwks, err := jp.JWKS(context.Background())
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

func runtimeRotatableIssuers(t *testing.T) map[string]runtimeRotatable {
	t.Helper()
	return map[string]runtimeRotatable{
		"eddsa": defaultimpl.NewEd25519JWTIssuer(),
		"es256": defaultimpl.NewECDSAJWTIssuer(),
		"rs256": defaultimpl.NewRSAJWTIssuer(),
	}
}

// TestRotateNow_OverlapWindow proves the runtime seam keeps the AGENTS.md §3
// overlap-window contract for every alg: a token minted before RotateNow still
// verifies after it (old key demoted verify-only), and both kids appear in JWKS.
func TestRotateNow_OverlapWindow(t *testing.T) {
	t.Parallel()
	for alg, iss := range runtimeRotatableIssuers(t) {
		t.Run(alg, func(t *testing.T) {
			oldKID := iss.KeyID()
			tok, err := iss.(sso.TokenIssuer).Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
			if err != nil {
				t.Fatalf("issue old: %v", err)
			}
			newKID, err := iss.RotateNow()
			if err != nil {
				t.Fatalf("RotateNow: %v", err)
			}
			if newKID == oldKID {
				t.Fatal("RotateNow produced the same kid")
			}
			if iss.KeyID() != newKID {
				t.Errorf("active kid = %q, want %q", iss.KeyID(), newKID)
			}
			if _, err := iss.(sso.TokenIssuer).Validate(context.Background(), tok.AccessToken); err != nil {
				t.Errorf("old token should still validate during overlap: %v", err)
			}
			if !seamHasKid(t, iss, oldKID) || !seamHasKid(t, iss, newKID) {
				t.Errorf("JWKS missing a kid during overlap (old=%q new=%q)", oldKID, newKID)
			}
		})
	}
}

// TestScheduleRetire_DropsAfterGrace proves ScheduleRetire drops the demoted kid
// only AFTER the grace window (fail-safe overlap), for every alg. Uses a short
// grace + poll rather than a real clock wait.
func TestScheduleRetire_DropsAfterGrace(t *testing.T) {
	t.Parallel()
	for alg, iss := range runtimeRotatableIssuers(t) {
		t.Run(alg, func(t *testing.T) {
			oldKID := iss.KeyID()
			if _, err := iss.RotateNow(); err != nil {
				t.Fatalf("RotateNow: %v", err)
			}
			// Old kid still present immediately after rotation (verify-only).
			if !seamHasKid(t, iss, oldKID) {
				t.Fatal("old kid dropped immediately — overlap window violated")
			}
			iss.ScheduleRetire(oldKID, 40*time.Millisecond)
			// Still present well before grace elapses.
			if !seamHasKid(t, iss, oldKID) {
				t.Fatal("old kid retired before grace — fail-safe violated")
			}
			deadline := time.Now().Add(2 * time.Second)
			for seamHasKid(t, iss, oldKID) {
				if time.Now().After(deadline) {
					t.Fatal("old kid never retired after grace")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

// TestScheduleRetire_ZeroGraceKeepsForever proves grace<=0 never auto-retires
// (the demoted key lingers for a manual RetireKey), matching the scheduler.
func TestScheduleRetire_ZeroGraceKeepsForever(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	oldKID := iss.KeyID()
	if _, err := iss.RotateNow(); err != nil {
		t.Fatalf("RotateNow: %v", err)
	}
	iss.ScheduleRetire(oldKID, 0)
	time.Sleep(30 * time.Millisecond)
	if !seamHasKid(t, iss, oldKID) {
		t.Fatal("grace<=0 must keep the demoted kid until manual retire")
	}
}
