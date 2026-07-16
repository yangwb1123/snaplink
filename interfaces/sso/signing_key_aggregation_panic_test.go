package sso_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/signingkeys"
	signingkeysmemory "github.com/snaplink/sso/platform/signingkeys/memory"
	"github.com/snaplink/sso/shared/core"
)

// panicOnAdoptIssuer wraps a real Ed25519JWTIssuer but panics out of
// AdoptVerifyKey for one specific kid — simulating a bug in a third-party,
// operator-supplied core.TokenIssuer implementation. Every other method
// (Issue/Validate/Revoke/JWKS/DropVerifyKey) delegates to the embedded real
// issuer untouched.
type panicOnAdoptIssuer struct {
	*defaultimpl.Ed25519JWTIssuer
	panicKid string
}

func (p *panicOnAdoptIssuer) AdoptVerifyKey(kid string, pub ed25519.PublicKey) error {
	if kid == p.panicKid {
		panic("simulated AdoptVerifyKey panic from a buggy peer-key adoption plugin")
	}
	return p.Ed25519JWTIssuer.AdoptVerifyKey(kid, pub)
}

// TestSigningKeyAggregationSurvivesAdoptVerifyKeyPanic proves
// runSigningKeyAggregation's subscriber loop survives a panic raised by a
// pluggable core.TokenIssuer's AdoptVerifyKey instead of letting it escape
// the bare `for evt := range events` loop (which has no recover of its own).
// An unrecovered panic in ANY goroutine is always process-fatal in Go —
// before the applySigningKeyEventSafe fix, this test would abort the entire
// `go test` binary the instant the aggregation loop reached the panicking
// peer announcement; the second, healthy peer's key would never be adopted
// either, because the whole process would already be gone.
func TestSigningKeyAggregationSurvivesAdoptVerifyKeyPanic(t *testing.T) {
	t.Parallel()
	reg := signingkeysmemory.New()
	defer func() { _ = reg.Close() }()

	// The panicking peer's own key ID is the trigger.
	panicPeer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://panic-peer.example"))
	panicKid := panicPeer.KeyID()

	m := metrics.New()
	local := &panicOnAdoptIssuer{
		Ed25519JWTIssuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example")),
		panicKid:         panicKid,
	}
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, local),
		sso.WithSharedSigningKeyRegistry(reg),
		sso.WithSigningKeyReplicaID("replica-local"),
		sso.WithMetrics(m),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := srv.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Publish the panic-triggering peer announcement first.
	panicJWKS, err := panicPeer.JWKS(ctx)
	if err != nil {
		t.Fatalf("panic peer JWKS: %v", err)
	}
	if err := reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "peer-panic", Keys: panicJWKS}); err != nil {
		t.Fatalf("publish panic peer: %v", err)
	}

	// If the loop crashed the process, nothing below would ever run. Poll for
	// the recover-path metric to confirm the panic was actually hit and
	// contained (not just skipped for some unrelated reason).
	if !waitFor(2*time.Second, func() bool {
		return adoptionErrorTotal(t, m, metrics.AdoptionReasonPanic) >= 1
	}) {
		t.Fatal("expected the recovered-panic path to bump sso_signing_key_adoption_errors_total{reason=panic}")
	}

	// A SECOND, healthy peer announced AFTER the panic must still be adopted
	// — proving the subscriber goroutine kept running (and did not silently
	// die) after recovering from the first peer's panic.
	healthyPeer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://healthy-peer.example"))
	healthyJWKS, err := healthyPeer.JWKS(ctx)
	if err != nil {
		t.Fatalf("healthy peer JWKS: %v", err)
	}
	if err := reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "peer-healthy", Keys: healthyJWKS}); err != nil {
		t.Fatalf("publish healthy peer: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		return jwksHasKidSrv(serverJWKS(t, srv), healthyPeer.KeyID())
	}) {
		t.Fatal("aggregation loop did not adopt the healthy peer's key after recovering from the panic — loop likely died")
	}

	// And the panicking peer's own kid must NEVER have been installed (the
	// panic happened INSIDE AdoptVerifyKey, before it could mutate state).
	if jwksHasKidSrv(serverJWKS(t, srv), panicKid) {
		t.Fatalf("panic-triggering kid %s was adopted despite AdoptVerifyKey panicking", panicKid)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}
}

var _ core.TokenIssuer = (*panicOnAdoptIssuer)(nil)
