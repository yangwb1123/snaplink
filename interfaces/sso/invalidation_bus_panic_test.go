package sso

// Panic-recovery test for the cross-replica invalidation-bus subscriber.
// Package sso (not sso_test) so it can reuse the tenantSuspensionCache
// observable seam + primeAndExpectInvalidated helper from
// invalidation_bus_selfheal_test.go to prove forward progress after a
// recovered panic, mirroring that file's self-heal tests. A hand-rolled fake
// TokenIssuer (rather than infrastructure/defaultimpl) avoids the import
// cycle defaultimpl has back into this package.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"
)

// panicOnRevokeIssuer is a minimal fake core.TokenIssuer whose Revoke always
// panics — simulating a bug in a third-party, operator-supplied TokenIssuer
// implementation reached via the cluster.KindTokenRevoked arm
// (applyTokenRevocation -> RevokeAcrossIssuers -> ti.Revoke). It deliberately
// does NOT implement TokenFormatHinter, so revokeAcrossIssuers' shape-skip
// gate never applies — every token is tried regardless of encoding, keeping
// the reproduction independent of real JWT material.
type panicOnRevokeIssuer struct{}

func (panicOnRevokeIssuer) Issue(_ context.Context, _ *Subject, _ []string) (*Token, error) {
	return &Token{AccessToken: "fake-access-token", TokenType: "Bearer"}, nil
}

func (panicOnRevokeIssuer) Validate(_ context.Context, _ string) (*TokenClaims, error) {
	return nil, errors.New("panicOnRevokeIssuer: validate not implemented")
}

func (panicOnRevokeIssuer) Revoke(_ context.Context, _ string) error {
	panic("simulated Revoke panic from a buggy TokenIssuer plugin")
}

var _ TokenIssuer = panicOnRevokeIssuer{}

// TestInvalidationBus_SurvivesTokenRevokePanic proves runInvalidationBus's
// subscriber loop survives a panic raised by a pluggable core.TokenIssuer's
// Revoke (the cluster.KindTokenRevoked arm, applyTokenRevocation ->
// RevokeAcrossIssuers) instead of letting it escape the bare `for evt :=
// range events` loop, which has no recover of its own. An unrecovered panic
// in ANY goroutine is always process-fatal in Go — before the
// applyInvalidationSafe fix, this test would abort the entire `go test`
// binary the instant the bus delivered the KindTokenRevoked event, and the
// KindTenantSuspension Event published right after would never be applied
// either, because the whole process (every replica sharing this bus) would
// already be gone.
func TestInvalidationBus_SurvivesTokenRevokePanic(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	srv := NewServer(
		WithTokenIssuer("jwt", panicOnRevokeIssuer{}),
		WithInvalidationBus(bus),
		WithCrossReplicaRevocation(),
		WithTenantSuspensionCheck(time.Hour), // creates tenantSuspensionCache
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := srv.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("StartInvalidationBus: %v", err)
	}

	if perr := bus.Publish(ctx, cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Payload: map[string]string{
			cluster.MetaRevokedToken: "some-revoked-token",
			cluster.MetaRevokedExp:   "0",
		},
	}); perr != nil {
		t.Fatalf("publish panic-triggering event: %v", perr)
	}

	// A later, unrelated Event must still be applied — proving the subscriber
	// goroutine survived the panic instead of silently dying with it (which,
	// unrecovered, would have taken the whole process down too).
	primeAndExpectInvalidated(t, srv, bus, "tenant-after-panic")

	if srv.invalidationBusDegraded.Load() {
		t.Fatal("a recovered per-event panic must not flip the subscription itself degraded (only a channel close does)")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel — subscriber loop likely died from the unrecovered panic")
	}
}
