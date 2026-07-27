package sso_test

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/signingkeys"
	"github.com/yangwb1123/snaplink/shared/core"
)

// upsertPeerKey feeds srv a synthetic EventKeysUpserted for peerIss under
// replicaID, via ApplySigningKeyEventForTest — the same seam
// TestSigningKeyAggregation_DropPath uses to drive reconcileAdopted
// deterministically without a real registry.
func upsertPeerKey(t *testing.T, srv *sso.Server, replicaID string, peerIss *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type: signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{
			ReplicaID: replicaID,
			Keys:      []core.JWK{peerIssuerJWK(t, peerIss)},
		},
	})
}

// TestPruneVerifyKeys_DropsStaleReplica proves the retention-window safety
// net: a peer whose kid was adopted via ApplySigningKeyEventForTest (so
// reconcileAdopted stamped lastSeenPeer) but hasn't been reconciled again
// gets its kid dropped once retention has elapsed, even though no
// EventKeysRemoved ever arrived.
func TestPruneVerifyKeys_DropsStaleReplica(t *testing.T) {
	t.Parallel()
	srv, localIss := newEventServer(t, "replica-local")
	_, peerIss := newEventServer(t, "replica-peer")
	peerKid := peerIss.KeyID()

	upsertPeerKey(t, srv, "replica-peer", peerIss)
	if !issuerHasKid(t, localIss, peerKid) {
		t.Fatalf("peer kid %s not adopted", peerKid)
	}

	// A vanishingly small retention: by the time PruneVerifyKeys runs, the
	// reconcile stamp above is already older than it (real wall-clock time
	// has advanced past 1ns just executing the lines above).
	dropped := srv.PruneVerifyKeys(1 * time.Nanosecond)
	if dropped != 1 {
		t.Fatalf("PruneVerifyKeys dropped = %d, want 1", dropped)
	}
	if issuerHasKid(t, localIss, peerKid) {
		t.Fatalf("peer kid %s still adopted after prune", peerKid)
	}
}

// TestPruneVerifyKeys_KeepsFreshReplica proves the sweep is conservative: a
// replica reconciled well within retention is left untouched.
func TestPruneVerifyKeys_KeepsFreshReplica(t *testing.T) {
	t.Parallel()
	srv, localIss := newEventServer(t, "replica-local")
	_, peerIss := newEventServer(t, "replica-peer")
	peerKid := peerIss.KeyID()

	upsertPeerKey(t, srv, "replica-peer", peerIss)

	dropped := srv.PruneVerifyKeys(1 * time.Hour)
	if dropped != 0 {
		t.Fatalf("PruneVerifyKeys dropped = %d, want 0 (replica just reconciled)", dropped)
	}
	if !issuerHasKid(t, localIss, peerKid) {
		t.Fatal("fresh replica's kid was pruned")
	}
}

// TestPruneVerifyKeys_NonPositiveRetentionIsNoop guards against an
// accidental prune-everything call.
func TestPruneVerifyKeys_NonPositiveRetentionIsNoop(t *testing.T) {
	t.Parallel()
	srv, localIss := newEventServer(t, "replica-local")
	_, peerIss := newEventServer(t, "replica-peer")
	peerKid := peerIss.KeyID()

	upsertPeerKey(t, srv, "replica-peer", peerIss)

	if dropped := srv.PruneVerifyKeys(0); dropped != 0 {
		t.Fatalf("PruneVerifyKeys(0) dropped = %d, want 0", dropped)
	}
	if !issuerHasKid(t, localIss, peerKid) {
		t.Fatal("zero-retention call must be a no-op")
	}
}

// TestPruneVerifyKeys_MetricsWiring proves the prune sweep records both the
// prune counter and the verify-set-size gauge when WithMetrics is wired.
func TestPruneVerifyKeys_MetricsWiring(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))
	srv := sso.NewServer(sso.WithTokenIssuer(sso.TokenStrategyJWT, iss), sso.WithMetrics(m))
	srv.SetReplicaIDForTest("replica-local")
	_, peerIss := newEventServer(t, "replica-peer")

	upsertPeerKey(t, srv, "replica-peer", peerIss)
	if dropped := srv.PruneVerifyKeys(1 * time.Nanosecond); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}

	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sawPruned, sawGauge bool
	for _, mf := range mfs {
		switch mf.GetName() {
		case metrics.NameSigningKeyPrunedTotal:
			sawPruned = true
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Errorf("%s = %v, want 1", metrics.NameSigningKeyPrunedTotal, got)
			}
		case metrics.NameSigningVerifyKeySetSize:
			sawGauge = true
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 0 {
				t.Errorf("%s = %v, want 0 after the only peer kid was pruned", metrics.NameSigningVerifyKeySetSize, got)
			}
		}
	}
	if !sawPruned {
		t.Errorf("%s series never registered", metrics.NameSigningKeyPrunedTotal)
	}
	if !sawGauge {
		t.Errorf("%s series never registered", metrics.NameSigningVerifyKeySetSize)
	}
}
