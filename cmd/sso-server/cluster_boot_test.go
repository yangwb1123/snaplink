package main

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

// TestWireInvalidationBusOpts_FailsClosedWhenArmedWithoutBus pins the P2
// hardening: a cross-replica SECURITY feature (cross_replica_revocation /
// coordinated_cutover) whose only purpose is bus propagation MUST refuse to boot
// when no live bus is wired, rather than silently running INERT and leaking
// revoked tokens across a multi-replica fleet.
func TestWireInvalidationBusOpts_FailsClosedWhenArmedWithoutBus(t *testing.T) {
	t.Parallel()
	armed := func(mut func(*config.Config)) *appBuilder {
		cfg := &config.Config{}
		mut(cfg)
		return &appBuilder{cfg: cfg, logger: quietLogger()}
	}

	t.Run("cross_replica_revocation without bus errors", func(t *testing.T) {
		b := armed(func(c *config.Config) { c.Cluster.CrossReplicaRevocation = true })
		if err := b.wireInvalidationBusOpts(nil); err == nil {
			t.Fatal("expected boot error when cross_replica_revocation is armed without a bus")
		}
	})

	t.Run("coordinated_cutover without bus errors", func(t *testing.T) {
		b := armed(func(c *config.Config) { c.Keys.Rotation.CoordinatedCutover = true })
		if err := b.wireInvalidationBusOpts(nil); err == nil {
			t.Fatal("expected boot error when coordinated_cutover is armed without a bus")
		}
	})

	t.Run("neither armed tolerates a nil bus", func(t *testing.T) {
		b := armed(func(*config.Config) {})
		if err := b.wireInvalidationBusOpts(nil); err != nil {
			t.Fatalf("nil bus with no cross-replica feature armed must be fine, got %v", err)
		}
	})
}
