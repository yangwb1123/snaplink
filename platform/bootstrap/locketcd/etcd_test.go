package etcd

// Pure-logic tests only — no etcd server required. Integration tests
// live outside the unit suite (running them needs a real etcd reachable
// on localhost:2379 and a build tag).
//
// Covered here: input validation. Acquire/Renew/Release are thin
// passthroughs to clientv3 and have nothing to verify without a server
// — exercising them in unit tests would just retest the etcd library.

import (
	"testing"
)

func TestNew_RequiresEndpoints(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when endpoints is empty")
	}
}
