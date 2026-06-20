package netpolicy

import "time"

// Test-only seams onto the Classifier's self-heal internals. They live here
// (package netpolicy) so the external self-heal test (package netpolicy_test)
// can read the degraded flag + shrink the resubscribe backoff WITHOUT the import
// cycle that an in-package test would hit (netpolicy/memory imports netpolicy).
// Mirrors the export_test.go seams the root package uses for its sibling
// invalidation-bus + signing-key aggregation self-heal tests.

// Degraded reports the unexported degraded flag for assertions.
func (c *Classifier) Degraded() bool { return c.degraded.Load() }

// SetBackoffBase shrinks the resubscribe backoff so the self-heal happens fast
// in tests.
func (c *Classifier) SetBackoffBase(d time.Duration) { c.backoffBase = d }
