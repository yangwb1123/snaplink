package federation

import (
	"context"
	"net"
)

// export_test.go exposes a few unexported internals to the EXTERNAL
// (federation_test) test package — the standard Go test-seam idiom. These
// symbols exist ONLY in the test binary and are NOT part of the public API.

// NegativeCacheLen reports the number of entries currently held in a
// RegistrationClientStore's negative (failed-resolution) cache, so a test can
// assert the size cap evicts under a distinct-id flood (the negative cache must
// not itself become an unbounded-memory DoS).
func NegativeCacheLen(s *RegistrationClientStore) int {
	s.negMu.Lock()
	defer s.negMu.Unlock()
	return len(s.negCache)
}

// DialWithSSRFCheck exposes dialWithSSRFCheck for external tests.
func DialWithSSRFCheck(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialWithSSRFCheck(ctx, network, addr)
}
