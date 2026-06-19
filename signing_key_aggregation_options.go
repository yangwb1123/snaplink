// Signing-key aggregation options: registry, replica ID, and lease TTL.
package sso

import (
	"time"

	"github.com/snaplink/sso/signingkeys"
)

// Signing-key aggregation resubscribe backoff bounds.
const (
	signingKeyAggBackoffInitial = 1 * time.Second
	signingKeyAggBackoffMax     = 30 * time.Second
	signingKeyAggDegradedReason = "subscribe_channel_closed"
)

// DefaultSigningKeyLeaseTTL is the lease a replica requests when publishing
// its signing keys to a shared registry.
const DefaultSigningKeyLeaseTTL = 5 * time.Minute

// WithSharedSigningKeyRegistry opts this Server into leaderless
// multi-replica signing-key aggregation.
func WithSharedSigningKeyRegistry(reg signingkeys.Registry) Option {
	return func(s *Server) { s.signingKeyRegistry = reg }
}

// WithSigningKeyReplicaID sets the stable identifier this replica announces.
func WithSigningKeyReplicaID(id string) Option {
	return func(s *Server) { s.replicaID = id }
}

// WithSigningKeyLeaseTTL overrides the lease a replica requests when publishing.
func WithSigningKeyLeaseTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultSigningKeyLeaseTTL
		}
		s.signingKeyLeaseTTL = ttl
	}
}
