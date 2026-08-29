package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
)

// Claim keys contain only a fixed-size claim fingerprint. The value is a
// constant marker: neither secret material nor an audit payload is persisted.
const (
	clientSecretWarningKeyPrefix = "sso:client-secret-warning:"
	clientSecretWarningClaimTTL  = 24 * time.Hour
)

// ClientSecretWarningClaimStore is the Redis-backed, cross-replica warning
// claim store. Each claim is a single key so it is safe on Redis Cluster too.
type ClientSecretWarningClaimStore struct {
	rdb goredis.Cmdable
}

// NewClientSecretWarningClaimStore builds a warning claim store over the
// server's existing Redis client. The caller owns the client lifecycle.
func NewClientSecretWarningClaimStore(rdb goredis.Cmdable) *ClientSecretWarningClaimStore {
	return &ClientSecretWarningClaimStore{rdb: rdb}
}

func clientSecretWarningKey(claim rotation.ClientSecretWarningClaim) string {
	return clientSecretWarningKeyPrefix + claim.Fingerprint()
}

// clientSecretWarningClaimScript atomically inserts a marker only when the
// claim key is absent. The TTL bounds stale claim state even if a day-key is
// never revisited.
var clientSecretWarningClaimScript = goredis.NewScript(`
local inserted = redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1])
if inserted then return 1 end
return 0
`)

// Claim implements rotation.ClientSecretWarningClaimStore. Redis errors are
// returned to the scanner, which logs them and falls back to local deduplication.
func (s *ClientSecretWarningClaimStore) Claim(ctx context.Context, claim rotation.ClientSecretWarningClaim) (bool, error) {
	if s == nil || s.rdb == nil {
		return false, errors.New("redis: client secret warning claim store not initialized")
	}
	result, err := clientSecretWarningClaimScript.Run(ctx, s.rdb, []string{clientSecretWarningKey(claim)}, clientSecretWarningClaimTTL.Milliseconds()).Int64()
	if err != nil {
		return false, fmt.Errorf("redis: claim client secret warning: %w", err)
	}
	if result != 0 && result != 1 {
		return false, fmt.Errorf("redis: claim client secret warning returned %d", result)
	}
	return result == 1, nil
}

var _ rotation.ClientSecretWarningClaimStore = (*ClientSecretWarningClaimStore)(nil)
