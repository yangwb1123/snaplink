package redis

import (
	"context"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/shared/security"
)

const jtiKeyPrefix = "sso:jti:" // sso:jti:<jti> -> "1" (presence marker)

// JTIReplayStore is the Redis-backed implementation of
// [security.JTIReplayStore]. A jti seen on one replica is recorded in
// shared Redis so every replica rejects the replay.
type JTIReplayStore struct {
	rdb goredis.Cmdable
}

// NewJTIReplayStore builds the store over an existing go-redis client.
func NewJTIReplayStore(rdb goredis.Cmdable) *JTIReplayStore {
	return &JTIReplayStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *JTIReplayStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: jti replay store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func jtiKey(jti string) string { return jtiKeyPrefix + jti }

// MarkSeen records the jti with SET key NX EX ttl — an atomic test-and-
// set. The SET succeeds (and SetNX returns true) iff the key did NOT
// already exist, so the FIRST caller gets firstSighting=true and every
// replay within the TTL window gets false. NX makes the check-and-write
// one atomic server op (the Redis analogue of SQLite's INSERT ... ON
// CONFLICT DO NOTHING + rows-affected test); EX bounds the key to the
// jti's expiry so the keyspace stays the size of the active window —
// Redis evicts the marker itself, no lazy GC needed.
//
// Errors are fail-open per the SPI contract: on a Redis error we return
// (true, err) so a degraded replay-defense backend doesn't block valid
// requests, and the caller logs it.
func (s *JTIReplayStore) MarkSeen(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if jti == "" {
		return true, nil
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// An expiry already past gets a 1s floor so an immediate replay
		// is still caught — mirrors the SQLite + memory backends.
		ttl = time.Second
	}
	ok, err := s.rdb.SetNX(ctx, jtiKey(jti), "1", ttl).Result()
	if err != nil {
		// Fail-open: don't block on a backend hiccup.
		return true, err
	}
	return ok, nil
}

var _ security.JTIReplayStore = (*JTIReplayStore)(nil)
