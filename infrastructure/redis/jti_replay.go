package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/security"
)

const (
	jtiKeyPrefix     = "sso:jti:"            // sso:jti:<jti> -> "1" (presence marker)
	revocationSetKey = "sso:jwt:revocations" // sorted-set member=token, score=exp
)

var recordRevocationScript = goredis.NewScript(`
redis.call("ZADD", KEYS[1], ARGV[2], ARGV[3])
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", "(" .. ARGV[1])
return 1
`)

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

// Forget DELs a previously MarkSeen jti so a retried request carrying it is
// admitted rather than dropped as a replay (security.JTIReplayForgetter). Used
// by the CAEP receiver to roll back the jti when a fail-closed mark was followed
// by a retryable action failure. Single-key DEL — cluster-slot safe. Idempotent.
func (s *JTIReplayStore) Forget(ctx context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	return s.rdb.Del(ctx, jtiKey(jti)).Err()
}

// RevocationStore is the shared Redis implementation of
// [defaultimpl.RevocationStore]. Tokens are members of one sorted set and
// their unix-second expiries are scores, allowing every replica to load the
// same deny-set after restart or invalidation-bus recovery while pruning with
// a single bounded command. Validation remains in-process; Redis is consulted
// only by Revoke, boot seeding, and recovery seeding.
type RevocationStore struct {
	rdb goredis.Cmdable
}

// NewRevocationStore builds the store over the process-wide Redis client.
func NewRevocationStore(rdb goredis.Cmdable) *RevocationStore {
	return &RevocationStore{rdb: rdb}
}

// Revoke atomically prunes expired members and records token until expUnix.
// The script is idempotent and one-key, so it is safe on standalone, Sentinel,
// and Redis Cluster clients and bounds storage to the active token window.
func (s *RevocationStore) Revoke(ctx context.Context, token string, expUnix int64) error {
	err := recordRevocationScript.Run(
		ctx,
		s.rdb,
		[]string{revocationSetKey},
		time.Now().Unix(),
		expUnix,
		token,
	).Err()
	if err != nil {
		return fmt.Errorf("redis: record token revocation: %w", err)
	}
	return nil
}

// Load returns every revocation whose expiry has not passed, after pruning
// older entries so both the returned map and Redis key remain TTL-bounded.
func (s *RevocationStore) Load(ctx context.Context) (map[string]int64, error) {
	now := time.Now().Unix()
	if err := s.Prune(ctx, now); err != nil {
		return nil, err
	}
	entries, err := s.rdb.ZRangeByScoreWithScores(ctx, revocationSetKey, &goredis.ZRangeBy{
		Min: strconv.FormatInt(now, 10), Max: "+inf",
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: load token revocations: %w", err)
	}
	out := make(map[string]int64, len(entries))
	for _, entry := range entries {
		token, ok := entry.Member.(string)
		if !ok {
			return nil, fmt.Errorf("redis: token revocation member has type %T", entry.Member)
		}
		out[token] = int64(entry.Score)
	}
	return out, nil
}

// Prune drops entries strictly older than nowUnix. The exclusive upper bound
// preserves a token whose exp equals the cutoff, matching the SPI contract.
func (s *RevocationStore) Prune(ctx context.Context, nowUnix int64) error {
	max := "(" + strconv.FormatInt(nowUnix, 10)
	if err := s.rdb.ZRemRangeByScore(ctx, revocationSetKey, "-inf", max).Err(); err != nil {
		return fmt.Errorf("redis: prune token revocations: %w", err)
	}
	return nil
}

var (
	_ security.JTIReplayStore     = (*JTIReplayStore)(nil)
	_ security.JTIReplayForgetter = (*JTIReplayStore)(nil)
	_ defaultimpl.RevocationStore = (*RevocationStore)(nil)
)
