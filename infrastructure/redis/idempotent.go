package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// idemKeyPrefix scopes the /token idempotency-cache keys.
const idemKeyPrefix = "sso:idem:" // sso:idem:<key> -> cached token response body

func idemKey(key string) string { return idemKeyPrefix + key }

// IdempotentCache is the Redis-backed [core.IdempotentCache] — the
// cluster-shared peer of defaultimpl.MemoryIdempotentCache. A client retry
// that lands on a DIFFERENT replica still hits the cached response (the
// memory peer is process-local, so a failover retry re-issues the token).
// Same Get/Set interface, one key per idempotency key with a server-side
// TTL, so stale entries expire without a local prune loop.
//
// Semantics match the memory peer: Get returns the cached body when the key
// exists and has not expired; Set stores it with the caller-supplied TTL.
// A concurrent first request (two replicas both miss) is not claimed by
// this cache — the memory peer has the same post-hoc shape; the claim
// boundary is the token endpoint's own single-use stores.
type IdempotentCache struct {
	rdb goredis.Cmdable
}

// NewIdempotentCache builds the cache over an existing go-redis client (or
// cluster client — any goredis.Cmdable). The caller owns the client
// lifecycle.
func NewIdempotentCache(rdb goredis.Cmdable) *IdempotentCache {
	return &IdempotentCache{rdb: rdb}
}

// Get returns the cached response body for key, or (nil, false) when absent
// or expired (server-side TTL makes the two indistinguishable, exactly like
// the memory peer's expiresAt check).
func (s *IdempotentCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	raw, err := s.rdb.Get(ctx, idemKey(key)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("redis: get idempotency entry: %w", err)
	}
	return raw, true, nil
}

// Set stores the response body for key with the given TTL. A non-positive
// TTL stores without expiry (the caller normally passes the token-lifetime
// bound the memory peer enforces via its constructor default).
func (s *IdempotentCache) Set(ctx context.Context, key string, body []byte, ttl time.Duration) error {
	if ttl > 0 {
		if err := s.rdb.Set(ctx, idemKey(key), body, ttl).Err(); err != nil {
			return fmt.Errorf("redis: set idempotency entry: %w", err)
		}
		return nil
	}
	if err := s.rdb.Set(ctx, idemKey(key), body, 0).Err(); err != nil {
		return fmt.Errorf("redis: set idempotency entry: %w", err)
	}
	return nil
}
