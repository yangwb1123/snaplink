package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/oauth"
)

const authCodeKeyPrefix = "sso:authcode:" // sso:authcode:<code> -> JSON

// AuthCodeStore is the Redis-backed implementation of
// [oauth.AuthCodeStore]. Suitable for multi-replica deployments: every
// replica issues + consumes against the same Redis.
type AuthCodeStore struct {
	rdb goredis.Cmdable
}

// NewAuthCodeStore builds the store over an existing go-redis client.
func NewAuthCodeStore(rdb goredis.Cmdable) *AuthCodeStore {
	return &AuthCodeStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *AuthCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: auth code store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func authCodeKey(code string) string { return authCodeKeyPrefix + code }

// Issue persists the code as a JSON blob with a key TTL set from the
// code's own expiry, so an unconsumed code self-evicts.
func (s *AuthCodeStore) Issue(ctx context.Context, code string, info *oauth.AuthCode) error {
	if code == "" || info == nil {
		return oauth.ErrAuthCodeNotFound
	}
	blob, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("redis: marshal auth_code: %w", err)
	}
	ttl := time.Until(info.ExpiresAt)
	if ttl <= 0 {
		// Already expired; storing with a non-positive TTL would persist
		// forever in Redis. Treat as a no-op success — the next Consume
		// would reject it as expired anyway.
		return nil
	}
	if err := s.rdb.Set(ctx, authCodeKey(code), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert auth_code: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the code via GETDEL — a single
// server-side get-and-delete (Redis 6.2+). This is the Redis analogue of
// SQLite's DELETE ... RETURNING: a second Consume of the same code finds
// nothing, so single-use is race-free. Unknown / TTL-expired / already-
// consumed all collapse to ErrAuthCodeNotFound (oracle-resistance §2).
func (s *AuthCodeStore) Consume(ctx context.Context, code string) (*oauth.AuthCode, error) {
	blob, err := s.rdb.GetDel(ctx, authCodeKey(code)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume auth_code: %w", err)
	}
	var out oauth.AuthCode
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal auth_code: %w", err)
	}
	// Defense in depth: even though the key TTL evicts expired codes,
	// the eviction-lag window means a just-expired code could still be
	// read; collapse it to the same not-found result.
	if out.IsExpired() {
		return nil, oauth.ErrAuthCodeNotFound
	}
	return &out, nil
}

var _ oauth.AuthCodeStore = (*AuthCodeStore)(nil)
