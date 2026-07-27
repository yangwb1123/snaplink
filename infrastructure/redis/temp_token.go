package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/shared/core"
)

const tempTokenPrefix = "sso:temptoken:" // sso:temptoken:<token> -> JSON subject

func tempTokenKey(token string) string { return tempTokenPrefix + token }

// TempTokenStore is the Redis-backed, cluster-shared [authenticators.TempTokenStore].
// The memory peer keeps the single-use temp token in one replica's memory, so a
// token minted on replica A is unknown to replica B's Consume — the temp-token
// authenticator (and the admin TokenAdminService that shares this store) issue
// on one request and redeem on another, which can land on different replicas.
// One key per token: SET/GETDEL are single-key and inherently CROSSSLOT-safe.
type TempTokenStore struct {
	rdb goredis.Cmdable
}

// NewTempTokenStore builds the store over an existing go-redis client.
func NewTempTokenStore(rdb goredis.Cmdable) *TempTokenStore {
	return &TempTokenStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *TempTokenStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: temp token store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

// Issue stores subject under token with the given TTL. A non-positive TTL is a
// no-op (a token with no expiry must never persist; Consume would reject it).
func (s *TempTokenStore) Issue(ctx context.Context, token string, subject *core.Subject, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	blob, err := json.Marshal(subject)
	if err != nil {
		return fmt.Errorf("redis: marshal temp token subject: %w", err)
	}
	if err := s.rdb.Set(ctx, tempTokenKey(token), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: issue temp token: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the bound subject (GETDEL = single-use,
// single-key, race-free). Missing or expired both map to
// [authenticators.ErrCodeInvalid] — the same sentinel the memory peer returns.
func (s *TempTokenStore) Consume(ctx context.Context, token string) (*core.Subject, error) {
	blob, err := s.rdb.GetDel(ctx, tempTokenKey(token)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, authenticators.ErrCodeInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume temp token: %w", err)
	}
	var subject core.Subject
	if err := json.Unmarshal(blob, &subject); err != nil {
		return nil, fmt.Errorf("redis: unmarshal temp token subject: %w", err)
	}
	return &subject, nil
}

var _ authenticators.TempTokenStore = (*TempTokenStore)(nil)
