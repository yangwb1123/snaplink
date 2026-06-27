package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/shared/core"
)

const (
	pwResetKeyPrefix = "sso:pwreset:" // sso:pwreset:<token> -> JSON
	// sso:pwreset:user:<userID> -> SET of that user's token strings. A secondary
	// index so the admin plane (PasswordResetRevoker/Lister) can revoke or list a
	// user's outstanding reset tokens before TTL — the helpdesk security-recovery
	// path the memory/sqlite peers expose. Best-effort: a stale member (its token
	// already consumed/expired) is harmless — List skips it on a GET miss and
	// Revoke's per-token DEL is a no-op.
	pwResetUserKeyPrefix = "sso:pwreset:user:"
)

// PasswordResetStore is the Redis-backed [core.PasswordResetStore] for the
// forgot-password flow. The memory + sqlite peers keep reset tokens per-pod,
// so a token minted on one replica is invisible to another (silent per-pod
// state on a multi-replica deployment); Redis makes the single-use token
// cluster-shared, so the /auth/reset-password leg consumes on whatever replica
// handles it.
//
// Cluster-safe by construction: one token == one key, so every op is a single
// key and cannot CROSSSLOT. Consume is GETDEL — one atomic server round trip
// that returns AND deletes — which is the single-use guarantee that stops a
// replayed reset token (the Redis analogue of the sqlite DELETE … RETURNING).
type PasswordResetStore struct {
	rdb goredis.Cmdable
}

// NewPasswordResetStore builds the store over an existing go-redis client.
func NewPasswordResetStore(rdb goredis.Cmdable) *PasswordResetStore {
	return &PasswordResetStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *PasswordResetStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: password reset store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func pwResetKey(token string) string      { return pwResetKeyPrefix + token }
func pwResetUserKey(userID string) string { return pwResetUserKeyPrefix + userID }

// Issue stores the token as JSON under its own key with a TTL derived from its
// absolute expiry, so Redis evicts the marker itself once it expires (no GC).
// A token whose ExpiresAt is already past is a no-op: SET EX with a non-positive
// TTL is meaningless and Consume would reject it on read anyway — mirrors how
// the auth_code / par stores skip non-positive TTLs.
func (s *PasswordResetStore) Issue(ctx context.Context, rt *core.PasswordResetToken) error {
	if rt == nil {
		return core.ErrResetTokenNotFound
	}
	ttl := time.Until(rt.ExpiresAt)
	if ttl <= 0 {
		// Already expired: nothing durable to store; the equivalent of an
		// immediately-evicted key. Consume would map it to not-found regardless.
		return nil
	}
	blob, err := json.Marshal(rt)
	if err != nil {
		return fmt.Errorf("redis: marshal password_reset_token: %w", err)
	}
	// Index the token under its user BEFORE writing the token, and treat index
	// failure as FATAL. That ordering makes the index authoritative: every live
	// token (the Set below succeeded) provably has its index member present, so
	// the admin RevokeByUser/ListByUser cannot miss a still-valid token. The only
	// residual skew is a stale member whose token Set later failed — harmless
	// (List skips it on a GET miss, Revoke's DEL is a no-op).
	if rt.UserID != "" {
		idx := pwResetUserKey(rt.UserID)
		if err := s.rdb.SAdd(ctx, idx, rt.Token).Err(); err != nil {
			return fmt.Errorf("redis: index password_reset_token: %w", err)
		}
		if err := s.rdb.Expire(ctx, idx, ttl).Err(); err != nil {
			return fmt.Errorf("redis: expire password_reset index: %w", err)
		}
	}
	if err := s.rdb.Set(ctx, pwResetKey(rt.Token), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: issue password_reset_token: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes via GETDEL — single-use, race-free
// (single key, so cluster-slot-safe and contention-free). Missing, expired, or
// already-consumed all map to core.ErrResetTokenNotFound: one oracle-safe
// response the reset handler collapses to a single reset_invalid. The expiry
// re-check after decode is defense in depth in case a key outlives its TTL.
func (s *PasswordResetStore) Consume(ctx context.Context, token string) (*core.PasswordResetToken, error) {
	blob, err := s.rdb.GetDel(ctx, pwResetKey(token)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, core.ErrResetTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume password_reset_token: %w", err)
	}
	var out core.PasswordResetToken
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal password_reset_token: %w", err)
	}
	if out.IsExpired() {
		return nil, core.ErrResetTokenNotFound
	}
	// Drop the consumed token from its user index (best-effort cleanup).
	if out.UserID != "" {
		_ = s.rdb.SRem(ctx, pwResetUserKey(out.UserID), token).Err()
	}
	return &out, nil
}

// RevokeByUser deletes every pending reset token bound to userID and returns the
// count actually removed (live tokens; stale index members DEL to 0). Implements
// [core.PasswordResetRevoker] — the helpdesk path to kill a leaked reset token
// before its TTL. Each DEL is single-key (the index and token keys may live in
// different slots), so the cluster routes them independently — no CROSSSLOT.
func (s *PasswordResetStore) RevokeByUser(ctx context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	idx := pwResetUserKey(userID)
	tokens, err := s.rdb.SMembers(ctx, idx).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: list reset index: %w", err)
	}
	removed := 0
	for _, tok := range tokens {
		n, derr := s.rdb.Del(ctx, pwResetKey(tok)).Result()
		if derr != nil {
			return removed, fmt.Errorf("redis: revoke reset token: %w", derr)
		}
		removed += int(n)
	}
	_ = s.rdb.Del(ctx, idx).Err()
	return removed, nil
}

// ListByUser returns the user's pending reset tokens. Implements
// [core.PasswordResetLister]. Redis evicts expired tokens, so a member whose key
// is already gone is simply skipped (the interface allows omitting expired ones).
func (s *PasswordResetStore) ListByUser(ctx context.Context, userID string) ([]*core.PasswordResetToken, error) {
	if userID == "" {
		return nil, nil
	}
	tokens, err := s.rdb.SMembers(ctx, pwResetUserKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list reset index: %w", err)
	}
	var out []*core.PasswordResetToken
	for _, tok := range tokens {
		blob, gerr := s.rdb.Get(ctx, pwResetKey(tok)).Bytes()
		if errors.Is(gerr, goredis.Nil) {
			continue // consumed or expired — skip
		}
		if gerr != nil {
			return nil, fmt.Errorf("redis: read reset token: %w", gerr)
		}
		var rt core.PasswordResetToken
		if json.Unmarshal(blob, &rt) == nil {
			out = append(out, &rt)
		}
	}
	return out, nil
}

var (
	_ core.PasswordResetStore   = (*PasswordResetStore)(nil)
	_ core.PasswordResetRevoker = (*PasswordResetStore)(nil)
	_ core.PasswordResetLister  = (*PasswordResetStore)(nil)
)
