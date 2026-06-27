package redis

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/domains/authenticators"
)

const otpCodePrefix = "sso:otp:" // sso:otp:<key> -> the one-time code

func otpCodeKey(key string) string { return otpCodePrefix + key }

// CodeStore is the Redis-backed, cluster-shared [authenticators.CodeStore] for
// passwordless email/phone OTP. The memory peer keeps the code in one replica's
// memory, so on a no-affinity load balancer the verify lands on a different
// replica than the send and always fails — passwordless login breaks under HA.
// One key per (key) so Save/Verify are single-key and CROSSSLOT-safe.
//
// Verify replicates the memory peer's retry semantics EXACTLY: a wrong code does
// NOT consume the entry (the user may retry a typo within the TTL); only a
// correct code is deleted (single-use). The comparison is constant-time, matching
// the memory peer — so the read-compare-delete is done client-side rather than a
// GETDEL (which would consume on every attempt, including typos). The GET-then-
// conditional-DEL is not a single atomic op, but the only race is two concurrent
// CORRECT submissions of the same code both succeeding — a benign double-use far
// less consequential than dropping a typo retry or leaking a timing signal.
type CodeStore struct {
	rdb goredis.Cmdable
}

// NewCodeStore builds the store over an existing go-redis client.
func NewCodeStore(rdb goredis.Cmdable) *CodeStore {
	return &CodeStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *CodeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: code store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

// Save stores code under key with the given TTL (redis evicts it on expiry, so
// Verify's expiry check is just a GET miss). A non-positive TTL is a no-op
// (mirrors the auth_code/par stores) — a code with no expiry must never persist.
func (s *CodeStore) Save(ctx context.Context, key, code string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	if err := s.rdb.Set(ctx, otpCodeKey(key), code, ttl).Err(); err != nil {
		return fmt.Errorf("redis: save otp code: %w", err)
	}
	return nil
}

// Verify constant-time-compares the presented code to the stored one. Missing or
// expired (GET miss) and a mismatch both return [authenticators.ErrCodeInvalid]
// (the same oracle-safe sentinel the memory peer returns); only a correct code
// is deleted (single-use), leaving a typo retryable within the TTL.
func (s *CodeStore) Verify(ctx context.Context, key, code string) error {
	stored, err := s.rdb.Get(ctx, otpCodeKey(key)).Result()
	if errors.Is(err, goredis.Nil) {
		return authenticators.ErrCodeInvalid
	}
	if err != nil {
		return fmt.Errorf("redis: verify otp code: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(code)) != 1 {
		return authenticators.ErrCodeInvalid
	}
	// Correct: consume (single-use). Best-effort DEL — the compare already
	// authorized the login; a DEL error at worst leaves the code redeemable
	// until its TTL.
	_ = s.rdb.Del(ctx, otpCodeKey(key)).Err()
	return nil
}

var _ authenticators.CodeStore = (*CodeStore)(nil)
