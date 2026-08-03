package redis

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const (
	otpCodePrefix     = "sso:otp:"    // sso:otp:<key> -> the one-time code
	otpCooldownPrefix = "sso:otp:cd:" // sso:otp:cd:<key> -> cooldown sentinel
	otpQuotaPrefix    = "sso:otp:q:"  // sso:otp:q:<tenant-hash> -> quota hash
	otpRecordPrefix   = "v1:"
)

func otpCodeKey(key string) string     { return otpCodePrefix + key }
func otpCooldownKey(key string) string { return otpCooldownPrefix + key }

// CodeStore is the Redis-backed, cluster-shared [authenticators.CodeStore] for
// passwordless email/phone OTP. The memory peer keeps the code in one replica's
// memory, so on a no-affinity load balancer the verify lands on a different
// replica than the send and always fails — passwordless login breaks under HA.
// One key per (key) so Save/Verify are single-key and CROSSSLOT-safe.
//
// Verify replicates the memory peer's retry semantics: a typo is retryable up
// to the fixed per-code attempt limit, a correct code is single-use, and the
// terminal failed attempt invalidates it. Comparisons happen client-side in
// constant time; Lua compare-and-update/delete operations make both consumption
// and attempt accounting atomic without consuming a code on the first typo.
type CodeStore struct {
	rdb         goredis.Cmdable
	cooldown    time.Duration
	maxAttempts int
	quota       authenticators.CodeSendQuota
}

// NewCodeStore builds the store over an existing go-redis client.
func NewCodeStore(rdb goredis.Cmdable) *CodeStore {
	return NewCodeStoreWithQuota(rdb, authenticators.DefaultCodeSendQuota())
}

// NewCodeStoreWithQuota builds a Redis store with explicit delivery budgets.
func NewCodeStoreWithQuota(rdb goredis.Cmdable, quota authenticators.CodeSendQuota) *CodeStore {
	return &CodeStore{
		rdb:         rdb,
		cooldown:    authenticators.DefaultCodeResendCooldown,
		maxAttempts: authenticators.DefaultCodeMaxAttempts,
		quota:       quota,
	}
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
// When a cooldown is configured (default 60 s), a SetNX on the cooldown key
// gates repeated sends: if the key already exists the cooldown is active and
// spi.ErrCodeCooldownActive is returned without overwriting the live code.
func (s *CodeStore) Save(ctx context.Context, key, code string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	cooldownAcquired := false
	if s.cooldown > 0 {
		ok, err := s.rdb.SetNX(ctx, otpCooldownKey(key), 1, s.cooldown).Result()
		if err == nil && !ok {
			return spi.ErrCodeCooldownActive
		}
		cooldownAcquired = err == nil && ok
		// On Redis error: fail open — don't block code sends due to Redis issues.
	}
	reserved, quotaErr := s.reserveQuota(ctx, key)
	if errors.Is(quotaErr, spi.ErrCodeSendQuotaExceeded) {
		if cooldownAcquired {
			_ = s.rdb.Del(ctx, otpCooldownKey(key)).Err()
		}
		return quotaErr
	}
	if err := s.rdb.Set(ctx, otpCodeKey(key), encodeOTPRecord(code, 0), ttl).Err(); err != nil {
		s.releaseReservation(ctx, key, reserved, cooldownAcquired)
		return fmt.Errorf("redis: save otp code: %w", err)
	}
	return nil
}

func (s *CodeStore) reserveQuota(ctx context.Context, identity string) (bool, error) {
	if s.quota.IdentityLimit <= 0 && s.quota.TenantLimit <= 0 {
		return false, nil
	}
	result, err := reserveOTPQuotaScript.Run(ctx, s.rdb, []string{otpQuotaKey(ctx)},
		otpQuotaIdentity(identity), s.quota.IdentityLimit, s.quota.TenantLimit,
		quotaWindowSeconds(s.quota.Window)).Int64()
	if err != nil {
		return false, nil // quota storage outage is fail-open
	}
	if result != 0 {
		return false, spi.ErrCodeSendQuotaExceeded
	}
	return true, nil
}

func (s *CodeStore) releaseReservation(ctx context.Context, identity string, reserved, cooldown bool) {
	if reserved {
		_, _ = releaseOTPQuotaScript.Run(ctx, s.rdb, []string{otpQuotaKey(ctx)}, otpQuotaIdentity(identity)).Result()
	}
	if cooldown {
		_ = s.rdb.Del(ctx, otpCooldownKey(identity)).Err()
	}
}

func otpQuotaKey(ctx context.Context) string {
	tenantID := spi.CodeSendTenant(ctx)
	if tenantID == "" {
		tenantID = "_public"
	}
	sum := sha256.Sum256([]byte(tenantID))
	return fmt.Sprintf("%s%x", otpQuotaPrefix, sum[:16])
}

func otpQuotaIdentity(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("i:%x", sum[:16])
}

func quotaWindowSeconds(window time.Duration) int64 {
	if window <= 0 {
		window = authenticators.DefaultCodeSendQuotaWindow
	}
	seconds := int64((window + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

// Verify constant-time-compares the presented code to the stored one. Missing or
// expired (GET miss) and a mismatch both return [authenticators.ErrCodeInvalid]
// (the same oracle-safe sentinel the memory peer returns); only a correct code
// is deleted (single-use), leaving typos retryable within the TTL until the
// shared attempt limit is reached.
func (s *CodeStore) Verify(ctx context.Context, key, code string) error {
	raw, err := s.rdb.Get(ctx, otpCodeKey(key)).Result()
	if errors.Is(err, goredis.Nil) {
		return authenticators.ErrCodeInvalid
	}
	if err != nil {
		return fmt.Errorf("redis: verify otp code: %w", err)
	}
	stored, attempts := decodeOTPRecord(raw)
	if subtle.ConstantTimeCompare([]byte(stored), []byte(code)) == 1 {
		return s.consume(ctx, key, raw)
	}
	return s.recordFailure(ctx, key, raw, stored, attempts+1)
}

func (s *CodeStore) consume(ctx context.Context, key, raw string) error {
	deleted, err := compareDeleteCodeScript.Run(ctx, s.rdb, []string{otpCodeKey(key)}, raw).Int64()
	if err != nil {
		return fmt.Errorf("redis: consume otp code: %w", err)
	}
	if deleted != 1 {
		return authenticators.ErrCodeInvalid
	}
	return nil
}

func (s *CodeStore) recordFailure(ctx context.Context, key, raw, code string, attempts int) error {
	next := encodeOTPRecord(code, attempts)
	if s.maxAttempts > 0 && attempts >= s.maxAttempts {
		next = ""
	}
	if _, err := compareUpdateCodeScript.Run(ctx, s.rdb, []string{otpCodeKey(key)}, raw, next).Result(); err != nil {
		return fmt.Errorf("redis: record otp failure: %w", err)
	}
	return authenticators.ErrCodeInvalid
}

// Invalidate conditionally removes an undelivered code and then releases its
// resend cooldown. The value comparison prevents a stale failure callback from
// deleting a newer issuance.
func (s *CodeStore) Invalidate(ctx context.Context, key, code string) error {
	raw, err := s.rdb.Get(ctx, otpCodeKey(key)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("redis: load otp for invalidation: %w", err)
	}
	stored, _ := decodeOTPRecord(raw)
	if subtle.ConstantTimeCompare([]byte(stored), []byte(code)) != 1 {
		return nil
	}
	deleted, err := compareDeleteCodeScript.Run(ctx, s.rdb, []string{otpCodeKey(key)}, raw).Int64()
	if err != nil {
		return fmt.Errorf("redis: invalidate otp code: %w", err)
	}
	if deleted == 1 {
		if err := s.rdb.Del(ctx, otpCooldownKey(key)).Err(); err != nil {
			return fmt.Errorf("redis: release otp cooldown: %w", err)
		}
		s.releaseReservation(ctx, key, true, false)
	}
	return nil
}

func encodeOTPRecord(code string, attempts int) string {
	return otpRecordPrefix + strconv.Itoa(attempts) + ":" + code
}

func decodeOTPRecord(raw string) (string, int) {
	if !strings.HasPrefix(raw, otpRecordPrefix) {
		return raw, 0
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, otpRecordPrefix), ":", 2)
	if len(parts) != 2 {
		return raw, 0
	}
	attempts, err := strconv.Atoi(parts[0])
	if err != nil || attempts < 0 {
		return raw, 0
	}
	return parts[1], attempts
}

var compareDeleteCodeScript = goredis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
  return 0
end
redis.call('DEL', KEYS[1])
return 1
`)

var compareUpdateCodeScript = goredis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
  return 0
end
if ARGV[2] == '' then
  redis.call('DEL', KEYS[1])
else
  redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
end
return 1
`)

var reserveOTPQuotaScript = goredis.NewScript(`
local identity = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
local total = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
local identity_limit = tonumber(ARGV[2])
local tenant_limit = tonumber(ARGV[3])
if identity_limit > 0 and identity >= identity_limit then return 1 end
if tenant_limit > 0 and total >= tenant_limit then return 2 end
redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
redis.call('HINCRBY', KEYS[1], 'total', 1)
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[4]) end
return 0
`)

var releaseOTPQuotaScript = goredis.NewScript(`
local identity = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
local total = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
if identity > 0 then redis.call('HINCRBY', KEYS[1], ARGV[1], -1) end
if total > 0 then redis.call('HINCRBY', KEYS[1], 'total', -1) end
return 1
`)

var _ authenticators.CodeStore = (*CodeStore)(nil)
var _ authenticators.CodeInvalidator = (*CodeStore)(nil)
