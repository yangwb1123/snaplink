package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/shared/security"
)

// Two keys per subject, BOTH carrying a {key} hash tag so the failure
// counter and the lock marker map to ONE Redis Cluster slot — the
// registerFailureScript touches both in a single EVAL, which would be a
// CROSSSLOT error on a real cluster without the shared tag. See cluster.go.
const (
	// + {key} -> INCR counter, PEXPIRE FailureWindow on first hit.
	lockoutFailPrefix = "sso:lockout:fail:"
	// + {key} -> unlock-deadline (unix nanos string), PX LockoutDuration.
	lockoutUntilPrefix = "sso:lockout:until:"
)

// AccountLockout is the Redis-backed [security.AccountLockout]. The memory
// peer forks its counter per replica, so on a multi-replica fleet an attacker
// rotating targets across pods never trips any single pod's threshold — the
// per-account defense silently degrades to per-pod. This peer shares the
// counter through Redis Cluster so the Nth failure counts wherever it lands,
// closing the distributed-credential-stuffing hole the SPI exists to plug.
//
// Semantics are pinned to security.MemoryAccountLockout: a sliding window of
// FailureWindow (the counter's TTL, refreshed only on the first failure of a
// window — INCR re-creates it fresh once it expires), a lock that engages on
// the MaxFailures-th failure and auto-unlocks after LockoutDuration (the lock
// marker's own PX), and an already-locked key that keeps returning the same
// (true, until) without advancing the counter. RegisterSuccess clears both.
type AccountLockout struct {
	// MaxFailures / LockoutDuration / FailureWindow mirror
	// security.MemoryAccountLockout's exported fields + zero-value defaults so
	// cmd can apply one set of overrides across every backend after
	// construction (e.g. l.MaxFailures = cfg.MaxFailures).
	MaxFailures     int
	LockoutDuration time.Duration
	FailureWindow   time.Duration

	rdb goredis.Cmdable
}

// NewAccountLockout builds the store over an existing go-redis client (or
// cluster client) with the Default* policy. Operators override the exported
// policy fields directly after construction.
func NewAccountLockout(rdb goredis.Cmdable) *AccountLockout {
	return &AccountLockout{
		MaxFailures:     security.DefaultLockoutMaxFailures,
		LockoutDuration: security.DefaultLockoutDuration,
		FailureWindow:   security.DefaultLockoutFailureWindow,
		rdb:             rdb,
	}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *AccountLockout) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: account lockout not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func lockoutFailKey(key string) string  { return lockoutFailPrefix + hashTag(key) }
func lockoutUntilKey(key string) string { return lockoutUntilPrefix + hashTag(key) }

// IsLocked reports the lock state from the single lock-marker key. The marker
// auto-expires (PX = LockoutDuration) exactly at the deadline, so presence ==
// locked, and its stored value is that deadline — no clock arithmetic, the
// instant returned is byte-identical to the one RegisterFailure handed back.
func (s *AccountLockout) IsLocked(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	val, err := s.rdb.Get(ctx, lockoutUntilKey(key)).Result()
	if errors.Is(err, goredis.Nil) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, fmt.Errorf("redis: lockout lookup: %w", err)
	}
	return true, parseLockoutDeadline(val), nil
}

// registerFailureScript is the atomic INCR + conditional-EXPIRE + threshold
// engage, run server-side so two concurrent failures across replicas cannot
// both read count=N-1 and skip the lock (the exact per-pod race this backend
// fixes). An already-locked key short-circuits on the marker GET and returns
// its stored deadline WITHOUT advancing the counter — matching the memory
// peer's "already locked stays locked, no further increment" contract. The
// window TTL is set only when the counter is first created (count == 1); once
// it expires, the next INCR re-creates it at 1 with a fresh window.
//
// KEYS[1] = fail counter      KEYS[2] = lock marker
// ARGV[1] = maxFailures       ARGV[2] = failureWindowMs (PEXPIRE)
// ARGV[3] = lockoutMs (PX)    ARGV[4] = unlock-deadline unix nanos (string)
// Returns {lockedFlag, untilNanosString} — {0, ""} when not (yet) locked.
var registerFailureScript = goredis.NewScript(`
local lock = redis.call('GET', KEYS[2])
if lock then
  return {1, lock}
end
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
if n >= tonumber(ARGV[1]) then
  redis.call('SET', KEYS[2], ARGV[4], 'PX', ARGV[3])
  return {1, ARGV[4]}
end
return {0, ''}
`)

// RegisterFailure increments the shared counter and engages the lock on the
// threshold crossing. See the AccountLockout interface for the return
// contract; the atomicity guarantee lives in registerFailureScript.
func (s *AccountLockout) RegisterFailure(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	deadline := time.Now().Add(s.LockoutDuration).UnixNano()
	res, err := registerFailureScript.Run(ctx, s.rdb,
		[]string{lockoutFailKey(key), lockoutUntilKey(key)},
		strconv.Itoa(s.MaxFailures),
		strconv.FormatInt(s.FailureWindow.Milliseconds(), 10),
		strconv.FormatInt(s.LockoutDuration.Milliseconds(), 10),
		strconv.FormatInt(deadline, 10),
	).Result()
	if err != nil {
		return false, time.Time{}, fmt.Errorf("redis: lockout register failure: %w", err)
	}
	return parseFailureResult(res)
}

// parseFailureResult decodes the {flag, untilNanos} table the script returns.
// An unexpected shape is treated as "not locked" rather than erroring — the
// gate stays fail-open on a malformed reply, never wedging a real login.
func parseFailureResult(res any) (bool, time.Time, error) {
	vals, ok := res.([]any)
	if !ok || len(vals) != 2 {
		return false, time.Time{}, nil
	}
	flag, _ := vals[0].(int64)
	if flag == 0 {
		return false, time.Time{}, nil
	}
	until, _ := vals[1].(string)
	return true, parseLockoutDeadline(until), nil
}

// RegisterSuccess clears both keys for the subject. They share the {key} hash
// tag so the multi-key DEL lands in one slot (no CROSSSLOT) and is atomic.
// Idempotent on an unknown key — DEL of absent keys is a no-op.
func (s *AccountLockout) RegisterSuccess(ctx context.Context, key string) error {
	if key == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, lockoutFailKey(key), lockoutUntilKey(key)).Err(); err != nil {
		return fmt.Errorf("redis: lockout clear: %w", err)
	}
	return nil
}

// parseLockoutDeadline turns the stored unix-nanos string into a UTC instant.
// A blank / unparseable value yields the zero time (treated as "not locked").
func parseLockoutDeadline(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

var _ security.AccountLockout = (*AccountLockout)(nil)
