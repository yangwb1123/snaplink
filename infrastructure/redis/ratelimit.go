package redis

import (
	"context"
	"errors"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
)

const rateLimitKeyPrefix = "sso:ratelimit:" // sso:ratelimit:<bucket>:<key> -> counter

// Limiter is the Redis-backed [ratelimit.Limiter] for the throughput /
// multi-replica layer — the genuinely-hot store, consulted on EVERY
// request that passes through the rate-limit middleware (brute-force
// protection on /auth/login above all). Counter state lives in shared
// Redis so a key that exhausted its budget on replica A is already over
// the limit on replica B; the cross-replica defense the in-process
// MemoryLimiter cannot give.
//
// # Window model
//
// This is a FIXED-WINDOW counter (limit requests per window), not the
// token-bucket the MemoryLimiter / SQLiteLimiter peers use. Fixed-window
// is the idiomatic Redis primitive: a single INCR is atomic, and one
// EXPIRE on the first hit of a window bounds the keyspace to the active
// window with no GC. The wire contract — Allow(key) (ok, retryAfter) — is
// identical to the token-bucket peers; only the smoothing differs (a
// fixed window admits up to limit in a burst at the window edge, vs. the
// bucket's steady drip). For brute-force defense this is the standard and
// sufficient shape. Operators who need bucket-exact smoothing across
// replicas should keep the SQLiteLimiter; operators who want the
// token-bucket knobs mapped onto a window can use [NewLimiterFromRate].
type Limiter struct {
	rdb        goredis.Cmdable
	limit      int64
	window     time.Duration
	bucketName string
}

// NewLimiter builds a fixed-window limiter allowing limit requests per
// window for each key. bucketName scopes the keyspace so multiple
// Limiters (one per Policy prefix rule) can share one Redis without
// colliding — pass "" for a single-Limiter deployment, distinct names
// when several share the client. limit < 1 is floored to 1; a
// non-positive window is floored to one second.
func NewLimiter(rdb goredis.Cmdable, limit int, window time.Duration, bucketName string) *Limiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Second
	}
	return &Limiter{rdb: rdb, limit: int64(limit), window: window, bucketName: bucketName}
}

// NewLimiterFromRate builds a fixed-window limiter from the same
// (perSecond, burst) knobs the MemoryLimiter / SQLiteLimiter take, for
// operators wiring all three backends off one config. The window is
// sized so the average admitted rate matches perSecond and the per-window
// allowance equals burst: window = burst / perSecond, limit = burst. A
// non-positive perSecond yields a deny-all limiter (limit 1 over a very
// long window) — the fixed-window analogue of the bucket's "deny
// everything" configuration.
func NewLimiterFromRate(rdb goredis.Cmdable, perSecond float64, burst int, bucketName string) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if perSecond <= 0 {
		// Deny-all: a single request per ~year window. Matches the
		// token-bucket peers' behavior when perSecond<=0 and the bucket
		// drains (no refill ever arrives).
		return NewLimiter(rdb, 1, 365*24*time.Hour, bucketName)
	}
	window := time.Duration(float64(burst) / perSecond * float64(time.Second))
	if window <= 0 {
		window = time.Second
	}
	return NewLimiter(rdb, burst, window, bucketName)
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (l *Limiter) Ping(ctx context.Context) error {
	if l == nil || l.rdb == nil {
		return errors.New("redis: rate limiter not initialized")
	}
	return l.rdb.Ping(ctx).Err()
}

func (l *Limiter) key(k string) string {
	return rateLimitKeyPrefix + l.bucketName + ":" + k
}

// allowScript is the atomic INCR + conditional-EXPIRE + over-limit check.
//
// Why a script and not INCR-then-EXPIRE as two client calls: if the
// process (or network) dies between a first-hit INCR and its EXPIRE, the
// key would have NO TTL and the counter would pin that key at its limit
// FOREVER — a permanent self-inflicted lockout of a legitimate IP. The
// script makes "INCR, and set the window TTL iff this was the first hit"
// one indivisible server-side op, so the TTL is set exactly when the
// window opens and can never be lost. It also returns the remaining TTL
// so the caller can compute an accurate Retry-After (the time until the
// window resets), and miniredis evaluates it identically to real Redis.
//
// KEYS[1] = counter key   ARGV[1] = window seconds   ARGV[2] = limit
// returns {count, pttl_ms}
var allowScript = goredis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local pttl = redis.call('PTTL', KEYS[1])
return {count, pttl}
`)

// Allow implements [ratelimit.Limiter] over a fixed window.
//
// It INCRs the per-(bucket,key) counter and sets the window TTL on the
// first hit (atomically — see allowScript). The request is admitted while
// the post-increment count is within limit; once it exceeds limit the
// request is denied and retryAfter is the time until the window resets
// (the key's remaining TTL).
//
// Fails OPEN on any Redis error, matching the MemoryLimiter /
// SQLiteLimiter peers and the §2 "ratelimit lookup is a defense layer,
// not a correctness layer" stance: a Redis partition must not 503 real
// users (the underlying authenticator still gates credentials), and a
// degraded limiter erring toward admit adds zero attacker value it
// didn't already have without a limiter at all.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	ctx := context.Background()
	windowSecs := int64(l.window / time.Second)
	if windowSecs < 1 {
		windowSecs = 1
	}

	res, err := allowScript.Run(ctx, l.rdb, []string{l.key(key)},
		strconv.FormatInt(windowSecs, 10), strconv.FormatInt(l.limit, 10)).Result()
	if err != nil {
		return true, 0 // fail-open
	}
	vals, ok := res.([]interface{})
	if !ok || len(vals) != 2 {
		return true, 0 // unexpected shape; fail-open
	}
	count, ok1 := vals[0].(int64)
	pttlMs, ok2 := vals[1].(int64)
	if !ok1 || !ok2 {
		return true, 0
	}

	if count <= l.limit {
		return true, 0
	}
	// Over the limit. Retry-After is the time until the window resets.
	// PTTL is -1 (no expiry, shouldn't happen given the script) or -2
	// (key gone, evicted between INCR and PTTL); both floor to the full
	// window so the client gets a sane non-negative backoff.
	if pttlMs < 0 {
		return false, l.window
	}
	return false, time.Duration(pttlMs) * time.Millisecond
}

var _ ratelimit.Limiter = (*Limiter)(nil)
