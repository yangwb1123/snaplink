package redis

import (
	"context"
	"math"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// tokenBucketKeyPrefix scopes the smooth-limiter keys (distinct from the
// fixed-window counter keys so both can coexist on one Redis).
const tokenBucketKeyPrefix = "sso:ratelimitbucket:" // sso:ratelimitbucket:<bucket>:<key> -> {tokens, last_refill_ts}

// TokenBucketLimiter is the Redis-backed smooth [ratelimit.Limiter] — the
// cross-replica token bucket the fixed-window Limiter's doc points to for
// "bucket-exact smoothing across replicas". The bucket state lives in one
// key per (bucket, key); the Lua script refills it against the SERVER clock
// (redis.call('TIME'), never the client's — the clock-drift discipline the
// fixed-window script already follows), so a key that exhausted its budget
// on replica A is already empty on replica B and the effective limit is
// exactly the configured one, not N x per replica.
//
// Unlike the fixed-window counter, the bucket admits at most `burst` tokens
// back-to-back and then drips at `rate` per second — no 2x burst at window
// edges, which is the brute-force-defense shape /auth/login wants.
//
// Fails OPEN on any Redis error, matching every limiter peer: a Redis
// partition must not 503 real users (the underlying authenticator still
// gates credentials).
type TokenBucketLimiter struct {
	rdb        goredis.Cmdable
	rate       float64 // tokens per second
	burst      float64 // capacity
	ttl        time.Duration
	bucketName string
}

// NewTokenBucketLimiter builds a distributed token-bucket limiter allowing
// burst tokens back-to-back then rate per second, per key. bucketName
// scopes the keyspace (one per Policy prefix rule). rate <= 0 or burst < 1
// are floored to a functional minimum (rate = 1e-6, burst = 1) so a
// misconfiguration degrades to "practically denied", never a div-by-zero.
func NewTokenBucketLimiter(rdb goredis.Cmdable, rate float64, burst int, bucketName string) *TokenBucketLimiter {
	if rate <= 0 {
		rate = 1e-6
	}
	if burst < 1 {
		burst = 1
	}
	// Idle expiry: the key survives while traffic flows (every touch
	// refreshes it) and a silent key resets to full after ~2 full-bucket
	// refill periods — the bucket equivalent of a window reset.
	idle := time.Duration(math.Max(2*float64(burst)/rate*1000, 1000)) * time.Millisecond
	return &TokenBucketLimiter{
		rdb: rdb, rate: rate, burst: float64(burst),
		ttl: idle, bucketName: bucketName,
	}
}

func (l *TokenBucketLimiter) key(k string) string {
	return tokenBucketKeyPrefix + l.bucketName + ":" + k
}

// tokenBucketScript refills and consumes one token atomically.
//
// KEYS[1] = bucket key
// ARGV[1] = rate (tokens/sec)  ARGV[2] = burst (capacity)
// ARGV[3] = idle ttl ms
// returns {ok, retry_after_ms}
//
// The refill uses redis.call('TIME') — the server clock — so replica clock
// skew cannot double-refill or starve a bucket, and the state encoding is
// cjson (supported by miniredis identically to real Redis). The TTL is
// refreshed on EVERY touch (allow and deny), so an exhausted bucket stays
// remembered while the caller is being throttled.
var tokenBucketScript = goredis.NewScript(`
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])
local now = redis.call('TIME')
local now_s = now[1] + now[2] / 1000000

local state = redis.call('GET', KEYS[1])
local tokens = burst
local last = now_s
if state then
  local t = cjson.decode(state)
  tokens = tonumber(t[1])
  last = tonumber(t[2])
  tokens = math.min(burst, tokens + (now_s - last) * rate)
end

local ok = 0
local retry_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  ok = 1
else
  retry_ms = math.ceil((1 - tokens) / rate * 1000)
end

redis.call('SET', KEYS[1], cjson.encode({tokens, now_s}), 'PX', ttl_ms)
return {ok, retry_ms}
`)

// Allow implements [ratelimit.Limiter]: consumes one token when the bucket
// has one, otherwise denies with the time until the next token drips in.
func (l *TokenBucketLimiter) Allow(key string) (bool, time.Duration) {
	res, err := tokenBucketScript.Run(context.Background(), l.rdb,
		[]string{l.key(key)}, l.rate, l.burst, float64(l.ttl.Milliseconds())).Result()
	if err != nil {
		// Fail open: a Redis partition must not lock real users out.
		return true, 0
	}
	vals, ok := res.([]any)
	if !ok || len(vals) != 2 {
		return true, 0
	}
	okN, _ := vals[0].(int64)
	retryMs, _ := vals[1].(int64)
	if okN == 1 {
		return true, 0
	}
	return false, time.Duration(retryMs) * time.Millisecond
}
