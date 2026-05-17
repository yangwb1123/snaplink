// Package ratelimit provides a token-bucket rate limiter and HTTP
// middleware for the SSO server. The headline use case is brute-force
// protection on /auth/login — without it, the server has no defense
// against credential stuffing.
//
// Two shapes shipped:
//
//   - Limiter SPI: pluggable bucket store. The in-process MemoryLimiter
//     here is the default; operators wanting cross-replica enforcement
//     can implement against Redis / Memcached / etcd.
//
//   - Policy + Middleware: a per-path policy table maps URL prefixes
//     to limiters, with a default for everything else. Keying is
//     pluggable (default: client IP); 429 responses include a
//     Retry-After header.
//
// Compose with [sso.WithRateLimit] for the default wiring, or call
// Middleware directly when the operator wants custom placement in
// their own middleware stack.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is the SPI implementations satisfy. Allow consults the
// bucket for key and either lets the request through (ok=true) or
// reports the wait until the next token (ok=false, retryAfter>0).
//
// Implementations must be safe for concurrent use.
type Limiter interface {
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// MemoryLimiter is a token-bucket limiter that keeps per-key state in
// the local process. Suitable for single-replica deployments; for HA
// rate limiting across replicas, plug in a Redis-backed Limiter.
//
// The bucket is sized by (perSecond, burst). Stale buckets are pruned
// on Allow when they haven't been touched for stalePruneAfter — keeps
// memory bounded even when keys (e.g. attacker IPs) cycle rapidly.
type MemoryLimiter struct {
	perSecond float64
	burst     int

	stalePruneAfter time.Duration

	mu      sync.Mutex
	buckets map[string]*bucketEntry
}

type bucketEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// Default cleanup horizon. Buckets idle longer than this get pruned
// on the next Allow. Conservative — most rate-limit use cases want
// buckets to expire quickly so memory doesn't accumulate on long-tail
// keys.
const defaultStalePruneAfter = 10 * time.Minute

// NewMemoryLimiter constructs a token bucket allowing perSecond
// sustained req/s with burst capacity. A bucket of burst=10 + rate=10/min
// means 10 immediate requests then 1 per 6 seconds.
//
// Per-second is float so operators can express "10 per minute" as
// 10.0/60 without rounding to zero.
func NewMemoryLimiter(perSecond float64, burst int) *MemoryLimiter {
	if burst < 1 {
		burst = 1
	}
	return &MemoryLimiter{
		perSecond:       perSecond,
		burst:           burst,
		stalePruneAfter: defaultStalePruneAfter,
		buckets:         make(map[string]*bucketEntry),
	}
}

// Allow returns whether key may issue another request now. When false,
// retryAfter is the duration until the next token — clients should
// receive this in the Retry-After header.
func (m *MemoryLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cheap stale pruning piggybacked on every Allow — bounded work
	// (the map iter cost grows with active keys, not history).
	m.pruneLocked(now)

	b, ok := m.buckets[key]
	if !ok {
		b = &bucketEntry{lim: rate.NewLimiter(rate.Limit(m.perSecond), m.burst)}
		m.buckets[key] = b
	}
	b.lastSeen = now

	reservation := b.lim.Reserve()
	if !reservation.OK() {
		// Reservation impossible (burst is 0 or rate is 0); deny without
		// a useful retry-after.
		return false, 0
	}
	wait := reservation.Delay()
	if wait > 0 {
		// Don't actually wait — return Retry-After to the caller so the
		// client can back off. Cancel the reservation so the bucket
		// isn't charged for the rejected request.
		reservation.Cancel()
		return false, wait
	}
	return true, 0
}

// Buckets returns the current number of tracked keys. Test-only;
// keeps the field unexported for production use.
func (m *MemoryLimiter) Buckets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

// pruneLocked is called with mu held.
func (m *MemoryLimiter) pruneLocked(now time.Time) {
	for k, b := range m.buckets {
		if now.Sub(b.lastSeen) > m.stalePruneAfter {
			delete(m.buckets, k)
		}
	}
}
