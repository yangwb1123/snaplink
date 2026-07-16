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
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memreaper"
)

// Limiter is the SPI implementations satisfy. Allow consults the
// bucket for key and either lets the request through (ok=true) or
// reports the wait until the next token (ok=false, retryAfter>0).
//
// Implementations must be safe for concurrent use.
type Limiter interface {
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// numShards is the number of independent lock+map shards inside
// MemoryLimiter. Must be a power of two so the shard index is a cheap
// bitmask. 16 shards reduces worst-case lock contention to 1/16 of the
// single-mutex baseline and is allocation-free (fixed-size array on the
// struct, no heap).
const numShards = 16

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucketEntry
}

// MemoryLimiter is a token-bucket limiter that keeps per-key state in
// the local process. Suitable for single-replica deployments; for HA
// rate limiting across replicas, plug in a Redis-backed Limiter.
//
// The bucket is sized by (perSecond, burst). Stale buckets are pruned
// lazily: the limiter samples 1-in-64 Allow calls (globally) and prunes
// only the shard touched by that call — this amortizes the O(N/shards)
// scan cost without accumulating unbounded memory even under IP-spray
// attacks with rapidly cycling keys.
//
// Lock sharding (16 independent mutex+map pairs, keyed by FNV-32a hash
// of the request key) parallelises legitimate traffic and limits the
// blast radius of any single contended bucket to 1/16 of the key space.
type MemoryLimiter struct {
	perSecond float64
	burst     int

	stalePruneAfter time.Duration

	shards [numShards]shard

	// calls counts every Allow invocation across all goroutines.
	// Prune fires on the shard servicing the 64th call (and every
	// subsequent multiple of 64), matching the SQLite peer's ratio.
	calls atomic.Uint64

	// pruning is true while a background StartPruner sweep is active, so
	// Allow's own sampled inline prune stops running its O(N) shard scan —
	// see StartPruner's doc for why.
	pruning atomic.Bool
	reaper  *memreaper.Reaper
}

type bucketEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// Default cleanup horizon. Buckets idle longer than this get pruned
// on a sampled Allow. Conservative — most rate-limit use cases want
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
	m := &MemoryLimiter{
		perSecond:       perSecond,
		burst:           burst,
		stalePruneAfter: defaultStalePruneAfter,
	}
	for i := range m.shards {
		m.shards[i].buckets = make(map[string]*bucketEntry)
	}
	return m
}

// NewMemoryLimiterWithStalePrune is like NewMemoryLimiter but lets the
// caller set a custom stalePruneAfter horizon. Intended for tests that
// need to age-out buckets quickly without waiting 10 minutes.
func NewMemoryLimiterWithStalePrune(perSecond float64, burst int, stalePruneAfter time.Duration) *MemoryLimiter {
	m := NewMemoryLimiter(perSecond, burst)
	m.stalePruneAfter = stalePruneAfter
	return m
}

// shardIndex returns the shard index for key using FNV-32a. The hash
// is allocation-free and cheap relative to the token-bucket Reserve call.
func shardIndex(key string) uint32 {
	h := fnv.New32a()
	// Write never returns an error for hash.Hash32.
	_, _ = h.Write([]byte(key))
	return h.Sum32() & (numShards - 1)
}

// Allow returns whether key may issue another request now. When false,
// retryAfter is the duration until the next token — clients should
// receive this in the Retry-After header.
func (m *MemoryLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()
	idx := shardIndex(key)
	sh := &m.shards[idx]

	// Sampled pruning: fire pruneLocked on 1-in-64 calls to amortize
	// the map-scan cost. The counter is global and atomic — cheap,
	// allocation-free, and correct under any concurrency. Matches the
	// SQLite peer (sqlite_limiter.go, same 1/64 ratio).
	//
	// Skipped entirely once a background StartPruner is active: the O(N)
	// shard scan below runs INSIDE this shard's lock, so a high-cardinality
	// attack repeatedly hashing to the same shard would otherwise make
	// pruneLocked increasingly expensive while holding that shard's lock,
	// blocking every other request hashed to it — the rate limiter
	// amplifying, rather than absorbing, the very attack it exists to stop.
	prune := !m.pruning.Load() && m.calls.Add(1)%64 == 0

	sh.mu.Lock()
	defer sh.mu.Unlock()

	if prune {
		m.pruneLocked(sh, now)
	}

	b, ok := sh.buckets[key]
	if !ok {
		b = &bucketEntry{lim: rate.NewLimiter(rate.Limit(m.perSecond), m.burst)}
		sh.buckets[key] = b
	}
	b.lastSeen = now

	return m.reserve(b)
}

// reserve consumes one token from b's underlying rate.Limiter and reports
// the Allow decision. Split out of Allow to keep it under the function-length
// budget; b.lastSeen and the shard lock are the caller's responsibility.
func (m *MemoryLimiter) reserve(b *bucketEntry) (bool, time.Duration) {
	reservation := b.lim.Reserve()
	if !reservation.OK() {
		// Reservation impossible (n exceeds burst); deny without a
		// useful retry-after. In practice unreachable since burst is
		// clamped to >=1 and n is always 1, but Reserve's contract
		// requires the check.
		return false, 0
	}
	wait := reservation.Delay()
	if wait == 0 {
		return true, 0
	}
	// Don't actually wait — return Retry-After to the caller so the
	// client can back off. Cancel the reservation so the bucket isn't
	// charged for the rejected request.
	reservation.Cancel()
	if m.perSecond <= 0 {
		// A zero (or negative) rate never refills the bucket, so
		// golang.org/x/time/rate.Reservation.Delay reports its ~292-year
		// InfDuration sentinel rather than a real wait. Left unguarded,
		// writeTooManyRequests would round that to a multi-billion-second
		// Retry-After header. Collapse to 0, matching the SQLiteLimiter
		// peer's denyAll contract (sqlite_limiter.go consumeToken) — deny
		// with no useful retry-after instead of a nonsensical one.
		return false, 0
	}
	return false, wait
}

// StartPruner launches a background goroutine sweeping every shard for
// stale entries on a fixed interval, each shard's own brief Lock/Unlock —
// never blocking Allow for longer than one shard's worth of work. Once
// active, Allow's sampled inline prune stops running its own O(N) scan (see
// Allow's doc for why that matters under a high-cardinality attack hashing
// repeatedly to one shard). A non-positive interval is a no-op and disables
// pruning-on-Allow too, matching StartReaper's sibling stores' contract. Not
// started by default: without it, Allow's existing sampled inline prune
// keeps running exactly as before this method existed (byte-identical).
// Idempotent — calling it again stops the previous pruner first.
func (m *MemoryLimiter) StartPruner(interval time.Duration) {
	_ = m.reaper.Close()
	m.pruning.Store(interval > 0)
	if interval <= 0 {
		return
	}
	m.reaper = memreaper.Start(interval, func(now time.Time) {
		for i := range m.shards {
			sh := &m.shards[i]
			sh.mu.Lock()
			m.pruneLocked(sh, now)
			sh.mu.Unlock()
		}
	})
}

// Close stops the background pruner started via StartPruner, if any.
func (m *MemoryLimiter) Close() error {
	m.pruning.Store(false)
	return m.reaper.Close()
}

// Buckets returns the total number of tracked keys across all shards.
// Test-only; keeps the field unexported for production use.
func (m *MemoryLimiter) Buckets() int {
	total := 0
	for i := range m.shards {
		sh := &m.shards[i]
		sh.mu.Lock()
		total += len(sh.buckets)
		sh.mu.Unlock()
	}
	return total
}

// pruneLocked scans sh.buckets for stale entries. Called with sh.mu held.
func (m *MemoryLimiter) pruneLocked(sh *shard, now time.Time) {
	for k, b := range sh.buckets {
		if time.Since(b.lastSeen) > m.stalePruneAfter {
			delete(sh.buckets, k)
		}
	}
}
