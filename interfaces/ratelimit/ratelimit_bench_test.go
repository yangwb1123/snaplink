package ratelimit

// Hot-path benchmarks for MemoryLimiter.Allow — the per-request gate
// run on /token, /auth/login, and every other rate-limited endpoint in
// front of the auth-heavy hot path.
//
// Three regimes are measured deliberately:
//
//   - SingleKey: the steady-state cost of one bucket (shard lookup +
//     token-bucket reserve).
//
//   - ManyKeys: the sampled-prune hot path. With 1-in-64 sampling and
//     16 shards, each prune scans ~N/16 entries instead of N. Compare
//     ns/op across N=100/1000/10000 against the old O(N) baseline —
//     growth should be ~flat between prune events rather than linear.
//
//   - Parallel: 16 goroutines hammering Allow concurrently from a small
//     key pool. This is the contention regression test: with 16 shards
//     the goroutines are mostly hitting distinct locks, so throughput
//     should scale near-linearly rather than serialising on one mutex.
//
// New file, dep-free (std testing only). b.ReportAllocs() + package-level
// sinks so the allow decision can't be elided.

import (
	"strconv"
	"testing"
)

var (
	benchAllowSink bool
	benchRetrySink int64
)

// benchLimiter uses a high rate + large burst so Allow stays on the
// "allowed" branch — the benchmark measures the limiter machinery, not
// the rejected-path Reserve/Cancel dance.
func benchLimiter() *MemoryLimiter {
	return NewMemoryLimiter(1e9, 1<<30)
}

// BenchmarkMemoryLimiterAllowSingleKey: steady-state cost with exactly
// one resident bucket.
func BenchmarkMemoryLimiterAllowSingleKey(b *testing.B) {
	m := benchLimiter()
	const key = "client-ip:203.0.113.7"
	// Warm the bucket so iteration 1 isn't a one-time map insert.
	m.Allow(key)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, retry := m.Allow(key)
		benchAllowSink, benchRetrySink = ok, int64(retry)
	}
}

// BenchmarkMemoryLimiterAllowManyKeys measures the sampled-prune hot
// path under a large resident key set. The map is PRE-POPULATED with n
// live keys; each Allow call is served from that set. With 1-in-64
// sampling the per-call cost is mostly the shard lock + bucket reserve,
// not a full map scan — compare ns/op against the old linear baseline.
func BenchmarkMemoryLimiterAllowManyKeys(b *testing.B) {
	for _, keyCount := range []int{100, 1000, 10000} {
		b.Run(strconv.Itoa(keyCount), func(b *testing.B) {
			m := benchLimiter()
			keys := make([]string, keyCount)
			for i := 0; i < keyCount; i++ {
				keys[i] = "client-ip:10." +
					strconv.Itoa(i/65536%256) + "." +
					strconv.Itoa(i/256%256) + "." +
					strconv.Itoa(i%256) + ":" + strconv.Itoa(i)
				// Seed the bucket so it is resident (and recently seen,
				// so pruneLocked keeps it — the prune cost grows with
				// the per-shard slice, ~N/numShards, not N).
				m.Allow(keys[i])
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, retry := m.Allow(keys[i%keyCount])
				benchAllowSink, benchRetrySink = ok, int64(retry)
			}
		})
	}
}

// BenchmarkMemoryLimiterAllowParallel measures contention under
// concurrent goroutines drawing from a small shared key pool. With
// sharded locks, goroutines on different keys run in parallel; only
// goroutines that hash to the same shard contend.
//
// Goroutine-local result variables are used instead of the shared
// package-level sinks to keep the benchmark race-free under -race.
func BenchmarkMemoryLimiterAllowParallel(b *testing.B) {
	m := benchLimiter()
	// Small pool so keys collide across goroutines — stress the locks.
	const poolSize = 32
	keys := make([]string, poolSize)
	for i := range poolSize {
		keys[i] = "ip:10.0.0." + strconv.Itoa(i)
		m.Allow(keys[i]) // warm
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Goroutine-local sinks prevent data races; the compiler cannot
		// elide the Allow call because the results feed an escaping var.
		var ok bool
		var retry int64
		i := 0
		for pb.Next() {
			ok, retry = func() (bool, int64) {
				o, r := m.Allow(keys[i%poolSize])
				return o, int64(r)
			}()
			i++
		}
		// Ensure ok/retry are not optimised away.
		if !ok && retry < 0 {
			panic("unreachable")
		}
	})
}
