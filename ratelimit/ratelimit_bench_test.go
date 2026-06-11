package ratelimit

// Hot-path benchmarks for MemoryLimiter.Allow — the per-request gate
// run on /token, /auth/login, and every other rate-limited endpoint in
// front of the auth-heavy hot path.
//
// Two regimes are measured deliberately:
//
//   - SingleKey: the steady-state cost of one bucket (lock + one-entry
//     prune + token-bucket reserve).
//
//   - ManyKeys: the documented O(N) hot path. Every Allow takes the
//     GLOBAL lock and calls pruneLocked, which iterates the ENTIRE
//     bucket map. As the resident key set grows (e.g. per-client-IP
//     keying under a wide client fleet or an IP-spray attack), the cost
//     of each Allow grows with the number of live keys — under one
//     mutex. The ManyKeys/N sub-benchmarks make that growth explicit:
//     compare ns/op across N=100 / 1000 / 10000 to see the linear prune
//     cost. This is the benchmark that matters for capacity planning.
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

// BenchmarkMemoryLimiterAllowManyKeys exposes the O(N) full-map prune
// under the global lock. The map is PRE-POPULATED with n live keys, then
// the loop calls Allow with rotating keys drawn from that resident set —
// so every Allow pays the full n-entry pruneLocked scan. Read the
// per-N ns/op: it should climb roughly linearly with keyCount, which is
// exactly the contention/scaling hazard the docs call out.
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
				// so pruneLocked keeps it — every Allow then scans all n).
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
