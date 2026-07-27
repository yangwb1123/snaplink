package trust

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func BenchmarkClampScore(b *testing.B) {
	values := []float64{-1.0, -0.5, 0.0, 0.5, 1.0, 1.5}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClampScore(values[i%len(values)])
	}
}

func BenchmarkFormatScore(b *testing.B) {
	values := []float64{0.0, 0.25, 0.5, 0.75, 1.0}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatScore(values[i%len(values)])
	}
}

func BenchmarkDecayedScore(b *testing.B) {
	cfg := DecayConfig{Interval: 24 * time.Hour, Factor: 0.95, Floor: 0.2, MinScore: 0.1}
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session := core.Session{TrustScore: 0.8, TrustSetAt: now.Add(-72 * time.Hour)}
		DecayedScore(session, now, cfg)
	}
}
