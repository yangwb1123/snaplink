package trust

import (
	"testing"
)

func FuzzClampScore(f *testing.F) {
	seeds := []float64{0.0, 0.5, 1.0, -1.0, 2.0, -0.5, 1.5}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v float64) {
		result := ClampScore(v)
		if result < 0.0 || result > 1.0 {
			t.Errorf("ClampScore(%f) = %f, out of [0,1]", v, result)
		}
	})
}

func FuzzFormatScore(f *testing.F) {
	seeds := []float64{0.0, 0.5, 1.0, 0.123, 0.999, 0.001}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v float64) {
		clamped := ClampScore(v)
		result := formatScore(clamped)
		if result == "" {
			t.Errorf("formatScore(%f) returned empty", clamped)
		}
		// Check format: exactly 2 decimal places
		if len(result) < 4 || result[len(result)-3] != '.' {
			t.Errorf("formatScore(%f) = %q, bad format", clamped, result)
		}
	})
}
