package trust

import (
	"testing"
	"testing/quick"
)

func TestClampScoreQuick(t *testing.T) {
	f := func(v float64) bool {
		result := ClampScore(v)
		return result >= 0.0 && result <= 1.0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestFormatScoreQuick(t *testing.T) {
	f := func(v float64) bool {
		// Clamp then format - should never panic and always produce valid output
		clamped := ClampScore(v)
		result := formatScore(clamped)
		if result == "" {
			return false
		}
		// Should have exactly 2 decimal places
		if len(result) < 4 || result[len(result)-3] != '.' {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestClampScoreIsIdempotent(t *testing.T) {
	f := func(v float64) bool {
		first := ClampScore(v)
		second := ClampScore(first)
		return first == second
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
