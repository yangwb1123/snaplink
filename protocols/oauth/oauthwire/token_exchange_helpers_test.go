package oauthwire

import (
	"testing"
)

func TestACRMatchesAny(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		if !ACRMatchesAny("https://acr.example.com/2fa", []string{"https://acr.example.com/2fa"}) {
			t.Error("expected exact match")
		}
	})

	t.Run("trailing space is no match", func(t *testing.T) {
		if ACRMatchesAny("https://acr.example.com/2fa ", []string{"https://acr.example.com/2fa"}) {
			t.Error("trailing space should not match (exact comparison)")
		}
	})

	t.Run("no match in demanded list", func(t *testing.T) {
		if ACRMatchesAny("https://acr.example.com/phr", []string{"https://acr.example.com/2fa"}) {
			t.Error("expected no match for different ACR")
		}
	})

	t.Run("empty demanded list", func(t *testing.T) {
		if ACRMatchesAny("https://acr.example.com/phr", nil) {
			t.Error("expected no match for empty demanded list")
		}
	})

	t.Run("empty inbound", func(t *testing.T) {
		if ACRMatchesAny("", []string{"https://acr.example.com/2fa"}) {
			t.Error("expected no match for empty inbound")
		}
	})

	t.Run("match one of many", func(t *testing.T) {
		if !ACRMatchesAny("acr-value-2", []string{"acr-value-1", "acr-value-2", "acr-value-3"}) {
			t.Error("expected match for one of many")
		}
	})
}

func TestMergeTargets(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		result := MergeTargets(nil, nil)
		if len(result) != 0 {
			t.Errorf("expected empty, got %v", result)
		}
	})

	t.Run("primary only", func(t *testing.T) {
		result := MergeTargets([]string{"a", "b"}, nil)
		if len(result) != 2 {
			t.Errorf("expected 2 items, got %d", len(result))
		}
	})

	t.Run("secondary only", func(t *testing.T) {
		result := MergeTargets(nil, []string{"c", "d"})
		if len(result) != 2 {
			t.Errorf("expected 2 items, got %d", len(result))
		}
	})

	t.Run("merge with dedup", func(t *testing.T) {
		result := MergeTargets([]string{"a", "b"}, []string{"b", "c"})
		if len(result) != 3 {
			t.Errorf("expected 3 items (dedup), got %d: %v", len(result), result)
		}
	})

	t.Run("merge with all duplicates", func(t *testing.T) {
		result := MergeTargets([]string{"a"}, []string{"a"})
		if len(result) != 1 {
			t.Errorf("expected 1 item, got %d: %v", len(result), result)
		}
	})

	t.Run("merge empty with values", func(t *testing.T) {
		result := MergeTargets([]string{}, []string{"x"})
		if len(result) != 1 {
			t.Errorf("expected 1 item, got %d", len(result))
		}
	})

	t.Run("order preservation", func(t *testing.T) {
		result := MergeTargets([]string{"first", "second"}, []string{"third"})
		if result[0] != "first" || result[1] != "second" || result[2] != "third" {
			t.Errorf("expected order [first second third], got %v", result)
		}
	})
}
