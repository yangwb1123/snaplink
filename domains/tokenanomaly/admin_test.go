package tokenanomaly

import (
	"testing"
)

func TestParseLimit(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"10", 10},
		{"0", 0},
		{"-1", 0},
		{"", 0},
		{"abc", 0},
		{"1000", 1000},
	}

	for _, tc := range tests {
		got := parseLimit(tc.input)
		if got != tc.want {
			t.Errorf("parseLimit(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseLimitNonNegative(t *testing.T) {
	// Even very large numbers are accepted
	result := parseLimit("99999")
	if result != 99999 {
		t.Errorf("expected 99999, got %d", result)
	}
}
