package trust_test

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/trust"
)

func TestClampScore(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want float64
	}{
		{"below_zero", -0.5, 0},
		{"zero", 0, 0},
		{"mid", 0.42, 0.42},
		{"one", 1, 1},
		{"above_one", 1.5, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := trust.ClampScore(tc.in); got != tc.want {
				t.Fatalf("ClampScore(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
