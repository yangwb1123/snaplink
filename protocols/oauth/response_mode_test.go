package oauth

import (
	"testing"
)

func TestIsValidResponseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want bool
	}{
		{"query", true},
		{"fragment", true},
		{"form_post", true},
		{"jwt", false},
		{"query.jwt", false},
		{"", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			got := IsValidResponseMode(tc.mode)
			if got != tc.want {
				t.Errorf("IsValidResponseMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
