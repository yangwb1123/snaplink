package oidc

import (
	"testing"
)

func TestIsJARMResponseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want bool
	}{
		{"jwt", true},
		{"query.jwt", true},
		{"fragment.jwt", true},
		{"form_post.jwt", true},
		{"query", false},
		{"fragment", false},
		{"form_post", false},
		{"", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			got := IsJARMResponseMode(tc.mode)
			if got != tc.want {
				t.Errorf("IsJARMResponseMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
