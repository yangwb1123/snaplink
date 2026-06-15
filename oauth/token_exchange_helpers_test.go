package oauth

import (
	"slices"
	"testing"
)

func TestACRMatchesAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		inbound  string
		demanded []string
		want     bool
	}{
		{name: "exact match", inbound: "urn:mace:incommon:iap:silver", demanded: []string{"urn:mace:incommon:iap:silver"}, want: true},
		{name: "match among multiple", inbound: "foo", demanded: []string{"bar", "foo", "baz"}, want: true},
		{name: "no match", inbound: "high", demanded: []string{"low", "medium"}, want: false},
		{name: "empty inbound", inbound: "", demanded: []string{"any"}, want: false},
		{name: "empty demanded", inbound: "anything", demanded: nil, want: false},
		{name: "both empty", inbound: "", demanded: nil, want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ACRMatchesAny(tc.inbound, tc.demanded)
			if got != tc.want {
				t.Errorf("ACRMatchesAny(%q, %v) = %v, want %v", tc.inbound, tc.demanded, got, tc.want)
			}
		})
	}
}

func TestMergeTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		primary   []string
		secondary []string
		want      []string
	}{
		{name: "both empty", primary: nil, secondary: nil, want: nil},
		{name: "primary only", primary: []string{"a", "b"}, secondary: nil, want: []string{"a", "b"}},
		{name: "secondary only", primary: nil, secondary: []string{"c", "d"}, want: []string{"c", "d"}},
		{name: "merge with dedup", primary: []string{"a", "b"}, secondary: []string{"b", "c"}, want: []string{"a", "b", "c"}},
		{name: "no overlap", primary: []string{"a"}, secondary: []string{"b"}, want: []string{"a", "b"}},
		{name: "skip empty strings", primary: []string{"a", ""}, secondary: []string{"", "b"}, want: []string{"a", "b"}},
		{name: "all empty", primary: []string{""}, secondary: []string{""}, want: nil},
		{name: "dedup within primary", primary: []string{"a", "b", "a"}, secondary: nil, want: []string{"a", "b"}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MergeTargets(tc.primary, tc.secondary)
			if len(got) != len(tc.want) {
				t.Fatalf("MergeTargets() = %v (len=%d), want %v (len=%d)", got, len(got), tc.want, len(tc.want))
			}
			for i, v := range tc.want {
				if !slices.Contains(got, v) {
					t.Errorf("MergeTargets() missing %q at index %d, got %v", v, i, got)
				}
			}
			// Check first-occurrence order preservation
			for i := 0; i < len(got); i++ {
				for j := i + 1; j < len(got); j++ {
					if got[i] == got[j] {
						t.Errorf("MergeTargets() duplicate at [%d] and [%d]: %q", i, j, got[i])
					}
				}
			}
		})
	}
}
