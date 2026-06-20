package oidcsupport

import (
	"slices"
	"testing"
)

func TestParsePromptValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want []string
	}{
		{raw: "", want: nil},
		{raw: "none", want: []string{"none"}},
		{raw: "login consent", want: []string{"login", "consent"}},
		{raw: "  login  consent  ", want: []string{"login", "consent"}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got := ParsePromptValues(tc.raw)
			if tc.want == nil {
				if got != nil {
					t.Errorf("ParsePromptValues(%q) = %v, want nil", tc.raw, got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePromptValues(%q) = %v (len=%d), want %v (len=%d)", tc.raw, got, len(got), tc.want, len(tc.want))
			}
			for _, v := range tc.want {
				if !slices.Contains(got, v) {
					t.Errorf("ParsePromptValues(%q) missing %q, got %v", tc.raw, v, got)
				}
			}
		})
	}
}

func TestParsePromptValuesDeduplicates(t *testing.T) {
	t.Parallel()

	got := ParsePromptValues("none none")
	if len(got) != 1 {
		t.Fatalf("expected 1 unique value, got %d: %v", len(got), got)
	}
	if got[0] != "none" {
		t.Errorf("expected 'none', got %q", got[0])
	}
}

func TestPromptHasNone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "explicit none", values: []string{"none"}, want: true},
		{name: "none with others", values: []string{"login", "none", "consent"}, want: true},
		{name: "no none", values: []string{"login", "consent"}, want: false},
		{name: "empty", values: nil, want: false},
		{name: "similar name", values: []string{"nonenone"}, want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PromptHasNone(tc.values)
			if got != tc.want {
				t.Errorf("PromptHasNone(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

func TestScopeContainsOpenID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{name: "contains openid", scopes: []string{"openid", "profile"}, want: true},
		{name: "openid only", scopes: []string{"openid"}, want: true},
		{name: "no openid", scopes: []string{"profile", "email"}, want: false},
		{name: "empty", scopes: nil, want: false},
		{name: "no false match", scopes: []string{"openid_extra"}, want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ScopeContainsOpenID(tc.scopes)
			if got != tc.want {
				t.Errorf("ScopeContainsOpenID(%v) = %v, want %v", tc.scopes, got, tc.want)
			}
		})
	}
}
