package sso

import (
	"testing"

	"github.com/snaplink/sso/internal/auth/consent"
)

func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"ABCD-EFGH", "ABCDEFGH"},
		{"abcd-efgh", "ABCDEFGH"},
		{"", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := normalizeUserCode(tc.input)
			if got != tc.want {
				t.Errorf("normalizeUserCode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSplitScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  []string
	}{
		{"openid profile email", []string{"openid", "profile", "email"}},
		{"openid", []string{"openid"}},
		{"", nil},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := splitScope(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("splitScope(%q) = %v (len=%d), want %v (len=%d)", tc.input, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("splitScope(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestURLQueryEscape(t *testing.T) {
	t.Parallel()

	if got := urlQueryEscape(""); got != "" {
		t.Errorf("urlQueryEscape('') = %q, want empty", got)
	}
	if got := urlQueryEscape("a b"); got != "a+b" {
		t.Errorf("urlQueryEscape('a b') = %q, want 'a+b'", got)
	}
}

func TestHasPromptValue(t *testing.T) {
	t.Parallel()

	if !consent.HasPromptValue("login consent", "login") {
		t.Error("hasPromptValue should find 'login' in space-separated prompt")
	}
	if consent.HasPromptValue("login consent", "none") {
		t.Error("hasPromptValue should not find 'none'")
	}
}

func TestConsentScopesMatch(t *testing.T) {
	t.Parallel()

	if !consent.ScopesMatch([]string{"openid"}, []string{"openid"}) {
		t.Error("consentScopesMatch(equal) should be true")
	}
	if consent.ScopesMatch([]string{"openid"}, []string{"profile"}) {
		t.Error("consentScopesMatch(different) should be false")
	}
}
