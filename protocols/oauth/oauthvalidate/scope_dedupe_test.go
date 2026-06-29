package oauthvalidate

import "testing"

func TestDedupeScopesEmptyAfterTrim(t *testing.T) {
	t.Parallel()
	if got := dedupeScopes([]string{"", "", ""}); got != nil {
		t.Errorf("dedupeScopes(all empty) = %v, want nil", got)
	}
	if got := dedupeScopes(nil); got != nil {
		t.Errorf("dedupeScopes(nil) = %v, want nil", got)
	}
}
