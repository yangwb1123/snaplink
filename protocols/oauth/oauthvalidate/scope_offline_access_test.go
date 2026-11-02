package oauthvalidate

import (
	"slices"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestGrantedScopesOfflineAccessIsExplicit(t *testing.T) {
	client := &core.Client{AllowedScopes: []string{"openid", "profile", "offline_access", "read", "profile"}}
	for _, requested := range [][]string{nil, {}, {""}} {
		got, err := GrantedScopes(requested, client)
		if err != nil || !slices.Equal(got, []string{"profile", "read"}) {
			t.Fatalf("empty request implicitly granted protocol credentials: %v error=%v", got, err)
		}
	}
	for _, requested := range [][]string{{"offline_access"}, {"openid", "offline_access", "offline_access"}, {"profile"}} {
		got, err := GrantedScopes(requested, client)
		if err != nil || !slices.Equal(got, dedupeScopes(requested)) {
			t.Fatalf("explicit allowed request changed: %v error=%v", got, err)
		}
	}
	if _, err := GrantedScopes([]string{"offline_access"}, &core.Client{AllowedScopes: []string{"read"}}); err != ErrScopeNotAllowed {
		t.Fatal("offline access bypassed the client scope ceiling")
	}
	got, err := GrantedScopes(nil, &core.Client{AllowedScopes: []string{"openid", "offline_access"}})
	if err != nil || len(got) != 0 {
		t.Fatal("protocol-only allowlist supplied an implicit grant")
	}
}
