package permissions_test

import (
	"testing"

	"github.com/snaplink/sso/domains/permissions"
)

func TestMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		have []string // permission codes the user holds
		want string
		ok   bool
	}{
		{name: "empty want is vacuously granted", have: nil, want: "", ok: true},
		{name: "empty want even with empty have", have: nil, want: "", ok: true},

		{name: "exact match", have: []string{"user:read"}, want: "user:read", ok: true},
		{name: "exact miss", have: []string{"user:read"}, want: "user:create", ok: false},

		{name: "domain wildcard matches action", have: []string{"user:*"}, want: "user:read", ok: true},
		{name: "domain wildcard matches another action", have: []string{"user:*"}, want: "user:delete", ok: true},
		{name: "domain wildcard does not cross domains", have: []string{"user:*"}, want: "order:read", ok: false},

		{name: "global wildcard matches everything", have: []string{"*"}, want: "anything:goes", ok: true},
		{name: "global wildcard matches even single-segment want", have: []string{"*"}, want: "ping", ok: true},

		{name: "no match in non-empty have", have: []string{"user:read", "order:read"}, want: "audit:read", ok: false},
		{name: "first match short-circuits", have: []string{"order:create", "*"}, want: "user:read", ok: true},

		{name: "domain wildcard requires colon boundary",
			have: []string{"user:*"}, want: "username", ok: false},
		{name: "matches against permission with same prefix but different segment",
			have: []string{"order:*"}, want: "order_summary:read", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			have := make([]permissions.Permission, 0, len(tc.have))
			for _, c := range tc.have {
				have = append(have, permissions.Permission{Code: c})
			}
			if got := permissions.Matches(have, tc.want); got != tc.ok {
				t.Fatalf("Matches(%v, %q) = %v, want %v", tc.have, tc.want, got, tc.ok)
			}
		})
	}
}

func TestPermissionSet_Deduplicates(t *testing.T) {
	t.Parallel()
	in := []permissions.Permission{
		{Code: "user:read"},
		{Code: "user:read"},
		{Code: "order:read"},
		{Code: "*"},
		{Code: "*"},
	}
	got := permissions.PermissionSet(in)
	want := map[string]struct{}{
		"user:read":  {},
		"order:read": {},
		"*":          {},
	}
	if len(got) != len(want) {
		t.Fatalf("PermissionSet size = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in set", k)
		}
	}
}

func TestPermissionSet_EmptyInput(t *testing.T) {
	t.Parallel()
	got := permissions.PermissionSet(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty set, got %v", got)
	}
}
