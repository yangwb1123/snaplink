package oauth

import (
	"errors"
	"reflect"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestGrantedScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		requested []string
		client    *core.Client
		want      []string
		wantErr   bool
	}{
		{
			// Rule 2: a client with no allowlist is unrestricted — the
			// requested set passes through verbatim (backward-compatible).
			name:      "empty allowlist unrestricted pass-through",
			requested: []string{"anything", "whatever"},
			client:    &core.Client{AllowedScopes: nil},
			want:      []string{"anything", "whatever"},
		},
		{
			// Rule 2 corner: empty allowlist + empty request ⇒ no default
			// injected (stays empty, byte-identical to the old behavior).
			name:      "empty allowlist empty request no default",
			requested: nil,
			client:    &core.Client{AllowedScopes: nil},
			want:      nil,
		},
		{
			// Rule 3: requested ⊆ allowed ⇒ granted = requested.
			name:      "requested subset of allowed",
			requested: []string{"api:read"},
			client:    &core.Client{AllowedScopes: []string{"api:read", "api:write"}},
			want:      []string{"api:read"},
		},
		{
			// Rule 3: any out-of-allowlist scope rejects the whole request.
			name:      "requested superset rejected",
			requested: []string{"api:read", "api:write"},
			client:    &core.Client{AllowedScopes: []string{"api:read"}},
			wantErr:   true,
		},
		{
			// Rule 4: empty request + non-empty allowlist ⇒ default to the
			// allowlist (minus openid) so the token always carries a scope.
			name:      "empty request defaults to allowlist",
			requested: nil,
			client:    &core.Client{AllowedScopes: []string{"api:read", "api:write"}},
			want:      []string{"api:read", "api:write"},
		},
		{
			// Rule 4 + rule 1: openid is excluded from the default copy so
			// an unrequested id_token is never minted.
			name:      "empty request default excludes openid",
			requested: nil,
			client:    &core.Client{AllowedScopes: []string{"openid", "profile"}},
			want:      []string{"profile"},
		},
		{
			// Rule 1: openid is always permitted even when not in the
			// allowlist (it is the OIDC trigger, not a resource scope).
			name:      "openid always allowed even outside allowlist",
			requested: []string{"openid", "profile"},
			client:    &core.Client{AllowedScopes: []string{"profile"}},
			want:      []string{"openid", "profile"},
		},
		{
			// Rule 1 + rule 3: openid passes, but a sibling out-of-allowlist
			// resource scope still rejects.
			name:      "openid allowed but other scope rejected",
			requested: []string{"openid", "email"},
			client:    &core.Client{AllowedScopes: []string{"profile"}},
			wantErr:   true,
		},
		{
			// Dedupe + order preservation + empty trim.
			name:      "dedupe preserves order and trims empties",
			requested: []string{"api:read", "", "api:read", "api:write"},
			client:    &core.Client{AllowedScopes: []string{"api:read", "api:write"}},
			want:      []string{"api:read", "api:write"},
		},
		{
			// nil client behaves like the empty allowlist (unrestricted).
			name:      "nil client unrestricted",
			requested: []string{"x"},
			client:    nil,
			want:      []string{"x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GrantedScopes(tt.requested, tt.client)
			if tt.wantErr {
				if !errors.Is(err, ErrScopeNotAllowed) {
					t.Fatalf("want ErrScopeNotAllowed, got err=%v scopes=%v", err, got)
				}
				if got != nil {
					t.Fatalf("want nil scopes on error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("granted = %v, want %v", got, tt.want)
			}
		})
	}
}
