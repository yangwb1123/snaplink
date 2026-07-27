package oidcsupport

import (
	"encoding/json"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// SilentRenewalRequest captures the subset of /auth/login parameters
// the OIDC prompt=none silent flow needs. Bound from the inline req
// struct in handleLogin so the silent-renewal path can be tested and
// reasoned about in isolation.
type SilentRenewalRequest struct {
	ClientID             string
	Scope                []string
	State                string
	Nonce                string
	Resource             []string
	AuthorizationDetails json.RawMessage
	IDTokenHint          string
	// MaxAge is the OIDC Core §3.1.2.1 max_age parameter — when
	// non-nil, the silent renewal is rejected with login_required
	// if the hint's auth_time is older than this many seconds.
	// nil = no max_age constraint (RP didn't pass one).
	MaxAge *int64
}

// ParsePromptValues splits the OIDC prompt parameter and returns the
// unique non-empty values. Empty input returns nil so the caller can
// short-circuit with a `len() == 0` check.
func ParsePromptValues(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, v := range strings.Fields(raw) {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// PromptHasNone reports whether the prompt parameter requests silent
// authentication. Convenience over scanning the slice at each site.
func PromptHasNone(values []string) bool {
	for _, v := range values {
		if v == core.PromptNone {
			return true
		}
	}
	return false
}

// ScopeContainsOpenID is a small helper used by the silent flow + ID
// token plumbing to gate openid-only behaviors. Independent of
// strings.Contains-on-joined to avoid the "openid_extra" false match.
func ScopeContainsOpenID(scopes []string) bool {
	for _, s := range scopes {
		if s == core.ScopeOpenID {
			return true
		}
	}
	return false
}
