package oauthvalidate

import (
	"encoding/json"

	"github.com/snaplink/sso/shared/core"
)

// The OIDC Core §5.5 `claims` request-parameter parser was relocated to core
// (the dependency-free shared leaf) so oauth, oidc, and the root userinfo
// handler can all use it without oidc importing oauth. These thin re-exports
// preserve the oauth.* public API byte-for-byte.

// ClaimRequest is an alias for [core.ClaimRequest].
type ClaimRequest = core.ClaimRequest

// ParseRequestedClaims delegates to [core.ParseRequestedClaims].
func ParseRequestedClaims(raw json.RawMessage) (idToken, userinfo map[string]*ClaimRequest, err error) {
	return core.ParseRequestedClaims(raw)
}

// ValidateClaimsParameter delegates to [core.ValidateClaimsParameter].
func ValidateClaimsParameter(raw json.RawMessage) error { return core.ValidateClaimsParameter(raw) }

// RequestedACRFromClaims delegates to [core.RequestedACRFromClaims].
func RequestedACRFromClaims(raw json.RawMessage) []string { return core.RequestedACRFromClaims(raw) }
