package core

import (
	"slices"
	"testing"
)

// TestSupportedGrantsIncludesEveryBuiltinDispatcherGrant pins the documented
// invariant of SupportedGrants: it must list every grant type that has a
// literal `case` in /token's built-in dispatcher switch
// (interfaces/sso.dispatchTokenGrant), independent of whether that grant's
// backing store is actually wired on a given deployment — the same
// convention server_discovery_config.go documents for GrantDeviceCode
// ("SupportedGrants still lists it for unsupported_grant_type").
//
// Two real consumers rely on completeness here:
//   - the /token unsupported_grant_type error body's supported_grants field.
//   - oauthvalidate.ValidateDCRMetadata, which REJECTS any client-requested
//     grant_type absent from this list. A missing entry silently blocks DCR
//     (RFC 7591) self-registration for a grant type the server actually
//     dispatches — e.g. GrantCIBA had a literal dispatcher case but was
//     missing from this list, so a client on a CIBA-enabled deployment could
//     never dynamically register with grant_types: ["urn:openid:params:grant-type:ciba"].
func TestSupportedGrantsIncludesEveryBuiltinDispatcherGrant(t *testing.T) {
	t.Parallel()

	// Mirrors, one-for-one, the literal `case` labels in
	// interfaces/sso's dispatchTokenGrant built-in switch (excluding
	// GrantAuthorizationCode/GrantRefreshToken/GrantClientCredentials, which
	// are unconditionally wired and were never at risk of this omission).
	builtinDispatcherGrants := []string{
		GrantDeviceCode,
		GrantTokenExchange,
		GrantJWTBearer,
		GrantCIBA,
	}

	for _, g := range builtinDispatcherGrants {
		if !slices.Contains(SupportedGrants, g) {
			t.Errorf("SupportedGrants is missing %q: a DCR client on a deployment where "+
				"this grant IS wired would be wrongly rejected at registration "+
				"(oauthvalidate.ValidateDCRMetadata rejects any grant_type outside "+
				"core.SupportedGrants), even though /token's dispatcher fully "+
				"recognizes and dispatches it", g)
		}
	}
}

// TestSupportedGrantsExcludesDynamicCustomGrants locks in the OTHER half of
// the invariant: grant types registered only through the dynamic
// WithCustomGrant mechanism (never a literal case in dispatchTokenGrant's
// built-in switch) are deliberately NOT part of this static list — whether
// they're DCR-registrable is a separate, per-deployment decision made by the
// operator wiring WithCustomGrant, not a property of the SDK's built-in
// grant set.
func TestSupportedGrantsExcludesDynamicCustomGrants(t *testing.T) {
	t.Parallel()

	dynamicCustomGrants := []string{
		GrantTypeSAML2Bearer,
		GrantTypeAgentDelegation,
	}

	for _, g := range dynamicCustomGrants {
		if slices.Contains(SupportedGrants, g) {
			t.Errorf("SupportedGrants unexpectedly contains %q: this grant type is only "+
				"ever registered dynamically via WithCustomGrant, not a literal "+
				"dispatchTokenGrant case, so it should not be in the static list", g)
		}
	}
}
