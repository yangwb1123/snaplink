package sso

import "github.com/snaplink/sso/shared/core"

// The Key* re-exports below moved here from aliases.go to keep that
// generated file within the per-file line budget; this file otherwise has
// no relation to the wire-payload key constants.
const KeyAccessToken = core.KeyAccessToken
const KeyACR = core.KeyACR
const KeyActive = core.KeyActive
const KeyAMR = core.KeyAMR
const KeyAud = core.KeyAud
const KeyAuthTime = core.KeyAuthTime
const KeyClientID = core.KeyClientID
const KeyTenantID = core.KeyTenantID
const KeyClientName = core.KeyClientName
const KeyScopes = core.KeyScopes
const KeyCode = core.KeyCode
const KeyCountryCode = core.KeyCountryCode
const KeyError = core.KeyError
const KeyErrorDescription = core.KeyErrorDescription
const KeyExp = core.KeyExp
const KeyExpiresIn = core.KeyExpiresIn
const KeyIat = core.KeyIat
const KeyIDToken = core.KeyIDToken
const KeyIss = core.KeyIss
const KeyIssuedTokenType = core.KeyIssuedTokenType
const KeyIssuer = core.KeyIssuer
const KeyJTI = core.KeyJTI
const KeyConsentChallengeID = core.KeyConsentChallengeID
const KeyMFAChallengeID = core.KeyMFAChallengeID
const KeyMFAMethod = core.KeyMFAMethod
const KeyMFAMethodData = core.KeyMFAMethodData
const KeyMFAMethods = core.KeyMFAMethods
const KeyNbf = core.KeyNbf
const KeyProviders = core.KeyProviders
const KeyRecommendedLang = core.KeyRecommendedLang
const KeyRedirectURI = core.KeyRedirectURI
const KeyRefreshToken = core.KeyRefreshToken
const KeyRevoked = core.KeyRevoked
const KeyScope = core.KeyScope
const KeyServingRegion = core.KeyServingRegion
const KeySessionID = core.KeySessionID
const KeyState = core.KeyState
const KeyStatus = core.KeyStatus
const KeyStrategy = core.KeyStrategy
const KeySub = core.KeySub
const KeySupportedGrants = core.KeySupportedGrants
const KeyTokenHint = core.KeyTokenHint
const KeyTokenStrategy = core.KeyTokenStrategy
const KeyTokenType = core.KeyTokenType
const KeyVCSRevision = core.KeyVCSRevision
const KeyVCSTime = core.KeyVCSTime
const KeyVersion = core.KeyVersion

// isOriginAllowed checks if the given origin is allowed by the CORS policy.
// Returns true if:
//   - No CORS policy is configured (allow all for backwards compatibility)
//   - The origin is in the AllowedOrigins list
//   - Wildcard "*" is configured
//
// Returns false if:
//   - CORS policy exists but origin is not in AllowedOrigins and no wildcard
//
// This is used for defense-in-depth CSRF protection on sensitive endpoints
// like /auth/login where we want to validate the Origin header even before
// the CORS middleware runs.
func (s *Server) isOriginAllowed(origin string) bool {
	// No CORS policy = no origin restrictions (backwards compatible)
	if s.corsPolicy == nil {
		return true
	}

	// Check each allowed origin
	for _, allowed := range s.corsPolicy.AllowedOrigins {
		// Wildcard allows any origin
		if allowed == "*" {
			return true
		}
		// Exact match
		if allowed == origin {
			return true
		}
	}

	return false
}
