package oidc

import "github.com/snaplink/sso/core"

// CodeChallengeMethodsFor returns the PKCE methods to advertise in
// the discovery doc. OAuth 2.1 §4.1.1 retires `plain` (S256-only);
// the discovery list MUST shrink to ["S256"] when the operator
// enabled the strict flag. Otherwise both are accepted on the wire
// and both are advertised. Per-client AllowedPKCEMethods narrows
// further at the request path; the discovery list reflects the
// AS-wide ceiling.
func CodeChallengeMethodsFor(oauth21Strict bool) []string {
	if oauth21Strict {
		return []string{core.PKCEMethodS256}
	}
	return []string{core.PKCEMethodS256, core.PKCEMethodPlain}
}

// ResponseTypesFor mirrors CodeChallengeMethodsFor. OAuth 2.1 §1.1
// retires the implicit grant (response_type=token), so strict mode
// MUST omit it from the discovery advertisement — otherwise an RP
// scanning discovery sees "token" supported, sends the request, and
// gets unsupported_response_type at runtime. The mismatch is a real
// integration footgun: lock the wire down to what we actually accept.
func ResponseTypesFor(oauth21Strict bool) []string {
	if oauth21Strict {
		return []string{"code"}
	}
	return []string{"code", "token"}
}

// SubjectTypesFor reflects WithPairwiseSubjectStore — every server
// advertises "public" (the default), and "pairwise" only when an
// operator wired the store so the AS can actually resolve pairwise
// subs at resource time. Advertising pairwise without the store
// would be a footgun: RPs registering with subject_type=pairwise
// would silently get public subs.
func SubjectTypesFor(pairwiseStoreWired bool) []string {
	if pairwiseStoreWired {
		return []string{"public", "pairwise"}
	}
	return []string{"public"}
}

// Response mode constants per OIDC Core §3.1.2.5 + Form Post 1.0 §2.
const (
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
	ResponseModeFormPost = "form_post"
)

// IsValidResponseMode reports whether the supplied response_mode
// value is one this server understands. Empty is always valid (it
// means "use the response_type-defined default"); callers MUST
// short-circuit on empty before this check.
func IsValidResponseMode(mode string) bool {
	switch mode {
	case ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost:
		return true
	}
	return false
}
