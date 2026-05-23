package oauth

import (
	"slices"
)

// DCRMetadata is the subset of RFC 7591 §2 client metadata the
// validator inspects. Mirrors the request struct used by /register
// so the SSO server can validate without round-tripping types.
type DCRMetadata struct {
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	AllowedAuthenticators   []string
}

// ValidateDCRMetadata enforces the subset of RFC 7591 §2 / §5 rules
// this server understands plus the policy's whitelist constraints.
//
// supportedGrants lists the grant types the AS advertises in
// discovery — caller supplies it (typically core.SupportedGrants) so
// the validator stays a leaf with no upstream imports.
//
// authzCodeGrant is the canonical name of the auth-code grant
// (typically core.GrantAuthorizationCode); the redirect_uris-required
// rule §2 only fires when this is present in or defaults from the
// request's grant_types.
func ValidateDCRMetadata(req *DCRMetadata, policy *DCRPolicy, supportedGrants []string, authzCodeGrant string) error {
	// redirect_uris is REQUIRED for grant_type=authorization_code
	// (the default), OPTIONAL for client_credentials-only clients
	// (per §2 — "redirect_uris is OPTIONAL ... If the grant types
	// supported include authorization_code or implicit, then this
	// metadata REQUIRED").
	wantsCodeFlow := len(req.GrantTypes) == 0 ||
		slices.Contains(req.GrantTypes, authzCodeGrant)
	if wantsCodeFlow && len(req.RedirectURIs) == 0 {
		return ErrDCR("redirect_uris required for authorization_code flow")
	}

	if slices.Contains(req.RedirectURIs, "") {
		return ErrDCR("empty redirect_uri")
	}

	switch req.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "none":
		// supported
	default:
		return ErrDCR("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
	}

	for _, g := range req.GrantTypes {
		if !slices.Contains(supportedGrants, g) {
			return ErrDCR("unsupported grant_type: " + g)
		}
	}

	for _, rt := range req.ResponseTypes {
		switch rt {
		case "code", "token", "":
			// supported
		default:
			return ErrDCR("unsupported response_type: " + rt)
		}
	}

	if len(policy.AllowedAuthenticators) > 0 {
		for _, a := range req.AllowedAuthenticators {
			if !slices.Contains(policy.AllowedAuthenticators, a) {
				return ErrDCR("authenticator not permitted by registration policy: " + a)
			}
		}
	}

	return nil
}

// ErrDCR wraps a DCR validation failure message as a typed error so
// the /register handler can recognize policy rejection vs other
// errors via errors.As.
func ErrDCR(msg string) error {
	return &dcrError{msg: msg}
}

type dcrError struct{ msg string }

func (e *dcrError) Error() string { return e.msg }
