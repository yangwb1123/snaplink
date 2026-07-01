package oauth

import (
	"github.com/snaplink/sso/shared/core"
)

// GrantHandler is an extension point for custom OAuth 2.0 grant types.
// Implementations are registered via [WithCustomGrant] and dispatched
// before the built-in grant switch in /token.
//
// The handler receives the already-authenticated client, the parsed
// token request, and the sender-constraint thumbprints. It MUST write
// a response (success or error) via ctx on every path.
type GrantHandler interface {
	// GrantType returns the URN the handler responds to
	// (e.g. "urn:ietf:params:oauth:grant-type:saml2-bearer").
	GrantType() string

	// Handle processes the token grant request. The caller has already
	// authenticated the client, checked the GrantTypes allowlist, and
	// captured sender-constraint proofs. Implementations must write
	// their own response via ctx.
	Handle(ctx core.HandlerContext, client *core.Client, req TokenRequest, dpopJKT, mtlsX5T string)
}

// GrantHandlerError is a helper for GrantHandler implementations to
// return a standard error body. It writes code as the HTTP status
// and {"error": code} as the response body.
func GrantHandlerError(ctx core.HandlerContext, httpStatus int, errorCode string) {
	ctx.JSON(httpStatus, map[string]string{core.KeyError: errorCode})
}
