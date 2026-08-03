package oauth

import (
	"github.com/yangwb1123/snaplink/shared/core"
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

// RoutesDeps is the union of the deps the oauth surface's handlers need —
// introspect, PAR, revoke (incl. revoke-all), DCR read/update/delete, and
// CIBA backchannel-auth. *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	IntrospectDeps
	PARDeps
	RevokeDeps
	RegisterDeps
	CIBADeps
}

// MountRoutes registers the OAuth 2.0 protocol surface on r: the
// always-present credential endpoints (introspect, PAR, revoke, revoke-all,
// DCR registration reads) plus the CIBA backchannel-authentication endpoint,
// wrapped in a core.GatedRouter so it hot-toggles with the CIBA feature gate
// exactly as it did when registered from interfaces/sso (mountCIBAEndpoint).
// The DCR create route (POST /register) stays registered by interfaces/sso
// beside its body-bearing handler. cibaGate must be non-nil — the Server's
// live cibaGateOn method value; nil is a programmer error.
func MountRoutes(r core.Router, d RoutesDeps, cibaGate func() bool) {
	if cibaGate == nil {
		panic("oauth: MountRoutes requires a non-nil cibaGate")
	}
	r.POST(core.PathIntrospect, func(ctx core.HandlerContext) { HandleIntrospect(d, ctx) })
	r.POST(core.PathPAR, func(ctx core.HandlerContext) { HandlePAR(d, ctx) })
	r.POST(core.PathRevoke, func(ctx core.HandlerContext) { HandleRevoke(d, ctx) })
	r.POST(core.PathRevokeAll, func(ctx core.HandlerContext) { HandleRevokeAll(d, ctx) })
	r.GET(PathRegisterByID, func(ctx core.HandlerContext) { HandleRegistrationGet(d, ctx) })
	r.PUT(PathRegisterByID, func(ctx core.HandlerContext) { HandleRegistrationPut(d, ctx) })
	r.DELETE(PathRegisterByID, func(ctx core.HandlerContext) { HandleRegistrationDelete(d, ctx) })
	core.NewGatedRouter(r, cibaGate).POST(core.PathBackchannelAuth, func(ctx core.HandlerContext) { HandleBackchannelAuth(d, ctx) })
}
