package commercehttp

import (
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// ClientCredentialsScopeGate is the stock route gate for deployments whose
// outer HTTP stack already ran rs.HTTPMiddleware. The RS middleware validates
// issuer, audience, signature, lifetime and sender constraints; this gate then
// requires the client_credentials identity shape (sub == client_id) and the
// exact machine scope requested by RegisterPaymentEventRoute.
func ClientCredentialsScopeGate(requiredScope string) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
		if !ok || claims == nil {
			rejectPaymentMachine(ctx, http.StatusUnauthorized, core.ErrInvalidToken, "")
			return
		}
		if claims.Subject == "" || claims.ClientID == "" || claims.Subject != claims.ClientID {
			rejectPaymentMachine(ctx, http.StatusForbidden, ErrorInsufficientScope, requiredScope)
			return
		}
		if rs.CheckScope(claims, requiredScope) != nil {
			rejectPaymentMachine(ctx, http.StatusForbidden, ErrorInsufficientScope, requiredScope)
		}
	}
}

func rejectPaymentMachine(ctx core.HandlerContext, status int, code, scope string) {
	privateNoStore(ctx)
	challenge := "Bearer realm=" + security.QuoteAuthParam(billingRealm)
	challenge += ", error=" + security.QuoteAuthParam(code)
	if scope != "" {
		challenge += ", scope=" + security.QuoteAuthParam(scope)
	}
	ctx.ResponseWriter().Header().Set(headerAuthenticate, challenge)
	ctx.JSON(status, core.ErrorBody(code))
	ctx.Abort()
}
