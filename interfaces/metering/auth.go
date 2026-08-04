package meteringhttp

import (
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

const bindingContextKey = "snaplink.metering.source_binding"

func (a *API) authorize(requiredScope string) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
		if !ok || claims == nil {
			rejectMachine(ctx, http.StatusUnauthorized, core.ErrInvalidToken, core.ErrInvalidToken, "")
			return
		}
		if claims.Subject == "" || claims.ClientID == "" || claims.Subject != claims.ClientID ||
			rs.CheckScope(claims, requiredScope) != nil {
			rejectMachine(ctx, http.StatusForbidden, ErrorInsufficientScope,
				ErrorInsufficientScope, requiredScope)
			return
		}
		binding, err := a.deps.Sources.Resolve(ctx.Request().Context(), claims.ClientID)
		if errors.Is(err, usageledger.ErrSourceBindingUnauthorized) {
			rejectMachine(ctx, http.StatusForbidden, ErrorSourceUnauthorized,
				ErrorInsufficientScope, requiredScope)
			return
		}
		if err != nil || binding == nil {
			writeMachineError(ctx, http.StatusServiceUnavailable, ErrorUnavailable)
			ctx.Abort()
			return
		}
		ctx.Set(bindingContextKey, binding)
	}
}

func rejectMachine(ctx core.HandlerContext, status int, code, challengeError, scope string) {
	privateNoStore(ctx)
	challenge := "Bearer realm=" + security.QuoteAuthParam(meteringRealm)
	challenge += ", error=" + security.QuoteAuthParam(challengeError)
	if scope != "" {
		challenge += ", scope=" + security.QuoteAuthParam(scope)
	}
	ctx.ResponseWriter().Header().Set(headerAuthenticate, challenge)
	ctx.JSON(status, core.ErrorBody(code))
	ctx.Abort()
}

func currentBinding(ctx core.HandlerContext) (*usageledger.SourceBinding, bool) {
	binding, ok := ctx.Get(bindingContextKey).(*usageledger.SourceBinding)
	if !ok || binding == nil || !binding.Enabled || binding.Validate() != nil {
		writeMachineError(ctx, http.StatusServiceUnavailable, ErrorUnavailable)
		return nil, false
	}
	return binding, true
}

func (a *API) recheckSource(ctx core.HandlerContext, expected *usageledger.SourceBinding) bool {
	current, err := a.deps.Sources.Resolve(ctx.Request().Context(), expected.ClientID)
	if errors.Is(err, usageledger.ErrSourceBindingUnauthorized) ||
		(err == nil && !sameBindingEvidence(current, expected)) {
		rejectMachine(ctx, http.StatusForbidden, ErrorSourceUnauthorized,
			ErrorInsufficientScope, ScopeEntitlementRead)
		return false
	}
	if err != nil || current == nil {
		writeMachineError(ctx, http.StatusServiceUnavailable, ErrorUnavailable)
		return false
	}
	return true
}

func sameBindingEvidence(left, right *usageledger.SourceBinding) bool {
	return left != nil && right != nil && left.Evidence() == right.Evidence() &&
		left.Enabled && right.Enabled
}
