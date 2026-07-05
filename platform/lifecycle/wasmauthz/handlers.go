package wasmauthz

import (
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// HandlerDeps is what the WASM authz admin HTTP handler needs. *sso.Server
// satisfies this via its WASMAuthzEngine() accessor.
type HandlerDeps interface {
	WASMAuthzEngine() *Engine
}

// HandleCheck implements POST /api/v1/admin/wasmauthz/check — an
// OPERATIONAL DEBUGGING endpoint (see the package doc): "what would the
// hosted WASM policy module decide for this request". POST (rather than
// rebac's GET+query-params check) because a [Request] has a richer, nested
// shape (a Context map) that does not fit cleanly into query parameters.
// admin:read via the /api/v1/admin/ prefix's AdminMiddleware method-scope
// rule; mounted only when [github.com/snaplink/sso/interfaces/sso.WithWASMAuthzEngine]
// is wired (byte-identical to a build without the feature otherwise).
func HandleCheck(d HandlerDeps, ctx core.HandlerContext) {
	eng := d.WASMAuthzEngine()
	if eng == nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrWASMAuthzNotConfigured))
		return
	}
	var req Request
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errBody(core.ErrInvalidRequest))
		return
	}
	dec, err := eng.Authorize(ctx.Request().Context(), req)
	if err != nil {
		// This is the admin DEBUG endpoint reporting why a decision could
		// not be evaluated — NOT a fabricated {"allowed":false} decision.
		// Any real integration calling Engine.Authorize directly still
		// MUST treat this same error as a denial (see the package doc).
		ctx.JSON(http.StatusInternalServerError, errBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyWASMAuthzAllowed: dec.Allowed,
		core.KeyWASMAuthzReason:  dec.Reason,
	})
}

func errBody(code string) map[string]string { return map[string]string{core.KeyError: code} }

func errBodyDesc(code, desc string) map[string]string {
	return map[string]string{core.KeyError: code, core.KeyErrorDescription: desc}
}
