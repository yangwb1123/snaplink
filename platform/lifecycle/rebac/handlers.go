package rebac

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

// HandlerDeps is what the ReBAC admin HTTP handler needs. *sso.Server
// satisfies this via its RebacEngine() accessor.
type HandlerDeps interface {
	RebacEngine() *Engine
}

// HandleCheck implements GET
// /api/v1/admin/rebac/check?object=&relation=&subject= — an OPERATIONAL
// DEBUGGING endpoint for the Check engine (see package doc): "why does/
// doesn't this subject have this relation on this object". admin:read via
// the /api/v1/admin/ prefix's AdminMiddleware method-scope rule; mounted
// only when sso.WithRebacEngine is wired (byte-identical to a build without
// the feature otherwise).
func HandleCheck(d HandlerDeps, ctx core.HandlerContext) {
	eng := d.RebacEngine()
	if eng == nil {
		ctx.JSON(http.StatusInternalServerError, errBody(core.ErrRebacNotConfigured))
		return
	}
	object := ctx.Query("object")
	relation := ctx.Query("relation")
	subject := ctx.Query("subject")
	if object == "" || relation == "" || subject == "" {
		ctx.JSON(http.StatusBadRequest, errBody(core.ErrInvalidRequest))
		return
	}
	allowed, err := eng.Check(ctx.Request().Context(), object, relation, subject)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errBodyDesc(core.ErrInternal, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyRebacAllowed:  allowed,
		core.KeyRebacObject:   object,
		core.KeyRebacRelation: relation,
		core.KeyRebacSubject:  subject,
	})
}

func errBody(code string) map[string]string { return map[string]string{core.KeyError: code} }

func errBodyDesc(code, desc string) map[string]string {
	return map[string]string{core.KeyError: code, core.KeyErrorDescription: desc}
}
