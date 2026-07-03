package admin

import (
	"net/http"
	"sort"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/shared/core"
)

// Zero-trust conditional-access (CAP) policy governance view. Read-only: policy
// authoring is out of band (a YAML bundle loaded at boot / a later admin
// mutation surface), so this handler only lists. Gated by AdminMiddleware
// (admin:read via the /api/v1/admin/ prefix).

// HandleAdminListAccessPolicies serves GET /api/v1/admin/access-policies — the
// wired conditional-access policies ordered by evaluation precedence (priority
// desc, then name), so an operator sees the order the engine resolves them in.
// admin:read.
func HandleAdminListAccessPolicies(d Deps, ctx core.HandlerContext) {
	store := d.ConditionalAccessStore()
	if store == nil {
		// Defensive: the route is only mounted when the engine is wired, but
		// guard so a future refactor can't reach a nil store.
		ctx.JSON(http.StatusOK, map[string]any{"policies": []conditionalaccess.Policy{}, "total": 0})
		return
	}
	policies, err := store.List(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin list access policies failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	sortAccessPoliciesByPrecedence(policies)
	ctx.JSON(http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

// sortAccessPoliciesByPrecedence orders the governance view the way the engine
// evaluates: higher priority first, then name for a stable, deterministic view.
// (The engine additionally breaks ties on condition specificity; the view keeps
// to the two operator-visible keys.)
func sortAccessPoliciesByPrecedence(policies []conditionalaccess.Policy) {
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority > policies[j].Priority
		}
		return policies[i].Name < policies[j].Name
	})
}
