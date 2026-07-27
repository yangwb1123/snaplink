package selfservice

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleLoginUIMetadata serves GET /api/v1/login-ui/metadata?client_id=...
// Returns endpoints, issuer, and client info for custom login UI facades.
// The caller (Server handler wrapper) enriches the response with geo and
// provider data via ctx.Set values.
func HandleLoginUIMetadata(d Deps, ctx core.HandlerContext) {
	clientID := ctx.Query("client_id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	iss := d.ResolveIssuer(ctx)
	meta := map[string]any{
		"client_id": clientID,
		"iss":       iss,
		"endpoints": map[string]string{
			"authorization": iss + "/auth/login",
			"token":         iss + "/token",
			"userinfo":      iss + "/userinfo",
			"jwks":          iss + "/.well-known/jwks.json",
		},
	}
	// Pass through any caller-enriched data from context.
	if v := ctx.Get("extensions"); v != nil {
		meta["extensions"] = v
	}
	d.TokenNoStoreHeaders(ctx)
	ctx.JSON(http.StatusOK, meta)
}
