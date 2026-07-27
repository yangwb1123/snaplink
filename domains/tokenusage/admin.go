package tokenusage

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Query parameter names for the admin usage read API.
const (
	paramSince = "since"
	paramUntil = "until"
)

// HandleAdminUsage serves GET /api/v1/admin/tokens/usage — the
// aggregated token-usage read API. Admin gating (admin:read) is the
// caller's responsibility (the /api/v1/admin/ prefix middleware).
//
// Query parameters:
//
//	client_id  (optional; empty = all clients)
//	since      (optional RFC 3339 timestamp; inclusive)
//	until      (optional RFC 3339 timestamp; EXCLUSIVE)
func HandleAdminUsage(store Store, log spi.Logger, ctx core.HandlerContext) {
	q, ok := parseAdminUsageQuery(ctx)
	if !ok {
		return
	}
	buckets, err := store.Query(ctx.Request().Context(), q)
	if err != nil {
		log.Error("token usage query failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if buckets == nil {
		buckets = []Bucket{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		"buckets":      buckets,
		"total":        len(buckets),
	})
}

// parseAdminUsageQuery binds the filter parameters. A malformed
// timestamp writes 400 invalid_request and returns ok=false.
func parseAdminUsageQuery(ctx core.HandlerContext) (Query, bool) {
	q := Query{ClientID: ctx.Query(core.KeyClientID)}
	since, ok := parseTimeParam(ctx, paramSince)
	if !ok {
		return q, false
	}
	until, ok := parseTimeParam(ctx, paramUntil)
	if !ok {
		return q, false
	}
	q.Since, q.Until = since, until
	return q, true
}

// parseTimeParam reads one optional RFC 3339 query parameter. Absent
// ⇒ zero time (unbounded side of the window).
func parseTimeParam(ctx core.HandlerContext, name string) (time.Time, bool) {
	v := ctx.Query(name)
	if v == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return time.Time{}, false
	}
	return t.UTC(), true
}
