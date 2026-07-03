package tokenanomaly

import (
	"net/http"
	"strconv"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Query parameter names for the suspicious-token read API.
const (
	paramType     = "type"
	paramSeverity = "severity"
	paramLimit    = "limit"
)

// HandleAdminSuspicious serves GET /api/v1/admin/tokens/suspicious — the
// detected token-behavior anomalies (governance/reporting only). Admin gating
// (admin:read) is the caller's responsibility (the /api/v1/admin/ prefix
// middleware).
//
// Findings carry a token thumbprint (never a token value), a coarse geo set,
// and the subject id — consistent with the wave-1 usage telemetry privacy
// stance. This is a READ of an already-detected list; it never triggers
// detection and never influences an auth decision.
//
// Query parameters (all optional):
//
//	type      one of multi_geo | velocity | rate_spike
//	severity  one of warn | critical
//	limit     max rows (most-recent first); <= 0 or absent = all
func HandleAdminSuspicious(store FindingStore, log spi.Logger, ctx core.HandlerContext) {
	q := FindingQuery{
		Type:     ctx.Query(paramType),
		Severity: Severity(ctx.Query(paramSeverity)),
		Limit:    parseLimit(ctx.Query(paramLimit)),
	}
	findings, err := store.List(ctx.Request().Context(), q)
	if err != nil {
		log.Error("token anomaly findings list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if findings == nil {
		findings = []Finding{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		"findings":     findings,
		"total":        len(findings),
	})
}

// parseLimit reads the optional limit parameter. A malformed or non-positive
// value yields 0 (no cap) — the list is already bounded by the store's own
// cap, so a bad limit is best-effort ignored, not a 400.
func parseLimit(v string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
