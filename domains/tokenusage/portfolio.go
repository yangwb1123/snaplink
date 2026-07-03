package tokenusage

import (
	"net/http"
	"sort"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// maxPortfolioClients caps the per-client breakdown returned by the portfolio
// overview so the response stays bounded even if the store tracks many
// clients. The list is sorted issued-desc, so the cap keeps the busiest
// clients — the ones an operator cares about.
const maxPortfolioClients = 100

// PortfolioView is the aggregated "token portfolio overview" the admin panel
// renders: totals + per-kind / per-client distribution + a per-minute
// issuance trend, all derived from the opt-in usage store. Governance data
// only (counts, never token values or subjects).
type PortfolioView struct {
	Window         PortfolioWindow  `json:"window"`
	TotalEvents    int64            `json:"total_events"`
	IssuedTotal    int64            `json:"issued_total"`
	Introspections int64            `json:"introspections"`
	Userinfo       int64            `json:"userinfo"`
	ByKind         map[string]int64 `json:"by_kind"`
	ByClient       []ClientIssued   `json:"by_client"`
	Trend          []TrendPoint     `json:"trend"`
}

// PortfolioWindow echoes the (optional) query window back so the caller knows
// exactly what span the counts cover. Zero times marshal as the JSON zero
// value, meaning "unbounded on that side".
type PortfolioWindow struct {
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

// ClientIssued is one client's issuance count in the window.
type ClientIssued struct {
	ClientID string `json:"client_id"`
	Issued   int64  `json:"issued"`
}

// TrendPoint is one minute of total issuance across all clients/kinds.
type TrendPoint struct {
	Minute string `json:"minute"`
	Issued int64  `json:"issued"`
}

// HandleAdminPortfolio serves GET /api/v1/admin/tokens/portfolio — the
// aggregated token-portfolio overview. Admin gating (admin:read) is the
// caller's responsibility (the /api/v1/admin/ prefix middleware). Same
// optional filters as the usage read API (client_id/since/until); the window
// echoes back in the response.
func HandleAdminPortfolio(store Store, log spi.Logger, ctx core.HandlerContext) {
	q, ok := parseAdminUsageQuery(ctx)
	if !ok {
		return
	}
	buckets, err := store.Query(ctx.Request().Context(), q)
	if err != nil {
		log.Error("token portfolio query failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	view := aggregatePortfolio(buckets)
	view.Window = PortfolioWindow{Since: ctx.Query(paramSince), Until: ctx.Query(paramUntil)}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		"portfolio":    view,
	})
}

// aggregatePortfolio folds usage buckets into the portfolio view. Issuance
// (EndpointToken) drives the "active token" counts + trend; introspection /
// userinfo are surfaced as separate totals so the overview distinguishes
// "tokens minted" from "tokens presented".
func aggregatePortfolio(buckets []Bucket) PortfolioView {
	v := PortfolioView{ByKind: map[string]int64{}}
	byClient := map[string]int64{}
	byMinute := map[string]int64{}
	for _, b := range buckets {
		v.TotalEvents += b.Count
		switch b.Endpoint {
		case EndpointToken:
			v.IssuedTotal += b.Count
			v.ByKind[string(b.Kind)] += b.Count
			byClient[b.ClientID] += b.Count
			byMinute[b.Minute.UTC().Format("2006-01-02T15:04:05Z07:00")] += b.Count
		case EndpointIntrospect:
			v.Introspections += b.Count
		case EndpointUserinfo:
			v.Userinfo += b.Count
		}
	}
	v.ByClient = topClients(byClient)
	v.Trend = sortedTrend(byMinute)
	return v
}

// topClients returns the per-client issuance sorted busiest-first, capped.
func topClients(byClient map[string]int64) []ClientIssued {
	out := make([]ClientIssued, 0, len(byClient))
	for c, n := range byClient {
		out = append(out, ClientIssued{ClientID: c, Issued: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Issued != out[j].Issued {
			return out[i].Issued > out[j].Issued
		}
		return out[i].ClientID < out[j].ClientID
	})
	if len(out) > maxPortfolioClients {
		out = out[:maxPortfolioClients]
	}
	return out
}

// sortedTrend returns the per-minute issuance series in ascending time order.
func sortedTrend(byMinute map[string]int64) []TrendPoint {
	out := make([]TrendPoint, 0, len(byMinute))
	for m, n := range byMinute {
		out = append(out, TrendPoint{Minute: m, Issued: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Minute < out[j].Minute })
	return out
}
