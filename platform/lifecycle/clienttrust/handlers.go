package clienttrust

import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// HandlerDeps is what the read-only client-trust admin handler needs.
// *sso.Server would satisfy this via its existing ClientStore() accessor —
// mirrors platform/lifecycle/webhook.HandlerDeps's shape (a narrow,
// package-local dependency interface rather than reusing interfaces/admin.Deps,
// which this platform-layer package must not import — interfaces is a
// HIGHER layer; see architecture_layer_test.go).
//
// Route mounting: NOT wired into the live interfaces/sso router by this
// change (interfaces/sso's per-file/per-directory maintainability budgets
// are all within a handful of lines of their ceiling — see AGENTS.md
// §0.1's "interfaces/sso is AT its 57 non-test-file ceiling" note — so
// adding a route there is deliberately left as a follow-up, exactly the
// same "build the handler, mount it later behind a With*Option" shape
// WithWebhookEngine/WithRebacEngine/WithWASMAuthzEngine already established
// for optional, request-path-inert admin surfaces). HandleGetClientTrustScore
// is fully callable/testable today via core.NewStdRouter (see handlers_test.go),
// exactly like every other HandleX in this SDK.
type HandlerDeps interface {
	ClientStore() core.ClientStore
}

// clientTrustView is the read-only JSON projection returned by
// HandleGetClientTrustScore. Scored is false when ClientTrustSetAt is zero
// ("never scored" — see core.Client.ClientTrustSetAt) so a caller can tell
// "genuinely never computed" apart from "computed and happens to be 0".
type clientTrustView struct {
	ClientID  string  `json:"client_id"`
	Score     float64 `json:"trust_score"`
	Scored    bool    `json:"scored"`
	SetAt     string  `json:"trust_set_at,omitempty"`
	ColdStart bool    `json:"cold_start_default,omitempty"`
}

// HandleGetClientTrustScore implements a read-only
// GET /api/v1/admin/clients/:id/trust-score. It returns the CURRENTLY
// PERSISTED score (core.Client.ClientTrustScore/ClientTrustSetAt) — a pure
// read, it never triggers a recompute (see UpdateAndAlert for that) and
// never affects any authorization decision.
func HandleGetClientTrustScore(d HandlerDeps, ctx core.HandlerContext) {
	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ClientStore()
	if store == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	client, err := store.Get(ctx.Request().Context(), clientID)
	if errors.Is(err, core.ErrNoSuchClient) {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, clientTrustViewOf(client))
}

// clientTrustViewOf projects a core.Client onto the read-only response
// shape. A client that has never been scored (ClientTrustSetAt zero) reports
// the neutral ColdStartScore rather than the misleading raw zero-value
// field — the SAME cold-start contract ClientTrustScorer.Score itself
// applies, so a caller reading either surface sees one consistent number.
func clientTrustViewOf(c *core.Client) clientTrustView {
	if c.ClientTrustSetAt.IsZero() {
		return clientTrustView{ClientID: c.ID, Score: ColdStartScore, Scored: false, ColdStart: true}
	}
	return clientTrustView{
		ClientID: c.ID,
		Score:    c.ClientTrustScore,
		Scored:   true,
		SetAt:    c.ClientTrustSetAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}
