package meteringhttp

import (
	"net/http"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	operationCommit  = "reservation.commit"
	operationRelease = "reservation.release"
)

type commitRequest struct {
	FactID   string            `json:"fact_id,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (a *API) HandleCommit(ctx core.HandlerContext) {
	privateNoStore(ctx)
	binding, ok := currentBinding(ctx)
	if !ok {
		return
	}
	reservationID := ctx.Param("reservation_id")
	var request commitRequest
	key, keyOK := idempotencyKey(ctx)
	if err := decodeStrictJSON(ctx, &request); err != nil || !keyOK ||
		!validRequestID(reservationID, true) || !validRequestID(request.FactID, false) {
		a.failRequest(ctx, binding, operationCommit, reservationID, err)
		return
	}
	reservation, counter, err := a.deps.Usage.CommitAuthorized(
		ctx.Request().Context(), binding.Evidence(), reservationID,
		usageledger.AuthorizedCommitCommand{
			ID: request.FactID, IdempotencyKey: key, Metadata: request.Metadata,
		},
	)
	if err != nil {
		a.failUsage(ctx, binding, operationCommit, "", reservationID, err)
		return
	}
	a.observeSuccess(ctx, binding, operationCommit, reservation.Dimension, reservationID)
	ctx.JSON(http.StatusOK, map[string]any{
		responseReservation: reservation, responseCounter: counter,
	})
}

func (a *API) HandleRelease(ctx core.HandlerContext) {
	privateNoStore(ctx)
	binding, ok := currentBinding(ctx)
	if !ok {
		return
	}
	reservationID := ctx.Param("reservation_id")
	if !validRequestID(reservationID, true) || !emptyRequestBody(ctx) {
		a.failRequest(ctx, binding, operationRelease, reservationID, errInvalidJSON)
		return
	}
	reservation, err := a.deps.Usage.ReleaseAuthorized(
		ctx.Request().Context(), binding.Evidence(), reservationID,
	)
	if err != nil {
		a.failUsage(ctx, binding, operationRelease, "", reservationID, err)
		return
	}
	a.observeSuccess(ctx, binding, operationRelease, reservation.Dimension, reservationID)
	ctx.JSON(http.StatusOK, map[string]any{responseReservation: reservation})
}
