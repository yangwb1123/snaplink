package meteringhttp

import (
	"errors"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	operationUsageAppend = "usage.append"
	operationReserve     = "reservation.reserve"
)

type appendUsageRequest struct {
	ID         string            `json:"id,omitempty"`
	Dimension  string            `json:"dimension"`
	Quantity   int64             `json:"quantity"`
	OccurredAt time.Time         `json:"occurred_at,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type reserveRequest struct {
	ID         string `json:"id,omitempty"`
	Dimension  string `json:"dimension"`
	Quantity   int64  `json:"quantity"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

func (a *API) HandleAppendUsage(ctx core.HandlerContext) {
	privateNoStore(ctx)
	binding, ok := currentBinding(ctx)
	if !ok {
		return
	}
	var request appendUsageRequest
	key, keyOK := idempotencyKey(ctx)
	if err := decodeStrictJSON(ctx, &request); err != nil || !keyOK ||
		!validRequestID(request.ID, false) || !validRequestID(request.Dimension, true) {
		a.failRequest(ctx, binding, operationUsageAppend, request.ID, err)
		return
	}
	dimension := usageledger.Dimension(request.Dimension)
	if !a.dimensionAllowed(ctx, binding, operationUsageAppend, dimension, request.ID) {
		return
	}
	fact, counter, err := a.deps.Usage.AppendAuthorized(
		ctx.Request().Context(), binding.Evidence(), usageledger.UsageCommand{
			ID: request.ID, Dimension: dimension, Quantity: request.Quantity,
			IdempotencyKey: key, OccurredAt: request.OccurredAt, Metadata: request.Metadata,
		},
	)
	if err != nil {
		a.failUsage(ctx, binding, operationUsageAppend, dimension, request.ID, err)
		return
	}
	a.observeSuccess(ctx, binding, operationUsageAppend, dimension, fact.ID)
	ctx.JSON(http.StatusCreated, map[string]any{responseFact: fact, responseCounter: counter})
}

func (a *API) HandleReserve(ctx core.HandlerContext) {
	privateNoStore(ctx)
	binding, ok := currentBinding(ctx)
	if !ok {
		return
	}
	var request reserveRequest
	key, keyOK := idempotencyKey(ctx)
	if err := decodeStrictJSON(ctx, &request); err != nil || !keyOK ||
		!validRequestID(request.ID, false) || !validRequestID(request.Dimension, true) ||
		request.TTLSeconds <= 0 || request.TTLSeconds > maxTTLSeconds {
		a.failRequest(ctx, binding, operationReserve, request.ID, err)
		return
	}
	dimension := usageledger.Dimension(request.Dimension)
	if !a.dimensionAllowed(ctx, binding, operationReserve, dimension, request.ID) {
		return
	}
	reservation, counter, err := a.deps.Usage.ReserveAuthorized(
		ctx.Request().Context(), binding.Evidence(), usageledger.ReservationCommand{
			ID: request.ID, Dimension: dimension, Quantity: request.Quantity,
			IdempotencyKey: key, TTL: time.Duration(request.TTLSeconds) * time.Second,
		},
	)
	if err != nil {
		a.failUsage(ctx, binding, operationReserve, dimension, request.ID, err)
		return
	}
	a.observeSuccess(ctx, binding, operationReserve, dimension, reservation.ID)
	ctx.JSON(http.StatusCreated, map[string]any{
		responseReservation: reservation, responseCounter: counter,
	})
}

func (a *API) dimensionAllowed(
	ctx core.HandlerContext, binding *usageledger.SourceBinding, operation string,
	dimension usageledger.Dimension, resourceID string,
) bool {
	if binding.Allows(dimension) {
		return true
	}
	a.observeFailure(ctx, binding, operation, dimension, resourceID, ErrorDimensionNotAllowed)
	rejectMachine(ctx, http.StatusForbidden, ErrorDimensionNotAllowed,
		ErrorInsufficientScope, ScopeMeteringWrite)
	return false
}

func (a *API) failRequest(
	ctx core.HandlerContext, binding *usageledger.SourceBinding, operation, resourceID string, err error,
) {
	if err == nil {
		err = errInvalidJSON
	}
	code := writeMappedError(ctx, err)
	a.observeFailure(ctx, binding, operation, "", resourceID, code)
}

func (a *API) failUsage(
	ctx core.HandlerContext, binding *usageledger.SourceBinding, operation string,
	dimension usageledger.Dimension, resourceID string, err error,
) {
	if errors.Is(err, usageledger.ErrSourceBindingUnauthorized) {
		a.observeFailure(ctx, binding, operation, dimension, resourceID, ErrorSourceUnauthorized)
		rejectMachine(ctx, http.StatusForbidden, ErrorSourceUnauthorized,
			ErrorInsufficientScope, ScopeMeteringWrite)
		return
	}
	code := writeMappedError(ctx, err)
	a.observeFailure(ctx, binding, operation, dimension, resourceID, code)
}
