package meteringhttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

type errorMapping struct {
	target error
	status int
	code   string
}

var meteringErrorMappings = []errorMapping{
	{errBodyTooLarge, http.StatusRequestEntityTooLarge, ErrorRequestTooLarge},
	{errInvalidJSON, http.StatusBadRequest, core.ErrInvalidRequest},
	{usageledger.ErrInvalidFact, http.StatusBadRequest, ErrorInvalidFact},
	{usageledger.ErrInvalidPeriod, http.StatusBadRequest, ErrorInvalidFact},
	{usageledger.ErrInvalidReservation, http.StatusBadRequest, ErrorInvalidReservation},
	{usageledger.ErrUsageTimeInvalid, http.StatusBadRequest, ErrorInvalidFact},
	{usageledger.ErrReservationNotFound, http.StatusNotFound, ErrorReservationNotFound},
	{usageledger.ErrReservationConflict, http.StatusConflict, ErrorReservationConflict},
	{usageledger.ErrIdempotencyConflict, http.StatusConflict, ErrorIdempotencyConflict},
	{usageledger.ErrQuotaExceeded, http.StatusConflict, ErrorQuotaExceeded},
	{usageledger.ErrCounterOverflow, http.StatusConflict, ErrorCounterOverflow},
	{usageledger.ErrPeriodClosed, http.StatusConflict, ErrorPeriodClosed},
	{usageledger.ErrEntitlementMissing, http.StatusForbidden, ErrorEntitlementMissing},
	{commerce.ErrEntitlementNotFound, http.StatusNotFound, ErrorEntitlementNotFound},
	{context.Canceled, http.StatusServiceUnavailable, ErrorUnavailable},
	{context.DeadlineExceeded, http.StatusServiceUnavailable, ErrorUnavailable},
}

func meteringError(err error) (int, string) {
	for _, mapping := range meteringErrorMappings {
		if errors.Is(err, mapping.target) {
			return mapping.status, mapping.code
		}
	}
	return http.StatusInternalServerError, core.ErrInternal
}

func writeMappedError(ctx core.HandlerContext, err error) string {
	status, code := meteringError(err)
	writeMachineError(ctx, status, code)
	return code
}

func writeMachineError(ctx core.HandlerContext, status int, code string) {
	privateNoStore(ctx)
	ctx.JSON(status, core.ErrorBody(code))
}

func (a *API) observe(ctx core.HandlerContext, record MutationRecord) {
	if a.deps.Observer != nil {
		a.deps.Observer.ObserveMeteringMutation(ctx.Request().Context(), record)
	}
}

func (a *API) observeFailure(
	ctx core.HandlerContext, binding *usageledger.SourceBinding, operation string,
	dimension usageledger.Dimension, resourceID, code string,
) {
	a.observe(ctx, MutationRecord{
		Operation: operation, TenantID: binding.TenantID, SourceSystem: binding.SourceSystem,
		Dimension: dimension, ResourceID: resourceID, Outcome: MutationFailed, ErrorCode: code,
	})
}

func (a *API) observeSuccess(
	ctx core.HandlerContext, binding *usageledger.SourceBinding, operation string,
	dimension usageledger.Dimension, resourceID string,
) {
	a.observe(ctx, MutationRecord{
		Operation: operation, TenantID: binding.TenantID, SourceSystem: binding.SourceSystem,
		Dimension: dimension, ResourceID: resourceID, Outcome: MutationSucceeded,
	})
}
