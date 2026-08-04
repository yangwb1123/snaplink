package commercehttp

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type adjustmentRequest struct {
	TenantID       string    `json:"tenant_id,omitempty"`
	Currency       string    `json:"currency"`
	AmountMinor    int64     `json:"amount_minor"`
	IdempotencyKey string    `json:"idempotency_key"`
	Reference      string    `json:"reference"`
	OccurredAt     time.Time `json:"occurred_at,omitempty"`
}

func (a *API) HandleGetWallet(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID, currency, ok := walletIdentity(ctx)
	if !ok {
		writeInvalidRequest(ctx)
		return
	}
	wallet, err := a.deps.Queries.GetWallet(ctx.Request().Context(), tenantID, currency)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{responseWallet: wallet})
}

func (a *API) HandleListLedgerEntries(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID, currency, ok := walletIdentity(ctx)
	if !ok {
		writeInvalidRequest(ctx)
		return
	}
	limit, ok := ledgerLimit(ctx.Query("limit"))
	if !ok {
		writeInvalidRequest(ctx)
		return
	}
	entries, err := a.deps.Queries.ListLedgerEntries(ctx.Request().Context(), tenantID, currency, limit)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	if entries == nil {
		entries = []*tenantcommerce.LedgerEntry{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyTenantID: tenantID, "currency": currency,
		responseEntries: entries, responseTotal: len(entries),
	})
}

func (a *API) HandlePostAdjustment(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	var request adjustmentRequest
	if tenantID == "" || oauth.BindParams(ctx, &request) != nil {
		a.invalidMutation(ctx, operationWalletAdjustment, tenantID, resourceWallet, tenantID)
		return
	}
	if request.IdempotencyKey == "" {
		request.IdempotencyKey = strings.TrimSpace(ctx.Request().Header.Get(headerIdempotency))
	}
	if !tenantMatchesPath(tenantID, request.TenantID) || !validAdjustment(request) {
		a.invalidMutation(ctx, operationWalletAdjustment, tenantID, resourceWallet, tenantID)
		return
	}
	command := tenantcommerce.PostLedgerCommand{
		TenantID: tenantID, Currency: request.Currency, Kind: tenantcommerce.LedgerAdjustment,
		AmountMinor: request.AmountMinor, IdempotencyKey: request.IdempotencyKey,
		Reference: request.Reference, OccurredAt: request.OccurredAt,
	}
	entry, wallet, err := a.deps.Commands.PostLedgerEntry(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationWalletAdjustment, tenantID, resourceWallet, tenantID, err)
		return
	}
	a.successfulMutation(ctx, operationWalletAdjustment, tenantID, resourceWallet, tenantID)
	ctx.JSON(http.StatusCreated, map[string]any{responseEntry: entry, responseWallet: wallet})
}

func walletIdentity(ctx core.HandlerContext) (string, string, bool) {
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	currency := strings.TrimSpace(ctx.Query("currency"))
	return tenantID, currency, tenantID != "" && validCurrency(currency)
}

func validCurrency(currency string) bool {
	return len(currency) == 3 && strings.ToUpper(currency) == currency
}

func validAdjustment(request adjustmentRequest) bool {
	return validCurrency(request.Currency) && request.AmountMinor != 0 &&
		strings.TrimSpace(request.IdempotencyKey) != "" && strings.TrimSpace(request.Reference) != ""
}

func ledgerLimit(raw string) (int, bool) {
	if raw == "" {
		return defaultLedgerLimit, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 || limit > maximumLedgerLimit {
		return 0, false
	}
	return limit, true
}
