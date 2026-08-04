package commercehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ClientCredentialsScopeMiddlewareFactory must return middleware that
// authenticates a Snaplink client_credentials access token and fails closed
// unless it grants the exact requested scope. The OAuth client must be
// registered client_credentials-only. Provider signature verification remains
// the external adapter's responsibility and precedes this route.
type ClientCredentialsScopeMiddlewareFactory func(requiredScope string) core.MiddlewareFunc

// RegisterPaymentEventRoute mounts the machine-only normalized fact endpoint.
// It intentionally cannot be mounted without an explicit scope gate: this is
// not a raw provider webhook and never receives provider signatures or secrets.
func (a *API) RegisterPaymentEventRoute(
	router core.Router, authorization ClientCredentialsScopeMiddlewareFactory,
) error {
	gate, err := a.paymentMachineGate(router, authorization, ScopePaymentWrite, ErrPaymentEventGateRequired)
	if err != nil {
		return err
	}
	router.Group("", gate).POST(PathPaymentEventIngest, a.HandlePaymentEvent)
	return nil
}

// RegisterPaymentOrderReadRoute mounts the least-privilege order snapshot
// endpoint used by out-of-process payment adapters before checkout creation.
func (a *API) RegisterPaymentOrderReadRoute(
	router core.Router, authorization ClientCredentialsScopeMiddlewareFactory,
) error {
	gate, err := a.paymentMachineGate(router, authorization, ScopePaymentOrderRead, ErrPaymentOrderGateRequired)
	if err != nil {
		return err
	}
	router.Group("", gate).GET(PathPaymentOrderRead, a.HandlePaymentOrderRead)
	return nil
}

func (a *API) paymentMachineGate(
	router core.Router, authorization ClientCredentialsScopeMiddlewareFactory, scope string, gateErr error,
) (core.MiddlewareFunc, error) {
	if router == nil {
		return nil, ErrRouterRequired
	}
	if authorization == nil {
		return nil, gateErr
	}
	if nilDependency(a.deps.PaymentSources) {
		return nil, ErrPaymentSourceRequired
	}
	gate := authorization(scope)
	if gate == nil {
		return nil, gateErr
	}
	return gate, nil
}

type normalizedPaymentEventRequest struct {
	TenantID        string                          `json:"tenant_id"`
	ID              string                          `json:"id"`
	Provider        string                          `json:"provider"`
	ProviderOrderID string                          `json:"provider_order_id"`
	OrderID         string                          `json:"order_id"`
	Type            tenantcommerce.PaymentEventType `json:"type"`
	Currency        string                          `json:"currency"`
	AmountMinor     int64                           `json:"amount_minor"`
	OccurredAt      time.Time                       `json:"occurred_at"`
}

type normalizedPaymentEventAlias normalizedPaymentEventRequest

func (r *normalizedPaymentEventRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*normalizedPaymentEventAlias)(r))
}

// HandlePaymentEvent accepts only the normalized fields above. There is no raw
// payload, signature, checkout credential, provider secret, or card-data field
// by design; the authenticated out-of-process adapter owns those concerns.
func (a *API) HandlePaymentEvent(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	orderID := strings.TrimSpace(ctx.Param("order_id"))
	var request normalizedPaymentEventRequest
	if !normalizedJSON(ctx) || tenantID == "" || orderID == "" || oauth.BindParams(ctx, &request) != nil ||
		request.TenantID != tenantID || request.OrderID != orderID {
		a.invalidMutation(ctx, operationPaymentEventApply, tenantID, resourcePaymentOrder, orderID)
		return
	}
	source, ok := a.paymentSourceEvidence(ctx, tenantID, request.Provider, orderID)
	if !ok {
		return
	}
	order, ok := a.paymentOrderForPath(ctx)
	if !ok {
		return
	}
	event := &tenantcommerce.PaymentEvent{
		ID: request.ID, Provider: request.Provider, ProviderOrderID: request.ProviderOrderID,
		OrderID: request.OrderID, Type: request.Type, Currency: request.Currency,
		AmountMinor: request.AmountMinor, OccurredAt: request.OccurredAt,
	}
	updated, entry, wallet, err := a.deps.Commands.ApplyAuthorizedPaymentEvent(
		ctx.Request().Context(), source, event,
	)
	if err != nil {
		if errors.Is(err, tenantcommerce.ErrPaymentSourceUnauthorized) {
			a.rejectPaymentSource(ctx, tenantID, order.ID)
			return
		}
		a.failMutation(ctx, operationPaymentEventApply, tenantID, resourcePaymentOrder, order.ID, err)
		return
	}
	a.successfulMutation(ctx, operationPaymentEventApply, tenantID, resourcePaymentOrder, order.ID)
	ctx.JSON(http.StatusOK, map[string]any{
		responseOrder: updated, responseEntry: entry, responseWallet: wallet,
	})
}

// HandlePaymentOrderRead returns a minimal trusted order snapshot only when
// the machine binding's payment provider owns the requested order.
func (a *API) HandlePaymentOrderRead(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	orderID := strings.TrimSpace(ctx.Param("order_id"))
	provider, ok := a.paymentSourceProvider(ctx, tenantID, orderID)
	if !ok {
		return
	}
	order, ok := a.paymentOrderForPath(ctx)
	if !ok {
		return
	}
	if order.Provider != provider {
		writeCommerceError(ctx, tenantcommerce.ErrPaymentNotFound)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{responseOrder: order})
}

func (a *API) paymentSourceProvider(ctx core.HandlerContext, tenantID, orderID string) (string, bool) {
	claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
	if !ok || claims == nil || claims.ClientID == "" || claims.Subject != claims.ClientID {
		a.rejectPaymentOrderRead(ctx, tenantID, orderID)
		return "", false
	}
	binding, err := a.deps.PaymentSources.Resolve(ctx.Request().Context(), claims.ClientID)
	sourceSystem := ""
	if binding != nil {
		sourceSystem = binding.SourceSystem
	}
	provider, validSource := strings.CutPrefix(sourceSystem, "payment:")
	expected, expectedErr := tenantcommerce.PaymentSourceSystem(provider)
	if err != nil || !validSource || expectedErr != nil || binding == nil || !binding.Enabled ||
		binding.ClientID != claims.ClientID || binding.TenantID != tenantID ||
		binding.SourceSystem != expected || len(binding.AllowedDimensions) != 0 {
		a.rejectPaymentOrderRead(ctx, tenantID, orderID)
		return "", false
	}
	return provider, true
}

func (a *API) rejectPaymentOrderRead(ctx core.HandlerContext, tenantID, orderID string) {
	a.observe(ctx, MutationRecord{
		Operation: operationPaymentOrderRead, TenantID: tenantID, ResourceType: resourcePaymentOrder,
		ResourceID: orderID, Outcome: MutationFailed, ErrorCode: ErrorInsufficientScope,
	})
	rejectPaymentMachine(ctx, http.StatusForbidden, ErrorInsufficientScope, ScopePaymentOrderRead)
}

func (a *API) paymentSourceEvidence(
	ctx core.HandlerContext, tenantID, provider, orderID string,
) (tenantcommerce.PaymentSourceEvidence, bool) {
	claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
	if !ok || claims == nil || claims.ClientID == "" || claims.Subject != claims.ClientID {
		a.rejectPaymentSource(ctx, tenantID, orderID)
		return tenantcommerce.PaymentSourceEvidence{}, false
	}
	binding, err := a.deps.PaymentSources.Resolve(ctx.Request().Context(), claims.ClientID)
	expected, expectedErr := tenantcommerce.PaymentSourceSystem(provider)
	if err != nil || expectedErr != nil || binding == nil || !binding.Enabled ||
		binding.ClientID != claims.ClientID || binding.TenantID != tenantID ||
		binding.SourceSystem != expected || len(binding.AllowedDimensions) != 0 {
		a.rejectPaymentSource(ctx, tenantID, orderID)
		return tenantcommerce.PaymentSourceEvidence{}, false
	}
	return tenantcommerce.PaymentSourceEvidence{
		BindingID: binding.ID, ClientID: binding.ClientID, TenantID: binding.TenantID,
		SourceSystem: binding.SourceSystem, Revision: binding.Revision,
	}, true
}

func (a *API) rejectPaymentSource(ctx core.HandlerContext, tenantID, orderID string) {
	a.observe(ctx, MutationRecord{
		Operation: operationPaymentEventApply, TenantID: tenantID, ResourceType: resourcePaymentOrder,
		ResourceID: orderID, Outcome: MutationFailed, ErrorCode: ErrorInsufficientScope,
	})
	rejectPaymentMachine(ctx, http.StatusForbidden, ErrorInsufficientScope, ScopePaymentWrite)
}

func normalizedJSON(ctx core.HandlerContext) bool {
	mediaType, _, err := mime.ParseMediaType(ctx.Request().Header.Get(core.HeaderContentType))
	return err == nil && mediaType == core.ContentTypeJSON
}
