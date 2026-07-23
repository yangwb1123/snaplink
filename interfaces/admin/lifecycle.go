package admin

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/connections/provider"
	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// ============================================================================
// User-lifecycle state-machine admin handlers
// ============================================================================

type lifecycleTransitionRequest struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func HandleAdminGetUserLifecycle(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID); err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	rec, err := d.LifecycleStore().Get(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin get lifecycle failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if rec.History == nil {
		rec.History = []userlifecycle.Transition{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id": userID, "state": rec.State,
		"allowed_transitions": userlifecycle.AllowedTransitions(rec.State),
		"history":             rec.History,
	})
}

func HandleAdminTransitionUserLifecycle(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	var req lifecycleTransitionRequest
	if userID == "" || oauth.BindParams(ctx, &req) != nil || strings.TrimSpace(req.State) == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID); err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	rec, err := d.LifecycleStore().Get(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin lifecycle get failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	to := userlifecycle.State(strings.TrimSpace(req.State))
	if err := userlifecycle.ValidateTransition(rec.State, to); err != nil {
		writeLifecycleValidationError(ctx, err)
		return
	}
	applyLifecycleTransition(d, ctx, userID, rec.State, to, req.Reason)
}

func applyLifecycleTransition(d Deps, ctx core.HandlerContext, userID string, from, to userlifecycle.State, reason string) {
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	t := userlifecycle.NewTransition(from, to, strings.TrimSpace(reason), actor, time.Now().UTC())
	if err := d.LifecycleStore().Append(ctx.Request().Context(), userID, t); err != nil {
		if errors.Is(err, userlifecycle.ErrStateConflict) {
			ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrLifecycleStateConflict))
			return
		}
		d.Logger().Error("admin lifecycle append failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	userlifecycle.RecordTransition(ctx.Request().Context(), d.Auditor(), userID, t)
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id": userID, "state": to, "previous_state": from,
		"allowed_transitions": userlifecycle.AllowedTransitions(to),
	})
}

func writeLifecycleValidationError(ctx core.HandlerContext, err error) {
	switch {
	case errors.Is(err, userlifecycle.ErrUnknownState):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownLifecycleState))
	default:
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrIllegalLifecycleTransition))
	}
}

// ============================================================================
// RFC 8693 token-exchange delegation-chain admin surface
// ============================================================================

func HandleTokenExchangeChain(store tokenexchange.ChainStore, log spi.Logger, ctx core.HandlerContext) {
	jti := strings.TrimSpace(ctx.Param("jti"))
	if jti == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	chain, err := store.GetChain(ctx.Request().Context(), jti)
	if err != nil {
		log.Error("admin token-exchange chain lookup failed", "error", err, "jti", jti)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if len(chain) == 0 {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "jti": jti, "chain": chain})
}

// ============================================================================
// Third-party login provider admin CRUD
// ============================================================================

type providerJSON struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id,omitempty"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	IconURL     string            `json:"icon_url,omitempty"`
	ButtonLabel string            `json:"button_label,omitempty"`
	ButtonColor string            `json:"button_color,omitempty"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

func providerToJSON(p *provider.Provider) providerJSON {
	return providerJSON{
		ID: p.ID, TenantID: p.TenantID, Type: string(p.Type),
		DisplayName: p.DisplayName, IconURL: p.IconURL,
		ButtonLabel: p.ButtonLabel, ButtonColor: p.ButtonColor,
		Enabled: p.Enabled, Config: p.Config,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func providerFromJSON(j providerJSON) *provider.Provider {
	return &provider.Provider{
		ID: j.ID, TenantID: j.TenantID, Type: provider.ProviderType(j.Type),
		DisplayName: j.DisplayName, IconURL: j.IconURL,
		ButtonLabel: j.ButtonLabel, ButtonColor: j.ButtonColor,
		Enabled: j.Enabled, Config: j.Config,
	}
}

func recordAdminProviderAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, providerID, tenantID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "provider_id", providerID)
	audit.SetMeta(evt, core.KeyTenantID, tenantID)
	aud.Record(ctx.Request().Context(), evt)
}

func HandleAdminListProviders(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	tenantID := ctx.Request().URL.Query().Get(core.KeyTenantID)
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	list, err := store.ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("admin: list providers", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DisplayName < list[j].DisplayName })
	out := make([]providerJSON, len(list))
	for i, p := range list {
		out[i] = providerToJSON(p)
	}
	ctx.JSON(http.StatusOK, map[string]any{"providers": out})
}

func HandleAdminGetProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	p, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, provider.ErrNoSuchProvider) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin: get provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, providerToJSON(p))
}

func HandleAdminCreateProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	var j providerJSON
	if err := ctx.Bind(&j); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	if j.ID == "" || j.Type == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if j.Config == nil {
		j.Config = make(map[string]string)
	}
	p := providerFromJSON(j)
	if err := store.Create(ctx.Request().Context(), p); err != nil {
		if errors.Is(err, provider.ErrProviderExists) {
			ctx.JSON(http.StatusConflict, core.ErrorBody("provider_already_exists"))
			return
		}
		d.Logger().Error("admin: create provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_created"), p.ID, p.TenantID)
	ctx.JSON(http.StatusCreated, providerToJSON(p))
}

func HandleAdminUpdateProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var j providerJSON
	if err := ctx.Bind(&j); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	j.ID = id
	p := providerFromJSON(j)
	if err := store.Update(ctx.Request().Context(), p); err != nil {
		if errors.Is(err, provider.ErrNoSuchProvider) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin: update provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_updated"), p.ID, p.TenantID)
	ctx.JSON(http.StatusOK, providerToJSON(p))
}

func HandleAdminDeleteProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	p, err := store.Get(ctx.Request().Context(), id)
	if err != nil && !errors.Is(err, provider.ErrNoSuchProvider) {
		d.Logger().Error("admin: get provider before delete", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	tenantID := ""
	if p != nil {
		tenantID = p.TenantID
	}
	if err := store.Delete(ctx.Request().Context(), id); err != nil {
		d.Logger().Error("admin: delete provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_deleted"), id, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}
