package admin

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
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


func HandleAdminListUserDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	userID := ctx.Param("id")
	if userID == "" { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	devices, err := store.ListByUser(ctx.Request().Context(), userID)
	if err != nil { d.Logger().Error("admin: list user devices", "error", err, "user_id", userID); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	ctx.JSON(http.StatusOK, map[string]any{"devices": devices})
}

func HandleAdminDeleteUserDevice(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	userID := ctx.Param("id"); deviceID := ctx.Param("deviceId")
	if userID == "" || deviceID == "" { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	if err := store.Delete(ctx.Request().Context(), deviceID); err != nil { d.Logger().Error("admin: delete user device", "error", err, "device_id", deviceID); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	if sm := d.SessionMgr(); sm != nil {
		if sessions, err := sm.ListByUser(ctx.Request().Context(), userID); err == nil {
			for _, s := range sessions { if s.DeviceID == deviceID || (s.DeviceID == "" && s.IP == dev.LastIP) { sm.Destroy(ctx.Request().Context(), s.ID) } }
		}
	}
	d.Logger().Info("admin: revoked user device", "user_id", userID, "device_id", deviceID, "device_ip", dev.LastIP)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}

func HandleAdminListAllDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil { d.Logger().Error("admin: list all devices", "error", err); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	ctx.JSON(http.StatusOK, map[string]any{"devices": filterDevices(ctx, devices), "total": len(devices)})
}

func HandleAdminDeviceStats(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil { d.Logger().Error("admin: device stats", "error", err); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	type ds struct { Total int `json:"total"`; ByType map[string]int `json:"by_type"`; Suspicious int `json:"suspicious"`; TrustLevels map[string]int `json:"trust_levels"`; Platforms map[string]int `json:"platforms"` }
	s := ds{Total: len(devices), ByType: make(map[string]int), TrustLevels: make(map[string]int), Platforms: make(map[string]int)}
	for _, d := range devices { s.ByType[string(d.Type)]++; if d.Suspicious { s.Suspicious++ }; if d.TrustLabel != "" { s.TrustLevels[d.TrustLabel]++ }; if d.Platform != "" { s.Platforms[d.Platform]++ } }
	ctx.JSON(http.StatusOK, s)
}

func HandleAdminDeviceActivity(d Deps, ctx core.HandlerContext) {
	deviceID := ctx.Param("id")
	if deviceID == "" { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	var dev *device.Device
	if ds := d.DeviceStore(); ds != nil { var err error; dev, err = ds.Get(ctx.Request().Context(), deviceID); if err != nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return } }
	if ls := d.LoginHistoryStore(); ls != nil { recs, err := ls.RecentByDevice(deviceID, 20); if err != nil { d.Logger().Error("admin: device activity", "error", err); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }; ctx.JSON(http.StatusOK, map[string]any{"device": dev, "activity": recs}); return }
	ctx.JSON(http.StatusOK, map[string]any{"device": dev, "activity": []*device.LoginRecord{}})
}

func HandleAdminResetDeviceTrust(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	dev, err := store.Get(ctx.Request().Context(), id)
	if err != nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	dev.TrustScore = 0.5; dev.TrustLabel = device.TrustLabelForScore(0.5)
	dev.TrustHistory = append(dev.TrustHistory, device.TrustHistoryEntry{Time: time.Now(), Score: 0.5, Label: "Medium", Reason: "admin_reset"})
	if err := store.Upsert(ctx.Request().Context(), dev); err != nil { d.Logger().Error("admin: reset device trust", "error", err, "device_id", id); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	d.Logger().Info("admin: reset device trust", "device_id", id, "user_id", dev.UserID)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "trust_score": 0.5, "trust_label": "Medium"})
}

func HandleAdminBulkRevokeDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	var req struct { TrustBelow float64 `json:"trust_below"`; Suspicious bool `json:"suspicious"`; Platform string `json:"platform"`; DeviceType string `json:"device_type"` }
	if err := ctx.Bind(&req); err != nil { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil { d.Logger().Error("admin: bulk revoke list", "error", err); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	matched := matchDevices(devices, req.TrustBelow, req.Suspicious, req.Platform, req.DeviceType)
	revoked := 0
	for _, dev := range matched {
		if sm := d.SessionMgr(); sm != nil { if sessions, err := sm.ListByUser(ctx.Request().Context(), dev.UserID); err == nil { for _, s := range sessions { if s.DeviceID == dev.ID { sm.Destroy(ctx.Request().Context(), s.ID) } } } }
		store.Delete(ctx.Request().Context(), dev.ID); revoked++
	}
	d.Logger().Info("admin: bulk revoke devices", "matched", len(matched), "revoked", revoked)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "matched": len(matched), "revoked": revoked})
}

func HandleAdminListUserLoginHistory(d Deps, ctx core.HandlerContext) {
	store := d.LoginHistoryStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	userID := ctx.Param("id"); if userID == "" { ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest)); return }
	recs, err := store.RecentByUser(userID, 50)
	if err != nil { d.Logger().Error("admin: list user login history", "error", err, "user_id", userID); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	ctx.JSON(http.StatusOK, map[string]any{"login_history": recs})
}

func HandleAdminListSecurityActivity(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound)); return }
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil { d.Logger().Error("admin: list security activity", "error", err); ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal)); return }
	type e struct { Type string `json:"type"`; UserID string `json:"user_id"`; DeviceID string `json:"device_id,omitempty"`; DeviceName string `json:"device_name,omitempty"`; TrustScore float64 `json:"trust_score,omitempty"`; Suspicious bool `json:"suspicious"`; Time string `json:"time,omitempty"` }
	var events []e
	for _, d := range devices { if d.Suspicious || d.TrustScore < 0.3 { events = append(events, e{Type: "suspicious_device", UserID: d.UserID, DeviceID: d.ID, DeviceName: d.DeviceName, TrustScore: d.TrustScore, Suspicious: d.Suspicious, Time: d.LastSeenAt.Format(time.RFC3339)}) } }
	ctx.JSON(http.StatusOK, map[string]any{"events": events})
}

func filterDevices(ctx core.HandlerContext, dvs []*device.Device) []*device.Device {
	if f := ctx.Query("type"); f != "" { dvs = filterField(dvs, func(d *device.Device) string { return string(d.Type) }, f) }
	if f := ctx.Query("platform"); f != "" { dvs = filterField(dvs, func(d *device.Device) string { return d.Platform }, f) }
	if f := ctx.Query("user_id"); f != "" { dvs = filterField(dvs, func(d *device.Device) string { return d.UserID }, f) }
	if f := ctx.Query("last_ip"); f != "" { dvs = filterField(dvs, func(d *device.Device) string { return d.LastIP }, f) }
	if ctx.Query("suspicious") == "true" { var o []*device.Device; for _, d := range dvs { if d.Suspicious { o = append(o, d) } }; dvs = o }
	if tl := ctx.Query("trust_level"); tl != "" { if min, max, ok := trustLevelRange(tl); ok { var o []*device.Device; for _, d := range dvs { if d.TrustScore >= min && d.TrustScore <= max { o = append(o, d) } }; dvs = o } }
	return dvs
}
func filterField(dvs []*device.Device, g func(*device.Device) string, v string) []*device.Device {
	if v == "" { return dvs }; var o []*device.Device; for _, d := range dvs { if g(d) == v { o = append(o, d) } }; return o
}
func trustLevelRange(l string) (float64, float64, bool) {
	switch l { case "very_low": return 0, 0.19, true; case "low": return 0.2, 0.39, true; case "medium": return 0.4, 0.59, true; case "high": return 0.6, 0.79, true; case "very_high": return 0.8, 1.0, true; default: return 0, 0, false }
}
func matchDevices(dvs []*device.Device, tb float64, susp bool, plat, dt string) []*device.Device {
	var o []*device.Device
	for _, d := range dvs {
		if tb > 0 && d.TrustScore >= tb { continue }; if susp && !d.Suspicious { continue }; if plat != "" && d.Platform != plat { continue }; if dt != "" && string(d.Type) != dt { continue }
		o = append(o, d)
	}
	return o
}
