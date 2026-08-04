package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
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

func HandleAdminListUserDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	devices, err := store.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin: list user devices", "error", err, "user_id", userID)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"devices": devices})
}

func HandleAdminDeleteUserDevice(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	userID := ctx.Param("id")
	deviceID := ctx.Param("deviceId")
	if userID == "" || deviceID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	sessions := device.RevokeSessions(
		ctx.Request().Context(), d.SessionMgr(), userID, deviceID, dev.LastIP,
	)
	result := device.MutationResult{
		DeviceID: deviceID, DeviceStatus: device.MutationDeleted, Sessions: sessions,
	}
	if err := store.Delete(ctx.Request().Context(), deviceID); err != nil {
		d.Logger().Error("admin: delete user device", "error", err, "device_id", deviceID)
		result.DeviceStatus = device.MutationFailed
		result.DeviceError = "device_delete_failed"
	}
	d.Logger().Info("admin: revoked user device", "user_id", userID, "device_id", deviceID, "device_ip", dev.LastIP)
	writeAdminDeviceMutation(ctx, result)
}

func HandleAdminListAllDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin: list all devices", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"devices": filterDevices(ctx, devices), "total": len(devices)})
}

func HandleAdminDeviceStats(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin: device stats", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	type ds struct {
		Total       int            `json:"total"`
		ByType      map[string]int `json:"by_type"`
		Suspicious  int            `json:"suspicious"`
		TrustLevels map[string]int `json:"trust_levels"`
		Platforms   map[string]int `json:"platforms"`
	}
	s := ds{Total: len(devices), ByType: make(map[string]int), TrustLevels: make(map[string]int), Platforms: make(map[string]int)}
	for _, d := range devices {
		s.ByType[string(d.Type)]++
		if d.Suspicious {
			s.Suspicious++
		}
		if d.TrustLabel != "" {
			s.TrustLevels[d.TrustLabel]++
		}
		if d.Platform != "" {
			s.Platforms[d.Platform]++
		}
	}
	ctx.JSON(http.StatusOK, s)
}

func HandleAdminDeviceActivity(d Deps, ctx core.HandlerContext) {
	deviceID := ctx.Param("id")
	if deviceID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var dev *device.Device
	if ds := d.DeviceStore(); ds != nil {
		var err error
		dev, err = ds.Get(ctx.Request().Context(), deviceID)
		if err != nil {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
	}
	if ls := d.LoginHistoryStore(); ls != nil {
		recs, err := ls.RecentByDevice(deviceID, 20)
		if err != nil {
			d.Logger().Error("admin: device activity", "error", err)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		ctx.JSON(http.StatusOK, map[string]any{"device": dev, "activity": recs})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"device": dev, "activity": []*device.LoginRecord{}})
}

func HandleAdminResetDeviceTrust(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	dev, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	dev.TrustScore = 0.5
	dev.TrustLabel = device.TrustLabelForScore(0.5)
	dev.TrustHistory = append(dev.TrustHistory, device.TrustHistoryEntry{Time: time.Now(), Score: 0.5, Label: "Medium", Reason: "admin_reset"})
	if err := store.Upsert(ctx.Request().Context(), dev); err != nil {
		d.Logger().Error("admin: reset device trust", "error", err, "device_id", id)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.Logger().Info("admin: reset device trust", "device_id", id, "user_id", dev.UserID)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "trust_score": 0.5, "trust_label": "Medium"})
}

func HandleAdminBulkRevokeDevices(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	var req struct {
		TrustBelow float64 `json:"trust_below"`
		Suspicious bool    `json:"suspicious"`
		Platform   string  `json:"platform"`
		DeviceType string  `json:"device_type"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin: bulk revoke list", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	matched := matchDevices(devices, req.TrustBelow, req.Suspicious, req.Platform, req.DeviceType)
	revoked := 0
	results := make([]device.MutationResult, 0, len(matched))
	for _, dev := range matched {
		result := device.MutationResult{DeviceID: dev.ID, DeviceStatus: device.MutationDeleted,
			Sessions: device.RevokeSessions(ctx.Request().Context(), d.SessionMgr(), dev.UserID, dev.ID, dev.LastIP)}
		if err := store.Delete(ctx.Request().Context(), dev.ID); err != nil {
			d.Logger().Error("admin: bulk revoke device", "error", err, "device_id", dev.ID)
			result.DeviceStatus = device.MutationFailed
			result.DeviceError = "device_delete_failed"
		}
		if result.Succeeded() {
			revoked++
		}
		results = append(results, result)
	}
	d.Logger().Info("admin: bulk revoke devices", "matched", len(matched), "revoked", revoked)
	code, status := http.StatusOK, core.StatusOK
	if revoked != len(matched) {
		code = http.StatusMultiStatus
		status = "partial_failure"
	}
	ctx.JSON(code, map[string]any{
		core.KeyStatus: status, "matched": len(matched), "revoked": revoked,
		"failed": len(matched) - revoked, "results": results,
	})
}

func writeAdminDeviceMutation(ctx core.HandlerContext, result device.MutationResult) {
	code := http.StatusOK
	status := core.StatusOK
	if !result.Succeeded() {
		code = http.StatusMultiStatus
		status = "partial_failure"
	}
	ctx.JSON(code, map[string]any{core.KeyStatus: status, "result": result})
}

func HandleAdminListUserLoginHistory(d Deps, ctx core.HandlerContext) {
	store := d.LoginHistoryStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	recs, err := store.RecentByUser(userID, 50)
	if err != nil {
		d.Logger().Error("admin: list user login history", "error", err, "user_id", userID)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"login_history": recs})
}

func HandleAdminListSecurityActivity(d Deps, ctx core.HandlerContext) {
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	devices, err := store.ListAll(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin: list security activity", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	type e struct {
		Type       string  `json:"type"`
		UserID     string  `json:"user_id"`
		DeviceID   string  `json:"device_id,omitempty"`
		DeviceName string  `json:"device_name,omitempty"`
		TrustScore float64 `json:"trust_score,omitempty"`
		Suspicious bool    `json:"suspicious"`
		Time       string  `json:"time,omitempty"`
	}
	var events []e
	for _, d := range devices {
		if d.Suspicious || d.TrustScore < 0.3 {
			events = append(events, e{Type: "suspicious_device", UserID: d.UserID, DeviceID: d.ID, DeviceName: d.DeviceName, TrustScore: d.TrustScore, Suspicious: d.Suspicious, Time: d.LastSeenAt.Format(time.RFC3339)})
		}
	}
	ctx.JSON(http.StatusOK, map[string]any{"events": events})
}

func filterDevices(ctx core.HandlerContext, dvs []*device.Device) []*device.Device {
	if f := ctx.Query("type"); f != "" {
		dvs = filterField(dvs, func(d *device.Device) string { return string(d.Type) }, f)
	}
	if f := ctx.Query("platform"); f != "" {
		dvs = filterField(dvs, func(d *device.Device) string { return d.Platform }, f)
	}
	if f := ctx.Query("user_id"); f != "" {
		dvs = filterField(dvs, func(d *device.Device) string { return d.UserID }, f)
	}
	if f := ctx.Query("last_ip"); f != "" {
		dvs = filterField(dvs, func(d *device.Device) string { return d.LastIP }, f)
	}
	if ctx.Query("suspicious") == "true" {
		var o []*device.Device
		for _, d := range dvs {
			if d.Suspicious {
				o = append(o, d)
			}
		}
		dvs = o
	}
	if tl := ctx.Query("trust_level"); tl != "" {
		if min, max, ok := trustLevelRange(tl); ok {
			var o []*device.Device
			for _, d := range dvs {
				if d.TrustScore >= min && d.TrustScore <= max {
					o = append(o, d)
				}
			}
			dvs = o
		}
	}
	return dvs
}
func filterField(dvs []*device.Device, g func(*device.Device) string, v string) []*device.Device {
	if v == "" {
		return dvs
	}
	var o []*device.Device
	for _, d := range dvs {
		if g(d) == v {
			o = append(o, d)
		}
	}
	return o
}
func trustLevelRange(l string) (float64, float64, bool) {
	switch l {
	case "very_low":
		return 0, 0.19, true
	case "low":
		return 0.2, 0.39, true
	case "medium":
		return 0.4, 0.59, true
	case "high":
		return 0.6, 0.79, true
	case "very_high":
		return 0.8, 1.0, true
	default:
		return 0, 0, false
	}
}
func matchDevices(dvs []*device.Device, tb float64, susp bool, plat, dt string) []*device.Device {
	var o []*device.Device
	for _, d := range dvs {
		if tb > 0 && d.TrustScore >= tb {
			continue
		}
		if susp && !d.Suspicious {
			continue
		}
		if plat != "" && d.Platform != plat {
			continue
		}
		if dt != "" && string(d.Type) != dt {
			continue
		}
		o = append(o, d)
	}
	return o
}
