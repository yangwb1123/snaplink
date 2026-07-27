package selfservice

import (
	"net/http"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ---- Device listing & management ----

func HandleMyDevices(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusOK, map[string]any{"devices": []device.Device{}})
		return
	}
	devices, err := store.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list devices failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	devices = filterDevicesByQuery(ctx, devices)
	entries := make([]deviceEntry, len(devices))
	sessions, _ := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	sessionByDevice := mapDeviceSessions(sessions)
	for i, dev := range devices {
		entries[i] = deviceEntry{Device: *dev, ActiveSessions: sessionByDevice[dev.ID]}
	}
	// Sort devices by query parameter (?sort_by=name&sort_order=asc).
	sortDevices(entries, ctx.Query("sort_by"), ctx.Query("sort_order"))
	ctx.JSON(http.StatusOK, map[string]any{"devices": entries})
}

func HandleMyDeviceByID(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	type deviceDetail struct {
		device.Device
		ActiveSessions []core.Session `json:"active_sessions"`
	}
	sessions, _ := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	var activeSessions []core.Session
	for _, s := range sessions {
		if s.DeviceID == deviceID || (s.DeviceID == "" && s.IP == dev.LastIP) {
			activeSessions = append(activeSessions, *s)
		}
	}
	if activeSessions == nil {
		activeSessions = []core.Session{}
	}
	ctx.JSON(http.StatusOK, deviceDetail{Device: *dev, ActiveSessions: activeSessions})
}

// HandleUpdateMyDevice serves PATCH /me/devices/:id — updates device metadata
// (e.g., custom name, notes). Only the device owner can update their device.
func HandleUpdateMyDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	var req struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if req.Name != "" {
		dev.DeviceName = req.Name
	}
	dev.Notes = req.Notes
	if err := store.Upsert(ctx.Request().Context(), dev); err != nil {
		d.Logger().Error("update device failed", "device_id", deviceID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	resp := map[string]any{core.KeyStatus: core.StatusOK}
	if req.Name != "" {
		resp["device_name"] = req.Name
	}
	if req.Notes != "" {
		resp["notes"] = req.Notes
	}
	ctx.JSON(http.StatusOK, resp)
}

// HandleReportLostDevice serves POST /me/devices/:id/lost — marks a device as
// lost/stolen, revokes all its sessions, and flags the device record.
func HandleReportLostDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	// Revoke all sessions for this device.
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err == nil {
		for _, s := range sessions {
			if s.DeviceID == deviceID || (s.DeviceID == "" && s.IP == dev.LastIP) {
				d.SessionManager().Destroy(ctx.Request().Context(), s.ID)
			}
		}
	}
	// Flag the device as suspicious.
	dev.Suspicious = true
	if err := store.Upsert(ctx.Request().Context(), dev); err != nil {
		d.Logger().Error("report lost device: upsert failed", "device_id", deviceID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	d.Logger().Info("device reported lost", "user_id", userID, "device_id", deviceID, "device_ip", dev.LastIP)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "device_suspended": true})
}

// HandleSetDeviceTrust serves POST /me/devices/:id/trust — marks a device as
// trusted, boosting its trust score to 0.9 (Very High).
func HandleSetDeviceTrust(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	dev.TrustScore = 0.9
	dev.TrustLabel = device.TrustLabelForScore(0.9)
	dev.TrustHistory = appendTrustHistoryForReason(dev, 0.9, "manual_trust")
	if err := store.Upsert(ctx.Request().Context(), dev); err != nil {
		d.Logger().Error("trust device failed", "device_id", deviceID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK, "trust_score": 0.9, "trust_label": "Very High"})
}

func HandleDeleteMyDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.DeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err == nil {
		for _, s := range sessions {
			if s.DeviceID == deviceID || (s.DeviceID == "" && s.IP == dev.LastIP) {
				d.SessionManager().Destroy(ctx.Request().Context(), s.ID)
			}
		}
	}
	if err := store.Delete(ctx.Request().Context(), deviceID); err != nil {
		d.Logger().Error("delete device failed", "device_id", deviceID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}

func mapDeviceSessions(sessions []*core.Session) map[string]int {
	m := make(map[string]int)
	for _, s := range sessions {
		if s.DeviceID != "" {
			m[s.DeviceID]++
		}
	}
	return m
}

func appendTrustHistoryForReason(dev *device.Device, score float64, reason string) []device.TrustHistoryEntry {
	entry := device.TrustHistoryEntry{Time: time.Now(), Score: score, Label: device.TrustLabelForScore(score), Reason: reason}
	if dev == nil || len(dev.TrustHistory) == 0 {
		return []device.TrustHistoryEntry{entry}
	}
	h := append(dev.TrustHistory, entry)
	if len(h) > 20 {
		h = h[len(h)-20:]
	}
	return h
}

type deviceEntry struct {
	device.Device
	ActiveSessions int `json:"active_sessions"`
}

func sortDevices(entries []deviceEntry, sortBy, order string) {
	desc := order != "asc"
	switch sortBy {
	case "name":
		sort.Slice(entries, func(i, j int) bool { return sortStr(entries[i].DeviceName, entries[j].DeviceName, desc) })
	case "type":
		sort.Slice(entries, func(i, j int) bool { return sortStr(string(entries[i].Type), string(entries[j].Type), desc) })
	case "trust":
		sort.Slice(entries, func(i, j int) bool { return sortFloat(entries[i].TrustScore, entries[j].TrustScore, desc) })
	case "last_seen":
		sort.Slice(entries, func(i, j int) bool { return sortTime(entries[i].LastSeenAt, entries[j].LastSeenAt, desc) })
	case "created":
		sort.Slice(entries, func(i, j int) bool { return sortTime(entries[i].FirstSeenAt, entries[j].FirstSeenAt, desc) })
	case "sessions":
		sort.Slice(entries, func(i, j int) bool { return sortInt(entries[i].ActiveSessions, entries[j].ActiveSessions, desc) })
	}
}

func sortStr(a, b string, desc bool) bool {
	if desc {
		return a > b
	}
	return a < b
}
func filterDevicesByQuery(ctx core.HandlerContext, devices []*device.Device) []*device.Device {
	if fl := ctx.Query("trust_label"); fl != "" {
		devices = filterByField(devices, func(d *device.Device) string { return d.TrustLabel }, fl)
	}
	if ctx.Query("suspicious") == "true" {
		devices = filterByPred(devices, func(d *device.Device) bool { return d.Suspicious })
	}
	if fp := ctx.Query("platform"); fp != "" {
		devices = filterByField(devices, func(d *device.Device) string { return d.Platform }, fp)
	}
	if ft := ctx.Query("type"); ft != "" {
		devices = filterByField(devices, func(d *device.Device) string { return string(d.Type) }, ft)
	}
	return devices
}
func filterByField(devices []*device.Device, getter func(*device.Device) string, val string) []*device.Device {
	if val == "" {
		return devices
	}
	var out []*device.Device
	for _, d := range devices {
		if getter(d) == val {
			out = append(out, d)
		}
	}
	return out
}
func filterByPred(devices []*device.Device, pred func(*device.Device) bool) []*device.Device {
	var out []*device.Device
	for _, d := range devices {
		if pred(d) {
			out = append(out, d)
		}
	}
	return out
}
func sortFloat(a, b float64, desc bool) bool {
	if desc {
		return a > b
	}
	return a < b
}
func sortInt(a, b int, desc bool) bool {
	if desc {
		return a > b
	}
	return a < b
}
func sortTime(a, b time.Time, desc bool) bool {
	if desc {
		return a.After(b)
	}
	return a.Before(b)
}
