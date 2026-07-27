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
	if !ok { return }
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
	if !ok { return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
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
	if activeSessions == nil { activeSessions = []core.Session{} }
	ctx.JSON(http.StatusOK, deviceDetail{Device: *dev, ActiveSessions: activeSessions})
}

// HandleUpdateMyDevice serves PATCH /me/devices/:id — updates device metadata
// (e.g., custom name, notes). Only the device owner can update their device.
func HandleUpdateMyDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
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
	if req.Name != "" { resp["device_name"] = req.Name }
	if req.Notes != "" { resp["notes"] = req.Notes }
	ctx.JSON(http.StatusOK, resp)
}

// HandleReportLostDevice serves POST /me/devices/:id/lost — marks a device as
// lost/stolen, revokes all its sessions, and flags the device record.
func HandleReportLostDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
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
	if !ok { return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
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
	if !ok { return }
	store := d.DeviceStore()
	if store == nil { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
	deviceID := ctx.Param("id")
	dev, err := store.Get(ctx.Request().Context(), deviceID)
	if err != nil || dev.UserID != userID { ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound)); return }
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
		if s.DeviceID != "" { m[s.DeviceID]++ }
	}
	return m
}

func appendTrustHistoryForReason(dev *device.Device, score float64, reason string) []device.TrustHistoryEntry {
	entry := device.TrustHistoryEntry{Time: time.Now(), Score: score, Label: device.TrustLabelForScore(score), Reason: reason}
	if dev == nil || len(dev.TrustHistory) == 0 { return []device.TrustHistoryEntry{entry} }
	h := append(dev.TrustHistory, entry)
	if len(h) > 20 { h = h[len(h)-20:] }
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
	if desc { return a > b }; return a < b
}
func filterDevicesByQuery(ctx core.HandlerContext, devices []*device.Device) []*device.Device {
	if fl := ctx.Query("trust_label"); fl != "" { devices = filterByField(devices, func(d *device.Device) string { return d.TrustLabel }, fl) }
	if ctx.Query("suspicious") == "true" { devices = filterByPred(devices, func(d *device.Device) bool { return d.Suspicious }) }
	if fp := ctx.Query("platform"); fp != "" { devices = filterByField(devices, func(d *device.Device) string { return d.Platform }, fp) }
	if ft := ctx.Query("type"); ft != "" { devices = filterByField(devices, func(d *device.Device) string { return string(d.Type) }, ft) }
	return devices
}
func filterByField(devices []*device.Device, getter func(*device.Device) string, val string) []*device.Device {
	if val == "" { return devices }
	var out []*device.Device
	for _, d := range devices { if getter(d) == val { out = append(out, d) } }
	return out
}
func filterByPred(devices []*device.Device, pred func(*device.Device) bool) []*device.Device {
	var out []*device.Device
	for _, d := range devices { if pred(d) { out = append(out, d) } }
	return out
}
func sortFloat(a, b float64, desc bool) bool {
	if desc { return a > b }; return a < b
}
func sortInt(a, b int, desc bool) bool {
	if desc { return a > b }; return a < b
}
func sortTime(a, b time.Time, desc bool) bool {
	if desc { return a.After(b) }; return a.Before(b)
}

// ---- Enriched session listing ----

func HandleMySessionsEnriched(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list sessions failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if sessions == nil { sessions = []*core.Session{} }
	type enrichedSession struct {
		*core.Session
		DeviceName string `json:"device_name,omitempty"`
		DeviceType string `json:"device_type,omitempty"`
		DevicePlat string `json:"device_platform,omitempty"`
		DeviceOSVer string `json:"device_os_version,omitempty"`
		DeviceBrowser string `json:"device_browser,omitempty"`
		TrustScore float64 `json:"trust_score,omitempty"`
		TrustLabel string `json:"trust_label,omitempty"`
	}
	out := make([]enrichedSession, len(sessions))
	for i, s := range sessions {
		e := enrichedSession{Session: s}
		if ds := d.DeviceStore(); ds != nil && s.DeviceID != "" {
			if dev, err := ds.Get(ctx.Request().Context(), s.DeviceID); err == nil {
				e.DeviceName = dev.DeviceName; e.DeviceType = string(dev.Type)
				e.DevicePlat = dev.Platform; e.DeviceOSVer = dev.OSVersion
				e.DeviceBrowser = dev.BrowserName
				e.TrustScore = dev.TrustScore; e.TrustLabel = dev.TrustLabel
			}
		}
		out[i] = e
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": out})
}

// ---- Security activity timeline ----

// HandleMyDeviceSessions serves GET /me/devices/:id/sessions — returns active
// sessions for a specific device. No-store headers.
func HandleMyDeviceSessions(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	deviceID := ctx.Param("id")
	// Verify device ownership and capture device for IP fallback.
	var dev *device.Device
	if ds := d.DeviceStore(); ds != nil {
		var err error
		dev, err = ds.Get(ctx.Request().Context(), deviceID)
		if err != nil || dev.UserID != userID {
			ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
			return
		}
	}
	// List matching sessions.
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("device sessions: list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	var out []*core.Session
	for _, s := range sessions {
		if s.DeviceID == deviceID || (s.DeviceID == "" && dev != nil && s.IP == dev.LastIP) { out = append(out, s) }
	}
	if out == nil { out = []*core.Session{} }
	ctx.JSON(http.StatusOK, map[string]any{"sessions": out, "session_count": len(out)})
}

// HandleMyDeviceActivity serves GET /me/devices/:id/activity — returns login
// history for a specific device. No-store headers.
func HandleMyDeviceActivity(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	deviceID := ctx.Param("id")
	// Verify the device belongs to this user.
	if ds := d.DeviceStore(); ds != nil {
		dev, err := ds.Get(ctx.Request().Context(), deviceID)
		if err != nil || dev.UserID != userID {
			ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
			return
		}
	}
	// Query login history for this device.
	if ls := d.LoginHistoryStore(); ls != nil {
		recs, err := ls.RecentByDevice(deviceID, 20)
		if err != nil {
			d.Logger().Error("device activity: list failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
			return
		}
		ctx.JSON(http.StatusOK, map[string]any{"activity": recs})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"activity": []*device.LoginRecord{}})
}

func HandleMySecurityActivity(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	type actEvt struct {
		Time time.Time `json:"time"`
		Type string `json:"type"`
		Detail string `json:"detail,omitempty"`
		DeviceID string `json:"device_id,omitempty"`
		Device string `json:"device,omitempty"`
		Location string `json:"location,omitempty"`
		IP string `json:"ip,omitempty"`
		TrustScore float64 `json:"trust_score,omitempty"`
		TrustLabel string `json:"trust_label,omitempty"`
	}
	var events []actEvt
	if ls := d.LoginHistoryStore(); ls != nil {
		if recs, err := ls.RecentByUser(userID, 20); err == nil {
			for _, r := range recs {
				typ := "login"
				if r.DeviceIsNew { typ = "new_device" }
				if r.LocationIsNew { typ = "new_location" }
				events = append(events, actEvt{Time: r.Time, Type: typ, Detail: r.Device, DeviceID: r.DeviceID, Device: r.Device, Location: r.Location, IP: r.IP})
			}
		}
	}
	if ds := d.DeviceStore(); ds != nil {
		if devs, err := ds.ListByUser(ctx.Request().Context(), userID); err == nil {
			for _, dev := range devs {
				detail := dev.DeviceName
				if detail == "" { detail = string(dev.Type) }
				events = append(events, actEvt{Time: dev.FirstSeenAt, Type: "device_registered", Detail: detail, DeviceID: dev.ID, Device: detail, IP: dev.LastIP, TrustScore: dev.TrustScore, TrustLabel: dev.TrustLabel})
			}
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > 30 { events = events[:30] }
	ctx.JSON(http.StatusOK, map[string]any{"events": events})
}

// ---- Login history ----

func HandleMyLoginHistory(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok { return }
	store := d.LoginHistoryStore()
	if store == nil {
		ctx.JSON(http.StatusOK, map[string]any{"login_history": []*device.LoginRecord{}})
		return
	}
	recs, err := store.RecentByUser(userID, 20)
	if err != nil {
		d.Logger().Error("login history: list failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"login_history": recs})
}
