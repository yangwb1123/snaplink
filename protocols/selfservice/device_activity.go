package selfservice

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/shared/core"
)

type securityActivityEvent struct {
	Time       time.Time `json:"time"`
	Type       string    `json:"type"`
	Detail     string    `json:"detail,omitempty"`
	DeviceID   string    `json:"device_id,omitempty"`
	Device     string    `json:"device,omitempty"`
	Location   string    `json:"location,omitempty"`
	IP         string    `json:"ip,omitempty"`
	TrustScore float64   `json:"trust_score,omitempty"`
	TrustLabel string    `json:"trust_label,omitempty"`
}

func HandleMySessionsEnriched(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list sessions failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*core.Session{}
	}
	type enrichedSession struct {
		*core.Session
		DeviceName    string  `json:"device_name,omitempty"`
		DeviceType    string  `json:"device_type,omitempty"`
		DevicePlat    string  `json:"device_platform,omitempty"`
		DeviceOSVer   string  `json:"device_os_version,omitempty"`
		DeviceBrowser string  `json:"device_browser,omitempty"`
		TrustScore    float64 `json:"trust_score,omitempty"`
		TrustLabel    string  `json:"trust_label,omitempty"`
	}
	out := make([]enrichedSession, len(sessions))
	for i, s := range sessions {
		e := enrichedSession{Session: s}
		if ds := d.DeviceStore(); ds != nil && s.DeviceID != "" {
			if dev, err := ds.Get(ctx.Request().Context(), s.DeviceID); err == nil {
				e.DeviceName = dev.DeviceName
				e.DeviceType = string(dev.Type)
				e.DevicePlat = dev.Platform
				e.DeviceOSVer = dev.OSVersion
				e.DeviceBrowser = dev.BrowserName
				e.TrustScore = dev.TrustScore
				e.TrustLabel = dev.TrustLabel
			}
		}
		out[i] = e
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": out})
}

// HandleMyDeviceSessions serves GET /me/devices/:id/sessions — returns active
// sessions for a specific device. No-store headers.
func HandleMyDeviceSessions(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
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
		if s.DeviceID == deviceID || (s.DeviceID == "" && dev != nil && s.IP == dev.LastIP) {
			out = append(out, s)
		}
	}
	if out == nil {
		out = []*core.Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": out, "session_count": len(out)})
}

// HandleMyDeviceActivity serves GET /me/devices/:id/activity — returns login
// history for a specific device. No-store headers.
func HandleMyDeviceActivity(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
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
	if !ok {
		return
	}
	events := loginSecurityActivity(d.LoginHistoryStore(), userID)
	events = append(events, deviceSecurityActivity(ctx.Request().Context(), d.DeviceStore(), userID)...)
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > 30 {
		events = events[:30]
	}
	ctx.JSON(http.StatusOK, map[string]any{"events": events})
}

func loginSecurityActivity(store device.HistoryStore, userID string) []securityActivityEvent {
	if store == nil {
		return nil
	}
	records, err := store.RecentByUser(userID, 20)
	if err != nil {
		return nil
	}
	var events []securityActivityEvent
	for _, record := range records {
		events = append(events, securityActivityEvent{
			Time:     record.Time,
			Type:     loginSecurityActivityType(record),
			Detail:   record.Device,
			DeviceID: record.DeviceID,
			Device:   record.Device,
			Location: record.Location,
			IP:       record.IP,
		})
	}
	return events
}

func loginSecurityActivityType(record *device.LoginRecord) string {
	eventType := "login"
	if record.DeviceIsNew {
		eventType = "new_device"
	}
	if record.LocationIsNew {
		eventType = "new_location"
	}
	return eventType
}

func deviceSecurityActivity(ctx context.Context, store device.Store, userID string) []securityActivityEvent {
	if store == nil {
		return nil
	}
	devices, err := store.ListByUser(ctx, userID)
	if err != nil {
		return nil
	}
	var events []securityActivityEvent
	for _, dev := range devices {
		detail := dev.DeviceName
		if detail == "" {
			detail = string(dev.Type)
		}
		events = append(events, securityActivityEvent{
			Time:       dev.FirstSeenAt,
			Type:       "device_registered",
			Detail:     detail,
			DeviceID:   dev.ID,
			Device:     detail,
			IP:         dev.LastIP,
			TrustScore: dev.TrustScore,
			TrustLabel: dev.TrustLabel,
		})
	}
	return events
}

func HandleMyLoginHistory(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
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
