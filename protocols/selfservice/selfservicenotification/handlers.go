// Package selfservicenotification implements the authenticated notification
// inbox without depending on the HTTP interface layer.
package selfservicenotification

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"
	"github.com/yangwb1123/snaplink/shared/core"
)

func HandleStream(d selfservicecore.Deps, ctx core.HandlerContext) {
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	broker := d.NotificationBroker()
	if broker == nil {
		unavailable(d, ctx, nil)
		return
	}
	sse.HandleFilteredStream(broker, sse.Filter{SubjectID: claims.Subject}, 0, ctx)
}

const (
	defaultLimit = 20
	maxLimit     = 100
	fallbackScan = 1000
)

func HandleList(d selfservicecore.Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	store := d.NotificationStore()
	if store == nil {
		unavailable(d, ctx, nil)
		return
	}
	limit, ok := parseLimit(ctx.Query("limit"))
	if !ok {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	unreadOnly, err := strconv.ParseBool(defaultString(ctx.Query("unread_only"), "false"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	items, hasMore, err := listPage(ctx, store, claims.Subject, ctx.Query("before_id"), unreadOnly, limit)
	if err != nil {
		unavailable(d, ctx, err)
		return
	}
	unread, err := store.UnreadCount(ctx.Request().Context(), claims.Subject)
	if err != nil {
		unavailable(d, ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"notifications": items, "unread_count": unread, "has_more": hasMore})
}

func HandleMarkRead(d selfservicecore.Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	store, id := d.NotificationStore(), strings.TrimSpace(ctx.Param("id"))
	if store == nil {
		unavailable(d, ctx, nil)
		return
	}
	if id == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	err := markOwned(ctx, store, claims.Subject, id)
	if errors.Is(err, core.ErrNotificationNotFound) {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err != nil {
		unavailable(d, ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "read", "id": id})
}

func HandleGetPreferences(d selfservicecore.Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	store := d.NotificationPreferenceStore()
	if store == nil {
		unavailable(d, ctx, nil)
		return
	}
	values, err := store.ListBySubject(ctx.Request().Context(), claims.Subject)
	if err != nil {
		unavailable(d, ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"preferences": mergeDefaults(claims.Subject, values)})
}

func HandlePutPreferences(d selfservicecore.Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	store := d.NotificationPreferenceStore()
	if store == nil {
		unavailable(d, ctx, nil)
		return
	}
	var req struct {
		Preferences []core.NotificationPreference `json:"preferences"`
	}
	if err := ctx.Bind(&req); err != nil || len(req.Preferences) > 32 {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	values, valid := validatePreferences(claims.Subject, req.Preferences)
	if !valid {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := replacePreferences(ctx, store, claims.Subject, values); err != nil {
		unavailable(d, ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"preferences": mergeDefaults(claims.Subject, values)})
}

func listPage(ctx core.HandlerContext, store core.NotificationStore, subjectID, beforeID string, unreadOnly bool, limit int) ([]*core.NotificationEvent, bool, error) {
	if pager, ok := store.(core.NotificationPageStore); ok {
		return pager.ListPage(ctx.Request().Context(), subjectID, beforeID, unreadOnly, limit)
	}
	items, err := store.ListBySubject(ctx.Request().Context(), subjectID, time.Time{}, fallbackScan)
	if err != nil {
		return nil, false, err
	}
	out, started := make([]*core.NotificationEvent, 0, limit+1), beforeID == ""
	for _, item := range items {
		if !started {
			started = item.ID == beforeID
			continue
		}
		if unreadOnly && item.ReadAt != nil {
			continue
		}
		out = append(out, item)
		if len(out) == limit+1 {
			break
		}
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func markOwned(ctx core.HandlerContext, store core.NotificationStore, subjectID, id string) error {
	if marker, ok := store.(core.NotificationSubjectMarker); ok {
		return marker.MarkReadForSubject(ctx.Request().Context(), subjectID, id)
	}
	items, err := store.ListBySubject(ctx.Request().Context(), subjectID, time.Time{}, fallbackScan)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ID == id {
			return store.MarkRead(ctx.Request().Context(), id)
		}
	}
	return core.ErrNotificationNotFound
}

func validatePreferences(subjectID string, input []core.NotificationPreference) ([]core.NotificationPreference, bool) {
	seen := map[string]struct{}{}
	out := make([]core.NotificationPreference, 0, len(input))
	for _, value := range input {
		if !knownType(value.Type) || !knownChannel(value.Channel) {
			return nil, false
		}
		key := string(value.Type) + "\x00" + string(value.Channel)
		if _, exists := seen[key]; exists {
			return nil, false
		}
		seen[key] = struct{}{}
		value.SubjectID = subjectID
		out = append(out, value)
	}
	return out, true
}

func replacePreferences(ctx core.HandlerContext, store core.NotificationPreferenceStore, subjectID string, values []core.NotificationPreference) error {
	if err := store.DeleteForSubject(ctx.Request().Context(), subjectID); err != nil {
		return err
	}
	for _, value := range values {
		if err := store.Put(ctx.Request().Context(), value); err != nil {
			return err
		}
	}
	return nil
}

func mergeDefaults(subjectID string, saved []core.NotificationPreference) []core.NotificationPreference {
	byKey := map[string]core.NotificationPreference{}
	for _, value := range saved {
		byKey[string(value.Type)+"\x00"+string(value.Channel)] = value
	}
	out := make([]core.NotificationPreference, 0, len(notificationTypes())*2)
	for _, typ := range notificationTypes() {
		for _, channel := range []core.NotificationChannel{core.NotificationChannelInApp, core.NotificationChannelEmail} {
			key := string(typ) + "\x00" + string(channel)
			value, ok := byKey[key]
			if !ok {
				value = core.NotificationPreference{SubjectID: subjectID, Type: typ, Channel: channel, Enabled: true}
			}
			out = append(out, value)
		}
	}
	return out
}

func notificationTypes() []core.NotificationType {
	return []core.NotificationType{core.NotificationPasswordExpiring, core.NotificationNewDeviceLogin, core.NotificationMFARemoved,
		core.NotificationConsentGranted, core.NotificationSessionExpiring, core.NotificationPasswordLeaked,
		core.NotificationAccountLocked, core.NotificationSecurityEvent}
}

func knownType(value core.NotificationType) bool {
	for _, item := range notificationTypes() {
		if item == value {
			return true
		}
	}
	return false
}

func knownChannel(value core.NotificationChannel) bool {
	return value == core.NotificationChannelInApp || value == core.NotificationChannelEmail
}

func parseLimit(raw string) (int, bool) {
	if raw == "" {
		return defaultLimit, true
	}
	value, err := strconv.Atoi(raw)
	return value, err == nil && value > 0 && value <= maxLimit
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func unavailable(d selfservicecore.Deps, ctx core.HandlerContext, err error) {
	if err != nil {
		d.Logger().Error("notification store unavailable", "error", err)
	}
	ctx.JSON(http.StatusServiceUnavailable, d.ErrorBody(core.ErrNotificationStoreUnavailable))
}
