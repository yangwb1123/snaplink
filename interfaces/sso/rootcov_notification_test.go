package sso_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/notification"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type expiringPasswordStore struct{ changedAt time.Time }

func (s expiringPasswordStore) SetPassword(context.Context, string, string) error { return nil }
func (s expiringPasswordStore) VerifyPassword(context.Context, string, string) error {
	return nil
}
func (s expiringPasswordStore) PasswordChangedAt(context.Context, string) (time.Time, error) {
	return s.changedAt, nil
}

func TestRcov_NotificationInboxAndPreferences(t *testing.T) {
	store := defaultimpl.NewMemoryNotificationStore()
	prefs := store.PreferenceStore()
	server := rcovNewServer(t, sso.WithNotificationStore(store, prefs))
	access, _ := rcovDirectLogin(t, server)
	ctx := context.Background()
	event := &core.NotificationEvent{SubjectID: rcovUser, Type: core.NotificationAccountLocked,
		Title: "Account locked", Body: "Review activity", Severity: core.NotificationCritical, Channel: core.NotificationChannelInApp}
	if err := store.Create(ctx, event); err != nil {
		t.Fatal(err)
	}
	foreign := &core.NotificationEvent{SubjectID: "other", Type: core.NotificationSecurityEvent,
		Channel: core.NotificationChannelInApp}
	if err := store.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	status, out := rcovDo(t, http.MethodGet, server.http.URL+sso.PathMyNotifications+"?limit=1&unread_only=true", access, nil)
	if status != http.StatusOK || int(out["unread_count"].(float64)) != 1 {
		t.Fatalf("list status=%d body=%v", status, out)
	}
	items := out["notifications"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != event.ID {
		t.Fatalf("items=%v", items)
	}
	status, out = rcovPostJSON(t, server.http.URL+"/me/notifications/"+event.ID+"/read", access, nil)
	if status != http.StatusOK {
		t.Fatalf("mark status=%d body=%v", status, out)
	}
	status, out = rcovPostJSON(t, server.http.URL+"/me/notifications/"+foreign.ID+"/read", access, nil)
	if status != http.StatusNotFound || out["error"] != core.ErrNotFound {
		t.Fatalf("foreign mark status=%d body=%v", status, out)
	}
	status, out = rcovDo(t, http.MethodPut, server.http.URL+sso.PathMyNotificationPreferences, access, map[string]any{
		"preferences": []map[string]any{{"type": "unknown", "channel": "email", "enabled": false}},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid preferences status=%d body=%v", status, out)
	}
	status, out = rcovDo(t, http.MethodPut, server.http.URL+sso.PathMyNotificationPreferences, access, map[string]any{
		"preferences": []map[string]any{{"type": "account_locked", "channel": "email", "enabled": false}},
	})
	if status != http.StatusOK {
		t.Fatalf("put preferences status=%d body=%v", status, out)
	}
	status, out = rcovDo(t, http.MethodGet, server.http.URL+sso.PathMyNotificationPreferences, access, nil)
	if status != http.StatusOK || len(out["preferences"].([]any)) != 16 {
		t.Fatalf("get preferences status=%d body=%v", status, out)
	}
	if status, _ := rcovDo(t, http.MethodGet, server.http.URL+sso.PathMyNotifications, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d", status)
	}
}

func TestRcov_PasswordExpiryProducesNotification(t *testing.T) {
	inbox := defaultimpl.NewMemoryNotificationStore()
	prefs := inbox.PreferenceStore()
	router := notification.NewRouter(nil, prefs, map[core.NotificationChannel]core.NotificationSender{
		core.NotificationChannelInApp: inbox,
	}, nil, notification.WithCooldown(0), notification.WithWorkers(1))
	server := rcovNewServer(t,
		sso.WithPasswordCredentialStore(expiringPasswordStore{changedAt: time.Now().Add(-5 * 24 * time.Hour)}),
		sso.WithPasswordPolicy(spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MaxAgeDays: 10})),
		sso.WithNotificationStore(inbox, prefs), sso.WithNotificationRouter(router))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.srv.ShutdownNotificationRouter(ctx)
	})
	rcovDirectLogin(t, server)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items, err := inbox.ListBySubject(context.Background(), rcovUser, time.Time{}, 10)
		if err == nil && len(items) == 1 && items[0].Type == core.NotificationPasswordExpiring {
			if !hasRcovEvent(t, server.sink, audit.EventPasswordExpiring) {
				t.Fatal("password expiry audit event missing")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("password expiry notification was not delivered")
}
