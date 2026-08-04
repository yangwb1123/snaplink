package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestNotificationStoresDurablePagingAndPreferences(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "notifications.db")
	store, err := NewNotificationStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prefs, err := NewNotificationPreferenceStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer prefs.Close()
	ctx := context.Background()
	first := &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationSecurityEvent, Channel: core.NotificationChannelInApp}
	second := &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationAccountLocked, Channel: core.NotificationChannelInApp}
	if err := store.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	page, more, err := store.ListPage(ctx, "alice", "", false, 1)
	if err != nil || !more || len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("page=%#v more=%v err=%v", page, more, err)
	}
	if err := store.MarkReadForSubject(ctx, "bob", first.ID); err != core.ErrNotificationNotFound {
		t.Fatalf("foreign mark error=%v", err)
	}
	if err := store.MarkReadForSubject(ctx, "alice", first.ID); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.UnreadCount(ctx, "alice"); count != 1 {
		t.Fatalf("unread=%d", count)
	}
	want := core.NotificationPreference{SubjectID: "alice", Type: core.NotificationAccountLocked, Channel: core.NotificationChannelEmail, Enabled: false}
	if err := prefs.Put(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := prefs.ListBySubject(ctx, "alice")
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("preferences=%#v err=%v", got, err)
	}
}

func TestNotificationStorePrunesOldReadRowsOnWrite(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "notification-retention.db")
	store, err := NewNotificationStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	readAt := time.Now().Add(-91 * 24 * time.Hour)
	old := &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationSecurityEvent,
		Channel: core.NotificationChannelInApp, CreatedAt: readAt, ReadAt: &readAt}
	if err := store.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationSecurityEvent,
		Channel: core.NotificationChannelInApp}); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListBySubject(ctx, "alice", time.Time{}, 10)
	if err != nil || len(items) != 1 || items[0].ID == old.ID {
		t.Fatalf("items=%#v err=%v", items, err)
	}
}
