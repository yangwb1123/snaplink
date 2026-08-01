package memorystorenotification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestStoreInboxPagingReadAndErasure(t *testing.T) {
	store := New()
	ctx := context.Background()
	first := &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationSecurityEvent, Channel: core.NotificationChannelInApp}
	second := &core.NotificationEvent{SubjectID: "alice", Type: core.NotificationAccountLocked, Channel: core.NotificationChannelInApp}
	if err := store.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := store.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	page, more, err := store.ListPage(ctx, "alice", "", false, 1)
	if err != nil || !more || len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("page=%#v more=%v err=%v", page, more, err)
	}
	next, _, err := store.ListPage(ctx, "alice", second.ID, false, 2)
	if err != nil || len(next) != 1 || next[0].ID != first.ID {
		t.Fatalf("next=%#v err=%v", next, err)
	}
	if err := store.MarkReadForSubject(ctx, "mallory", first.ID); !errors.Is(err, core.ErrNotificationNotFound) {
		t.Fatalf("ownership error=%v", err)
	}
	if err := store.MarkReadForSubject(ctx, "alice", first.ID); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.UnreadCount(ctx, "alice"); count != 1 {
		t.Fatalf("unread=%d", count)
	}
	if err := store.DeleteForSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if items, _ := store.ListBySubject(ctx, "alice", time.Time{}, 20); len(items) != 0 {
		t.Fatalf("items remain: %d", len(items))
	}
}

func TestStorePreferencesAreIndependent(t *testing.T) {
	store := New()
	prefs := store.PreferenceStore()
	want := core.NotificationPreference{SubjectID: "alice", Type: core.NotificationNewDeviceLogin, Channel: core.NotificationChannelEmail, Enabled: false}
	if err := prefs.Put(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := prefs.ListBySubject(context.Background(), "alice")
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if err := prefs.DeleteForSubject(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	got, _ = prefs.ListBySubject(context.Background(), "alice")
	if len(got) != 0 {
		t.Fatalf("preferences remain: %#v", got)
	}
}
