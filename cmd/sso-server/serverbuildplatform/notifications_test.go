package serverbuildplatform

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestBuildNotificationsMemoryAndSQLite(t *testing.T) {
	for _, cfg := range []config.NotificationsConfig{
		{Enabled: true, Backend: "memory", QueueSize: 8, Workers: 1},
		{Enabled: true, Backend: "sqlite", SQLite: config.NotificationSQLiteConfig{DSN: "file:" + filepath.Join(t.TempDir(), "n.db")}, QueueSize: 8, Workers: 1},
	} {
		opts, err := BuildNotifications(cfg, nil, nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		server := sso.NewServer(opts...)
		if server.NotificationStore() == nil || server.NotificationPreferenceStore() == nil {
			t.Fatalf("backend=%s not wired", cfg.Backend)
		}
		_ = server.NotificationStore().Create(context.Background(), &core.NotificationEvent{
			SubjectID: "alice", Type: core.NotificationSecurityEvent, Channel: core.NotificationChannelInApp})
		if count, _ := server.NotificationStore().UnreadCount(context.Background(), "alice"); count != 1 {
			t.Fatalf("backend=%s unread=%d", cfg.Backend, count)
		}
		if closer, ok := server.NotificationStore().(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		if closer, ok := server.NotificationPreferenceStore().(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

func TestBuildNotificationsEmailResolver(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(context.Background(), &core.User{ID: "alice", Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	opts, err := BuildNotifications(config.NotificationsConfig{Enabled: true, Backend: "memory",
		EmailEnabled: true, QueueSize: 8, Workers: 1}, users, nil, nil, nil, nil)
	if err != nil || len(opts) != 2 {
		t.Fatalf("opts=%d err=%v", len(opts), err)
	}
}
