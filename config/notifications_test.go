package config

import (
	"strings"
	"testing"
	"time"
)

func TestNotificationsDefaultsAndValidation(t *testing.T) {
	cfg := &Config{Notifications: NotificationsConfig{Enabled: true}}
	cfg.applyDefaults()
	if cfg.Notifications.Backend != "memory" || cfg.Notifications.Cooldown != 5*time.Minute ||
		cfg.Notifications.QueueSize != 256 || cfg.Notifications.Workers != 2 ||
		cfg.Notifications.SessionExpiryWarning != 30*time.Minute || cfg.Notifications.SessionScanInterval != time.Minute {
		t.Fatalf("defaults=%#v", cfg.Notifications)
	}
	if err := cfg.validateNotifications(); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationsRejectInvalidBackendAndSQLiteDSN(t *testing.T) {
	tests := []NotificationsConfig{
		{Enabled: true, Backend: "redis", QueueSize: 1, Workers: 1},
		{Enabled: true, Backend: "sqlite", QueueSize: 1, Workers: 1},
	}
	for _, value := range tests {
		cfg := &Config{Notifications: value}
		if err := cfg.validateNotifications(); err == nil || !strings.Contains(err.Error(), "notifications") {
			t.Fatalf("config=%#v err=%v", value, err)
		}
	}
}
