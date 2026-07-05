package userlifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
)

func TestIsDormant(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	day := 24 * time.Hour
	cases := []struct {
		name       string
		lastActive time.Time
		threshold  time.Duration
		want       bool
	}{
		{"idle past threshold", now.Add(-40 * day), 30 * day, true},
		{"active within threshold", now.Add(-10 * day), 30 * day, false},
		{"exactly at threshold is not past it", now.Add(-30 * day), 30 * day, false},
		{"zero last-active is unknown, never dormant", time.Time{}, 30 * day, false},
		{"non-positive threshold is off", now.Add(-100 * day), 0, false},
		{"negative threshold is off", now.Add(-100 * day), -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsDormant(c.lastActive, now, c.threshold); got != c.want {
				t.Errorf("IsDormant(%v, now, %v) = %v, want %v", c.lastActive, c.threshold, got, c.want)
			}
		})
	}
}

func TestSessionLastActive_NewestSession(t *testing.T) {
	sm := memorystoreidentity.NewMemorySessionManager()
	src := SessionLastActive{Sessions: sm}
	ctx := context.Background()

	// No sessions -> zero time (unknown, so IsDormant treats it as not dormant).
	got, err := src.LastActive(ctx, "user-1")
	if err != nil || !got.IsZero() {
		t.Fatalf("LastActive with no sessions = (%v, %v), want (zero, nil)", got, err)
	}

	before := time.Now().UTC()
	if _, err := sm.Create(ctx, "user-1"); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	got, err = src.LastActive(ctx, "user-1")
	if err != nil {
		t.Fatalf("LastActive: %v", err)
	}
	if got.Before(before) {
		t.Errorf("LastActive = %v, want >= %v (the live session's CreatedAt)", got, before)
	}
}

func TestSessionLastActive_NilManager(t *testing.T) {
	src := SessionLastActive{Sessions: nil}
	got, err := src.LastActive(context.Background(), "user-1")
	if err != nil || !got.IsZero() {
		t.Errorf("LastActive with nil manager = (%v, %v), want (zero, nil)", got, err)
	}
}
