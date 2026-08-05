package redis

import (
	"context"
	"testing"
	"time"
)

// TestNotificationCooldown_CheckAndSet proves the atomic suppression: the
// first call proceeds, calls inside the window are suppressed, and after
// the window elapses (server-side TTL) a new window opens.
func TestNotificationCooldown_CheckAndSet(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	c := NewNotificationCooldown(rdb)
	ctx := context.Background()
	now := time.Now()

	if ok, err := c.Suppressed(ctx, "u1\x00login", now, time.Minute); err != nil || ok {
		t.Fatalf("first call = (%v, %v), want proceed", ok, err)
	}
	if ok, err := c.Suppressed(ctx, "u1\x00login", now.Add(30*time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("in-window call = (%v, %v), want suppressed", ok, err)
	}
	// Different key: independent window.
	if ok, err := c.Suppressed(ctx, "u1\x00session", now, time.Minute); err != nil || ok {
		t.Fatalf("different-type call = (%v, %v), want proceed", ok, err)
	}
	// Fast-forward past the window TTL: a fresh window opens.
	mr.FastForward(2 * time.Minute)
	if ok, err := c.Suppressed(ctx, "u1\x00login", now.Add(2*time.Minute), time.Minute); err != nil || ok {
		t.Fatalf("post-window call = (%v, %v), want proceed", ok, err)
	}
}
