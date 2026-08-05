package notification

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// deliveredKeys records deliveries so tests can assert suppression.
type deliveredKeys struct {
	keys []string // subjectID|type
}

func (d *deliveredKeys) SendNotification(_ context.Context, event *core.NotificationEvent) error {
	d.keys = append(d.keys, event.SubjectID+"|"+string(event.Type))
	return nil
}

// TestSharedCooldownStore_SuppressesAcrossRouters proves the cluster-shared
// contract: two routers sharing one cooldown store agree on the window —
// the first delivers, the second (a different replica seeing the same audit
// event) is suppressed. With the default in-process maps, both would
// deliver.
func TestSharedCooldownStore_SuppressesAcrossRouters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryCooldownStore()
	prefs := testPrefs{}
	event := &audit.Event{Type: audit.EventNewDeviceLogin, ActorID: "alice"}

	deliver := func(d *deliveredKeys) {
		t.Helper()
		router := NewRouter(nil, prefs, map[core.NotificationChannel]core.NotificationSender{
			core.NotificationChannelInApp: d,
		}, nil, WithCooldown(time.Minute), WithCooldownStore(store))
		router.route(ctx, event)
	}

	first := &deliveredKeys{}
	second := &deliveredKeys{}
	deliver(first)
	deliver(second)

	if len(first.keys) != 1 {
		t.Fatalf("first router delivered %d, want 1", len(first.keys))
	}
	if len(second.keys) != 0 {
		t.Fatalf("second router delivered %d; shared cooldown must suppress the duplicate replica delivery", len(second.keys))
	}
}

// TestInProcessCooldown_UnchangedWithoutStore pins the nil-store default:
// the router's own map still suppresses within one process.
func TestInProcessCooldown_UnchangedWithoutStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	prefs := testPrefs{}
	s := &deliveredKeys{}
	router := NewRouter(nil, prefs, map[core.NotificationChannel]core.NotificationSender{
		core.NotificationChannelInApp: s,
	}, nil, WithCooldown(time.Minute))
	event := &audit.Event{Type: audit.EventNewDeviceLogin, ActorID: "alice"}
	router.route(ctx, event)
	router.route(ctx, event)
	if len(s.keys) != 1 {
		t.Fatalf("delivered %d, want 1 (in-process cooldown still applies)", len(s.keys))
	}
}
