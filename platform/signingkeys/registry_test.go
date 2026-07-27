package signingkeys

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestEventTypeConstants(t *testing.T) {
	if EventKeysUpserted != "keys_upserted" {
		t.Errorf("expected 'keys_upserted', got %q", EventKeysUpserted)
	}
	if EventKeysRemoved != "keys_removed" {
		t.Errorf("expected 'keys_removed', got %q", EventKeysRemoved)
	}
}

func TestAnnouncementFields(t *testing.T) {
	a := Announcement{
		ReplicaID:    "peer-1",
		Keys:         []core.JWK{{Kty: "OKP", Crv: "Ed25519"}},
		LeaseSeconds: 3600,
	}

	if a.ReplicaID != "peer-1" {
		t.Errorf("expected 'peer-1', got %q", a.ReplicaID)
	}
	if len(a.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(a.Keys))
	}
	if a.LeaseSeconds != 3600 {
		t.Errorf("expected 3600, got %d", a.LeaseSeconds)
	}
}

func TestEventFields(t *testing.T) {
	e := Event{
		Type: EventKeysUpserted,
		Announcement: Announcement{
			ReplicaID: "peer-1",
		},
	}

	if e.Type != EventKeysUpserted {
		t.Errorf("expected EventKeysUpserted, got %q", e.Type)
	}
	if e.Announcement.ReplicaID != "peer-1" {
		t.Errorf("expected 'peer-1', got %q", e.Announcement.ReplicaID)
	}
}

func TestAnnouncementZeroValue(t *testing.T) {
	var a Announcement
	if a.ReplicaID != "" {
		t.Errorf("expected empty ReplicaID, got %q", a.ReplicaID)
	}
	if len(a.Keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(a.Keys))
	}
}
