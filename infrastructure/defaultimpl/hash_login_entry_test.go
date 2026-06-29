package defaultimpl_test

import (
	"testing"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/geo"
)

func TestHashLoginEntry_PopulatesAllFields(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	event := &anomaly.LoginEvent{
		SubjectID: "alice",
		ClientID:  "web",
		Outcome:   "success",
		RemoteIP:  "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		Geo: &geo.GeoInfo{
			CountryCode: "US",
			Latitude:    37.7749,
			Longitude:   -122.4194,
		},
		Timestamp: now,
	}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry == nil {
		t.Fatal("HashLoginEntry nil for valid event")
	}
	if entry.SubjectID != "alice" || entry.ClientID != "web" || entry.Outcome != "success" {
		t.Errorf("scalar fields: %+v", entry)
	}
	if entry.IPHash == "" || entry.IPHash == "10.0.0.1" {
		t.Errorf("IPHash should be salted hash, got %q", entry.IPHash)
	}
	if entry.UAFingerprintHash == "" {
		t.Errorf("UAFingerprintHash should be populated for non-empty UA")
	}
	if entry.CountryCode != "US" || entry.Latitude != 37.7749 || entry.Longitude != -122.4194 {
		t.Errorf("geo fields: %+v", entry)
	}
	if !entry.Timestamp.Equal(now) {
		t.Errorf("timestamp drift")
	}
}

func TestHashLoginEntry_NilEventReturnsNil(t *testing.T) {
	t.Parallel()
	if got := defaultimpl.HashLoginEntry(nil, []byte("salt")); got != nil {
		t.Errorf("nil event: got %v, want nil", got)
	}
}

func TestHashLoginEntry_EmptySubjectReturnsNil(t *testing.T) {
	t.Parallel()
	event := &anomaly.LoginEvent{Outcome: "failure"}
	if got := defaultimpl.HashLoginEntry(event, []byte("salt")); got != nil {
		t.Errorf("empty subject: got %v, want nil", got)
	}
}

func TestHashLoginEntry_EmptyUASkipsUAHash(t *testing.T) {
	t.Parallel()
	event := &anomaly.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry.UAFingerprintHash != "" {
		t.Errorf("empty UA: should not hash, got %q", entry.UAFingerprintHash)
	}
}

func TestHashLoginEntry_NilGeoSkipsGeoFields(t *testing.T) {
	t.Parallel()
	event := &anomaly.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry.CountryCode != "" || entry.Latitude != 0 || entry.Longitude != 0 {
		t.Errorf("nil geo: should leave geo fields zero, got %+v", entry)
	}
}

func TestHashLoginEntry_SaltAffectsIPHash(t *testing.T) {
	t.Parallel()
	event := &anomaly.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	a := defaultimpl.HashLoginEntry(event, []byte("salt-a"))
	b := defaultimpl.HashLoginEntry(event, []byte("salt-b"))
	if a.IPHash == b.IPHash {
		t.Errorf("different salts should produce different IP hashes; both = %q", a.IPHash)
	}
}

func TestHashLoginEntry_SameSubjectSameUAStableHash(t *testing.T) {
	t.Parallel()
	// Replay invariant: two events with same subject + UA + salt
	// produce same fingerprint, so the new-device detector can
	// compare across login events.
	event1 := &anomaly.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1", UserAgent: "Browser/1"}
	event2 := &anomaly.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.2", UserAgent: "Browser/1"}
	a := defaultimpl.HashLoginEntry(event1, []byte("salt"))
	b := defaultimpl.HashLoginEntry(event2, []byte("salt"))
	if a.UAFingerprintHash != b.UAFingerprintHash {
		t.Errorf("same subject + same UA should produce same hash: %q vs %q",
			a.UAFingerprintHash, b.UAFingerprintHash)
	}
}

func TestHashLoginEntry_DifferentSubjectsDifferentUAHash(t *testing.T) {
	t.Parallel()
	// Privacy invariant: same UA across two users produces
	// different hashes (per-subject salt).
	event1 := &anomaly.LoginEvent{SubjectID: "alice", UserAgent: "Browser/1"}
	event2 := &anomaly.LoginEvent{SubjectID: "bob", UserAgent: "Browser/1"}
	a := defaultimpl.HashLoginEntry(event1, []byte("salt"))
	b := defaultimpl.HashLoginEntry(event2, []byte("salt"))
	if a.UAFingerprintHash == b.UAFingerprintHash {
		t.Errorf("different subjects with same UA should produce different hashes; both = %q",
			a.UAFingerprintHash)
	}
}
