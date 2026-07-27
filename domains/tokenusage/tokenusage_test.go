package tokenusage

import (
	"context"
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if KindAccess != "access" {
		t.Errorf("expected 'access', got %q", KindAccess)
	}
	if KindRefresh != "refresh" {
		t.Errorf("expected 'refresh', got %q", KindRefresh)
	}
	if EndpointToken != "token" {
		t.Errorf("expected 'token', got %q", EndpointToken)
	}
	if EndpointIntrospect != "introspect" {
		t.Errorf("expected 'introspect', got %q", EndpointIntrospect)
	}
}

func TestEventFields(t *testing.T) {
	now := time.Now()
	e := Event{
		Thumbprint: "tp-1",
		ClientID:   "client-1",
		SubjectID:  "user-1",
		Endpoint:   EndpointToken,
		Kind:       KindAccess,
		GeoCountry: "US",
		At:         now,
	}

	if e.Thumbprint != "tp-1" {
		t.Errorf("expected 'tp-1', got %q", e.Thumbprint)
	}
	if e.ClientID != "client-1" {
		t.Errorf("expected 'client-1', got %q", e.ClientID)
	}
	if e.Endpoint != EndpointToken {
		t.Errorf("expected token endpoint, got %q", e.Endpoint)
	}
	if e.Kind != KindAccess {
		t.Errorf("expected access kind, got %q", e.Kind)
	}
}

func TestBucketFields(t *testing.T) {
	now := time.Now()
	b := Bucket{
		Minute:   now,
		ClientID: "client-1",
		Kind:     KindRefresh,
		Endpoint: EndpointToken,
		Count:    42,
	}

	if b.Minute != now {
		t.Errorf("expected Minute %v, got %v", now, b.Minute)
	}
	if b.Count != 42 {
		t.Errorf("expected Count 42, got %d", b.Count)
	}
	if !b.Minute.Equal(now) {
		t.Error("Minute should be equal")
	}
}

func TestQueryZeroValues(t *testing.T) {
	q := Query{}
	if q.ClientID != "" {
		t.Errorf("expected empty ClientID, got %q", q.ClientID)
	}
	if !q.Since.IsZero() {
		t.Errorf("expected zero Since, got %v", q.Since)
	}
	if !q.Until.IsZero() {
		t.Errorf("expected zero Until, got %v", q.Until)
	}
}

func TestStoreInterface(t *testing.T) {
	// Compile-time check
	var _ Store = (*MemoryStore)(nil)
}

type MemoryStore struct{}

func (m *MemoryStore) Record(_ context.Context, ev Event) error { return nil }

func (m *MemoryStore) Query(_ context.Context, q Query) ([]Bucket, error) { return nil, nil }

func (m *MemoryStore) TrackedBuckets() int { return 0 }
