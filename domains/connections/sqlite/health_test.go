package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/connections"
	csqlite "github.com/snaplink/sso/domains/connections/sqlite"
)

func TestSQLite_Health_DefaultsToUnknown(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	h, err := s.Health(ctx, "nope")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != connections.HealthUnknown || !h.LastCheckedAt.IsZero() {
		t.Fatalf("Health(unknown) = %+v, want HealthUnknown/zero", h)
	}
}

func TestSQLite_RecordHealth_RoundTripsAndUpserts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	if err := s.Upsert(ctx, &connections.Connection{ID: "acme", TenantID: "t1", Type: connections.TypeOIDC}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.RecordHealth(ctx, "acme", &connections.ConnectionHealth{
		Status: connections.HealthHealthy, LastCheckedAt: now, LastSuccessAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h, err := s.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != connections.HealthHealthy || !h.LastCheckedAt.Equal(now) || !h.LastSuccessAt.Equal(now) {
		t.Fatalf("Health after record = %+v, want healthy at %v", h, now)
	}

	// Re-record (a second probe) UPSERTs rather than duplicating a row.
	later := now.Add(time.Minute)
	if err := s.RecordHealth(ctx, "acme", &connections.ConnectionHealth{
		Status: connections.HealthUnreachable, LastCheckedAt: later, LastSuccessAt: now, LastError: "dial tcp: refused",
	}); err != nil {
		t.Fatal(err)
	}
	h2, err := s.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if h2.Status != connections.HealthUnreachable || !h2.LastCheckedAt.Equal(later) || !h2.LastSuccessAt.Equal(now) || h2.LastError == "" {
		t.Fatalf("Health after second record = %+v", h2)
	}
}

func TestSQLite_Delete_ClearsHealth(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	if err := s.Upsert(ctx, &connections.Connection{ID: "acme", TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordHealth(ctx, "acme", &connections.ConnectionHealth{Status: connections.HealthHealthy, LastCheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	h, err := s.Health(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != connections.HealthUnknown {
		t.Errorf("Health after delete = %+v, want unknown (row cleared)", h)
	}
}

func TestSQLite_ConnectionsMaxVersion_IncludesHealthMigration(t *testing.T) {
	t.Parallel()
	if got := csqlite.ConnectionsMaxVersion(); got < 3 {
		t.Errorf("ConnectionsMaxVersion() = %d, want >= 3 (connection_health migration)", got)
	}
}
