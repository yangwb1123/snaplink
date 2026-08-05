package regiontest

import (
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/region"
	regionmemory "github.com/yangwb1123/snaplink/domains/region/memory"
	regionsqlite "github.com/yangwb1123/snaplink/domains/region/sqlite"
)

// Both shipped backends must satisfy the same contract. The memory store's
// Set returns an error now (deliberate API tightening), which does not
// affect its PolicyStore conformance.
func TestConformance_Memory(t *testing.T) {
	ConformanceSuite{
		New: func(t *testing.T) region.PolicyStore { return regionmemory.New() },
	}.Run(t)
}

func TestConformance_SQLite(t *testing.T) {
	ConformanceSuite{
		New: func(t *testing.T) region.PolicyStore {
			t.Helper()
			dsn := "file:" + filepath.Join(t.TempDir(), "region.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
			s, err := regionsqlite.New(dsn)
			if err != nil {
				t.Fatalf("sqlite store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
	}.Run(t)
}

// TestSQLite_PersistsAcrossReopen proves durability: Set → close → reopen
// the same DSN → the policy survives.
func TestSQLite_PersistsAcrossReopen(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "region.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	s, err := regionsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Set(t.Context(), "t1", region.ResidencyPolicy{HomeRegion: "eu-west-1", EnforceWrites: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	_ = s.Close()

	reopened, err := regionsqlite.New(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	got, err := reopened.GetPolicy(t.Context(), "t1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.HomeRegion != "eu-west-1" || !got.EnforceWrites {
		t.Errorf("policy not durable across reopen: %+v", got)
	}
}
