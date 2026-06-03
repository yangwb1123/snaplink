package sqlite

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/migrate"
	samlidp "github.com/snaplink/sso/saml/idp"
	"github.com/snaplink/sso/saml/samltest/sessionindextest"
)

const testSPCap = 8

// TestSessionIndexConformance_SQLite runs the shared session-index conformance
// suite against the sqlite SessionIndex — the SAME suite the in-memory index
// runs (saml/idp.TestSessionIndexConformance_Memory), so memory==sqlite on the
// shared contract (CRUD, in-place re-record, insertion order, blank-ignored,
// list-copy, per-subject SP cap). The subject-LRU bound is memory-only by design
// (see SessionIndexConformance's doc) and not asserted here.
func TestSessionIndexConformance_SQLite(t *testing.T) {
	sessionindextest.SessionIndexConformance{
		Factory: func(t *testing.T) samlidp.SAMLSessionIndex {
			idx, err := NewSessionIndex(uniqDSN("idp_sessidx_conf"), WithMaxSPsPerSubject(testSPCap))
			if err != nil {
				t.Fatalf("new session index: %v", err)
			}
			t.Cleanup(func() { _ = idx.Close() })
			return idx
		},
		SPsPerSubjectCap: testSPCap,
	}.Run(t)
}

// TestSessionIndex_ReRecordBumpsOrder proves a re-recorded SP moves to the
// newest position (recorded_at bumped), matching the memory store's MoveToBack —
// so the per-subject cap evicts by genuine recency, not original insert order.
func TestSessionIndex_ReRecordBumpsOrder(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_sessidx_order"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()
	const sub = "u@example.com"

	_ = idx.Record(ctx, sub, row("sp-1"))
	time.Sleep(time.Millisecond) // ensure a distinct recorded_at nanosecond
	_ = idx.Record(ctx, sub, row("sp-2"))
	time.Sleep(time.Millisecond)
	// Re-record sp-1 → it becomes newest; order should now be sp-2, sp-1.
	_ = idx.Record(ctx, sub, row("sp-1"))

	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 2 || rows[0].SPEntityID != "sp-2" || rows[1].SPEntityID != "sp-1" {
		t.Fatalf("re-record did not bump recency: %+v", rows)
	}
}

// TestSessionIndex_Migration proves the baseline migration applies on a fresh DB
// (records v1) and no-ops on re-open.
func TestSessionIndex_Migration(t *testing.T) {
	db := openSharedDB(t, "idp_sessidx_migrate")
	ctx := context.Background()
	if _, err := NewSessionIndexWithDB(db); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	if v, err := migrate.CurrentVersion(ctx, db, "saml_session_index"); err != nil || v != 1 {
		t.Fatalf("version = %d (err %v), want 1", v, err)
	}
	if _, err := NewSessionIndexWithDB(db); err != nil {
		t.Fatalf("populated: %v", err)
	}
	if v, _ := migrate.CurrentVersion(ctx, db, "saml_session_index"); v != 1 {
		t.Fatalf("version after re-open = %d, want 1", v)
	}
}

// TestSessionIndex_SharedDBNamespaceIsolation proves the session index + the
// logout-replay store can share one *sql.DB without their migration namespaces
// clobbering each other (distinct schema_migrations_* tables, both v1).
func TestSessionIndex_SharedDBNamespaceIsolation(t *testing.T) {
	db := openSharedDB(t, "idp_shared")
	ctx := context.Background()
	if _, err := NewSessionIndexWithDB(db); err != nil {
		t.Fatalf("session index: %v", err)
	}
	if _, err := NewLogoutReplayStoreWithDB(db); err != nil {
		t.Fatalf("logout replay: %v", err)
	}
	for _, ns := range []string{"saml_session_index", "saml_idp_logout_replay"} {
		if v, err := migrate.CurrentVersion(ctx, db, ns); err != nil || v != 1 {
			t.Fatalf("namespace %s version = %d (err %v), want 1", ns, v, err)
		}
	}
}

// TestSessionIndex_ConcurrentRecordSameSP hammers Record for the SAME
// (subject, SP) from many goroutines and asserts the upsert leaves EXACTLY ONE
// row (the composite PK + ON CONFLICT collapses concurrent inserts). Run with
// -race -count=10.
func TestSessionIndex_ConcurrentRecordSameSP(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_sessidx_conc"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()
	const sub = "race@example.com"

	const workers = 24
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			_ = idx.Record(ctx, sub, row("sp-shared"))
		}()
	}
	wg.Wait()
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 1 {
		t.Fatalf("concurrent upsert of one (subject,SP) left %d rows, want 1", len(rows))
	}
}

// TestSessionIndex_ConcurrentMixed hammers Record/List/Remove/RemoveAll across
// many subjects (race-detector + bound check). Run with -race -count=10.
func TestSessionIndex_ConcurrentMixed(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_sessidx_mixed"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 80; i++ {
				sub := fmt.Sprintf("sub-%d", (w+i)%24)
				sp := fmt.Sprintf("sp-%d", i%6)
				_ = idx.Record(ctx, sub, row(sp))
				_, _ = idx.ListBySubject(ctx, sub)
				if i%5 == 0 {
					_ = idx.Remove(ctx, sub, sp)
				}
				if i%40 == 0 {
					_ = idx.RemoveAll(ctx, sub)
				}
			}
		}(w)
	}
	wg.Wait()
}

func row(spEntityID string) samlidp.SAMLSPSession {
	return samlidp.SAMLSPSession{
		SPEntityID: spEntityID,
		SPClientID: spEntityID + "-client",
		SPSLOUrl:   "https://" + spEntityID + "/slo",
		SPBinding:  samlidp.BindingRedirect,
		NameID:     "nameid",
	}
}
