package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestPostgresRefreshGraceConcurrentClose(t *testing.T) {
	db, err := postgres.Open(postgres.Config{DSN: pgtest.Schema(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := postgres.NewRefreshGraceStoreWithDB(db, postgres.DialectPostgres, time.Minute, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()
	ready := map[string]any{core.KeyAccessToken: "issued", core.KeyRefreshToken: "successor"}
	pending := map[string]any{core.KeyRefreshGracePending: true, core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}
	s.Remember("consumed", ready, now)
	if _, hit := s.Lookup("consumed", now); !hit {
		t.Fatal("live grace store did not replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	actions := []func(){
		func() { _ = s.DB() },
		func() { _ = s.Ping(ctx) },
		func() { _, _ = s.PruneExpired(ctx) },
		func() { _, _ = s.Lookup("consumed", now) },
		func() { s.Remember("consumed", ready, now) },
		func() { s.PreparePending("pending", pending, now) },
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, action := range actions {
		wg.Go(func() {
			<-start
			for range 128 {
				action()
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			<-start
			if err := s.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if s.DB() != nil {
		t.Fatal("closed wrapper exposes a database")
	}
	if err := s.Ping(ctx); err == nil {
		t.Fatal("closed wrapper passed readiness")
	}
	if _, err := s.PruneExpired(ctx); err == nil {
		t.Fatal("closed wrapper admitted pruning")
	}
	if _, hit := s.Lookup("consumed", now); hit {
		t.Fatal("closed wrapper replayed a credential")
	}
	select {
	case <-s.CleanupDone():
	default:
		t.Fatal("Close returned before pruning stopped")
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("caller-owned PostgreSQL pool closed: %v", err)
	}
	var before, after int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM refresh_grace_cache").Scan(&before); err != nil {
		t.Fatal(err)
	}
	s.Remember("after-close", ready, now)
	s.PreparePending("after-close-pending", pending, now)
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM refresh_grace_cache").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("closed wrapper wrote into the caller-owned database")
	}
}

func TestPostgresRefreshGraceNilAndZeroClose(t *testing.T) {
	for _, s := range []*postgres.RefreshGraceStore{nil, {}} {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s.DB() != nil {
			t.Fatal("empty store exposes a database")
		}
		if _, hit := s.Lookup("unknown", time.Now()); hit {
			t.Fatal("empty store replayed a credential")
		}
	}
}
