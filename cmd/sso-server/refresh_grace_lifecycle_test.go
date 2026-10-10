package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestRefreshGraceShutdownDrainsThenClosesOwnedDatabase(t *testing.T) {
	store, err := sqlite.NewRefreshGraceStoreWithDSN(filepath.Join(t.TempDir(), "grace.db"), time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	db := store.DB()
	logger := spi.NopLogger{}
	done := closeGraceAfterPrune(store.CleanupDone(), store, logger)
	select {
	case <-done:
		t.Fatal("grace database closed while the runtime was active")
	default:
	}
	a := &app{refreshGracePruneCancel: store.CleanupStop(), refreshGracePruneDone: done}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	shutdownSchedulers(ctx, a, logger)
	select {
	case <-done:
	default:
		t.Fatal("shutdown returned before grace resources drained")
	}
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("DSN-owned database survived shutdown")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}
