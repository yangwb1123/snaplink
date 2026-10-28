package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type shutdownGraceStore interface {
	DB() *sql.DB
	Ping(context.Context) error
	PruneExpired(context.Context) (int64, error)
	Remember(string, map[string]any, time.Time)
	PreparePending(string, map[string]any, time.Time)
	Lookup(string, time.Time) (map[string]any, bool)
}

func TestRefreshGraceForcedHTTPShutdown(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			cfg := graceLifecycleConfig(t, backend)
			if backend == "postgres" {
				cfg.Postgres.DSN = pgtest.Schema(t)
			}
			a, err := buildApp(cfg, spi.NopLogger{})
			if err != nil {
				t.Fatal(err)
			}
			store := a.server.RefreshGrace().(shutdownGraceStore)
			db := store.DB()
			now := time.Now()
			ready := map[string]any{core.KeyAccessToken: "issued", core.KeyRefreshToken: "successor"}
			pending := map[string]any{core.KeyRefreshGracePending: true, core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}
			store.Remember("consumed", ready, now)
			entered, release, handled, requested := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var resume sync.Once
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handled)
				close(entered)
				<-release
				// Model an unwinding handler: SPI operations retain their own contexts.
				for range 128 {
					_ = store.DB()
					_ = store.Ping(r.Context())
					_, _ = store.PruneExpired(r.Context())
					_, _ = store.Lookup("consumed", now)
					store.Remember("consumed", ready, now)
					store.PreparePending("pending", pending, now)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(func() {
				resume.Do(func() { close(release) })
				server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				shutdownSubsystems(ctx, a, spi.NopLogger{})
				waitGraceLifecycle(t, a.refreshGracePruneDone)
				closeAppStores(a)
			})
			go func() {
				defer close(requested)
				client := server.Client()
				client.Timeout = 3 * time.Second
				resp, err := client.Get(server.URL)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if err == nil {
					t.Error("blocked request survived forced HTTP close")
				}
			}()
			waitGraceLifecycle(t, entered)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			shutdownServers(ctx, spi.NopLogger{}, server.Config, nil, nil, nil)
			shutdownSchedulers(ctx, a, spi.NopLogger{})
			resume.Do(func() { close(release) })
			waitGraceLifecycle(t, handled)
			waitGraceLifecycle(t, requested)
			waitGraceLifecycle(t, a.refreshGracePruneDone)
			if store.DB() != nil {
				t.Fatal("forced shutdown retained grace database admission")
			}
			if _, hit := store.Lookup("consumed", now); hit {
				t.Fatal("closed grace wrapper replayed a credential")
			}
			if backend == "sqlite" {
				if err := db.PingContext(t.Context()); err == nil {
					t.Fatal("forced shutdown retained owned SQLite database")
				}
			} else if err := db.PingContext(t.Context()); err != nil {
				t.Fatalf("grace close released the shared PostgreSQL pool: %v", err)
			}
		})
	}
}
