package ssotest

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/shared/core"
)

func newGraceBackend(t *testing.T, backend string, window time.Duration) (tokengrant.RefreshGraceStore, func(time.Duration)) {
	t.Helper()
	advance := func(time.Duration) {}
	var store tokengrant.RefreshGraceStore
	switch backend {
	case "memory":
		store = tokengrant.NewRefreshGraceCache(window)
	case "sqlite":
		persistent, err := sqlite.NewRefreshGraceStoreWithDSN(filepath.Join(t.TempDir(), "grace.db"), window, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = persistent.Close() })
		store = persistent
	case "redis":
		server := miniredis.RunT(t)
		client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		store = redisbackend.NewRefreshGraceStore(client, window)
		advance = server.FastForward
	case "postgres":
		db, err := postgres.Open(postgres.Config{DSN: pgtest.Schema(t)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		persistent, err := postgres.NewRefreshGraceStoreWithDB(db, postgres.DialectPostgres, window, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = persistent.Close() })
		store = persistent
	default:
		t.Fatal("unknown grace backend")
	}
	return store, advance
}

func TestRefreshGraceBackendsRespectGrantDeadline(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite", "redis", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store, advance := newGraceBackend(t, backend, time.Hour)
			now := time.Now()
			body := map[string]any{core.KeyAccessToken: "issued", core.KeyRefreshToken: "successor", core.KeyRefreshGraceDeadline: now.Add(time.Second).Format(time.RFC3339Nano)}
			store.Remember("consumed", body, now)
			if _, hit := store.Lookup("consumed", now); !hit {
				t.Fatal("live deadline was not cached")
			}
			advance(2 * time.Second)
			if _, hit := store.Lookup("consumed", now.Add(2*time.Second)); hit {
				t.Fatal("grant deadline was extended to the one-hour configured window")
			}
			body[core.KeyRefreshGraceDeadline] = "malformed"
			store.Remember("malformed", body, now)
			if _, hit := store.Lookup("malformed", now); hit {
				t.Fatal("malformed deadline evidence was retained")
			}
		})
	}
}
