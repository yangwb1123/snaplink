package securitystore

import (
	"context"
	"errors"
	"testing"
	"time"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

func TestRevocationsExactKeysExpiryReopenAndCancel(t *testing.T) {
	db, dsn := fixture(t)
	s, err := NewRevocationStoreWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "Token", "token", "token ", "用户😀"} {
		if err := s.Revoke(t.Context(), token, 9007199254740993); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Revoke(t.Context(), "expired", time.Now().Unix()-60); err != nil {
		t.Fatal(err)
	}
	b, err := NewRevocationStoreWithDB(openPool(t, dsn), pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Load(t.Context())
	if err != nil || len(got) != 5 || got["用户😀"] != 9007199254740993 {
		t.Fatalf("exact re-seed shape=%d error=%v", len(got), err)
	}
	if err := b.Prune(t.Context(), 9007199254740993); err != nil || scalar(t, db, "SELECT COUNT(*) FROM revocations") != 5 {
		t.Fatal("expiry equality was pruned", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.Revoke(ctx, "cancelled", 9007199254740993); err == nil || scalar(t, db, "SELECT COUNT(*) FROM revocations WHERE token='cancelled'") != 0 {
		t.Fatal("cancelled revocation persisted")
	}
	if err := s.Close(); err != nil || db.PingContext(t.Context()) != nil {
		t.Fatal("adapter retired caller-owned pool", err)
	}
	if _, err := s.Load(t.Context()); err == nil {
		t.Fatal("closed adapter accepted load")
	}
}

func TestRevocationBudgetsRejectPartialSeed(t *testing.T) {
	db, _ := fixture(t)
	s, err := NewRevocationStoreWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, "INSERT INTO revocations SELECT i::text,9007199254740993 FROM generate_series(1,$1) i", maxRevocations+1)
	if got, err := s.Load(t.Context()); err == nil || got != nil {
		t.Fatal("row budget published a partial deny-set")
	}
	exec(t, db, "DELETE FROM revocations")
	exec(t, db, "INSERT INTO revocations SELECT md5(i::text)||repeat('x',2000),9007199254740993 FROM generate_series(1,10000) i")
	if got, err := s.Load(t.Context()); err == nil || got != nil {
		t.Fatal("byte budget published a partial deny-set")
	}
}

func TestSecuritySchemasAheadAndMissingPoolFailClosed(t *testing.T) {
	if _, err := NewRevocationStoreWithDB(nil, pg.DialectPostgres); err == nil {
		t.Fatal("missing revocation pool accepted")
	}
	if _, err := NewAccountLockoutWithDB(nil, pg.DialectPostgres); err == nil {
		t.Fatal("missing lockout pool accepted")
	}
	db, _ := fixture(t)
	if _, err := NewAccountLockoutWithDB(db, pg.DialectCockroach); err == nil {
		t.Fatal("uncertified lockout dialect accepted")
	}
	s, err := NewRevocationStoreWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(t.Context(), "preserved", 9007199254740993); err != nil {
		t.Fatal(err)
	}
	exec(t, db, "UPDATE schema_migrations_revocations SET version=$1", RevocationsMaxVersion()+1)
	if _, err := NewRevocationStoreWithDB(db, pg.DialectPostgres); !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Fatal("ahead schema accepted", err)
	}
	if scalar(t, db, "SELECT exp FROM revocations WHERE token='preserved'") != 9007199254740993 {
		t.Fatal("ahead rejection changed historical row")
	}
}
