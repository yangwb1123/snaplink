package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// testDSN returns the Postgres/CockroachDB DSN for integration tests, or skips.
// Set SSO_TEST_POSTGRES_DSN (e.g. postgres://user@localhost:5432/sso_test?sslmode=disable)
// to run these against a real database; CI without a DB skips them.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres integration test")
	}
	return dsn
}

func testConfig(t *testing.T) Config {
	d := Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT")) // "" => postgres
	return Config{DSN: testDSN(t), Dialect: d}
}

func TestMigrate_RunIdempotentAndVersioned(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	// Fresh start for this namespace.
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS consent_grants, schema_migrations_consent"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if v, err := CurrentVersion(ctx, db, "consent"); err != nil || v != 0 {
		t.Fatalf("fresh CurrentVersion = (%d, %v), want (0, nil)", v, err)
	}
	if err := Run(ctx, db, "consent", consentMigrations, cfg.Dialect); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if v, err := CurrentVersion(ctx, db, "consent"); err != nil || v != 1 {
		t.Fatalf("after Run CurrentVersion = (%d, %v), want (1, nil)", v, err)
	}
	// Idempotent: a second Run with the same set is a no-op.
	if err := Run(ctx, db, "consent", consentMigrations, cfg.Dialect); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	// CheckSchema: live (1) ahead of binaryMax (0) must error; equal is fine.
	if err := CheckSchema(ctx, db, "consent", 0); err == nil {
		t.Error("CheckSchema must reject a DB schema ahead of the binary")
	}
	if err := CheckSchema(ctx, db, "consent", 1); err != nil {
		t.Errorf("CheckSchema at matching version must pass, got %v", err)
	}
}

func freshConsentStore(t *testing.T) *ConsentStore {
	t.Helper()
	s, err := NewConsentStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewConsentStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE consent_grants"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestConsent_RecordGetRevoke(t *testing.T) {
	t.Parallel()
	s := freshConsentStore(t)
	ctx := context.Background()

	// Missing → ErrNoConsentGrant.
	if _, err := s.GetConsent(ctx, "u1", "c1"); err != core.ErrNoConsentGrant {
		t.Fatalf("missing GetConsent err = %v, want ErrNoConsentGrant", err)
	}

	grant := core.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"openid", "profile"}, GrantedAt: time.Now().UTC()}
	if err := s.RecordConsent(ctx, grant); err != nil {
		t.Fatalf("RecordConsent: %v", err)
	}
	got, err := s.GetConsent(ctx, "u1", "c1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "openid" {
		t.Fatalf("scopes round-trip = %v", got.Scopes)
	}
	if got.GrantedAt.UnixNano() != grant.GrantedAt.UnixNano() {
		t.Fatalf("granted_at nanosecond round-trip lost: got %d want %d", got.GrantedAt.UnixNano(), grant.GrantedAt.UnixNano())
	}

	// Upsert: re-record with new scopes replaces in full.
	grant.Scopes = []string{"openid"}
	if err := s.RecordConsent(ctx, grant); err != nil {
		t.Fatalf("re-RecordConsent: %v", err)
	}
	got, _ = s.GetConsent(ctx, "u1", "c1")
	if len(got.Scopes) != 1 {
		t.Fatalf("upsert did not replace scopes: %v", got.Scopes)
	}

	// Revoke is idempotent.
	if err := s.RevokeConsent(ctx, "u1", "c1"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if err := s.RevokeConsent(ctx, "u1", "c1"); err != nil {
		t.Fatalf("RevokeConsent (idempotent): %v", err)
	}
	if _, err := s.GetConsent(ctx, "u1", "c1"); err != core.ErrNoConsentGrant {
		t.Fatalf("after revoke GetConsent err = %v, want ErrNoConsentGrant", err)
	}
}

func TestConsent_ListByUserDescending(t *testing.T) {
	t.Parallel()
	s := freshConsentStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	// Insert out of order; ListByUser must return newest-first.
	for i, cid := range []string{"c-old", "c-mid", "c-new"} {
		g := core.ConsentGrant{UserID: "u1", ClientID: cid, Scopes: []string{"openid"}, GrantedAt: base.Add(time.Duration(i) * time.Hour)}
		if err := s.RecordConsent(ctx, g); err != nil {
			t.Fatalf("RecordConsent %s: %v", cid, err)
		}
	}
	// A grant for a different user must not leak.
	if err := s.RecordConsent(ctx, core.ConsentGrant{UserID: "u2", ClientID: "c-x", Scopes: []string{"openid"}, GrantedAt: base}); err != nil {
		t.Fatalf("RecordConsent u2: %v", err)
	}

	list, err := s.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListByUser len = %d, want 3 (no cross-user leak)", len(list))
	}
	if list[0].ClientID != "c-new" || list[2].ClientID != "c-old" {
		t.Fatalf("ListByUser order = [%s..%s], want newest-first", list[0].ClientID, list[2].ClientID)
	}

	// Unknown user → empty slice, not error.
	empty, err := s.ListByUser(ctx, "nobody")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("ListByUser(unknown) = (%v, %v), want (empty non-nil, nil)", empty, err)
	}
}
