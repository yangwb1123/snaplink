package serverbuildsign

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestPostgresSigningIssuerReseedsAfterRebuild(t *testing.T) {
	if os.Getenv("SSO_TEST_POSTGRES_DSN") == "" {
		t.Fatal("owned PostgreSQL fixture required for issuer re-seeding")
	}
	db, err := pg.Open(pg.Config{DSN: pgtest.Schema(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cfg := config.SigningConfig{RevocationBackend: "postgres", KeyFile: filepath.Join(t.TempDir(), "private-key")}
	srv := config.ServerConfig{Issuer: "https://sso.test", TokenTTL: time.Hour}
	first, _, _, err := BuildSigningIssuerWithPostgres(cfg, srv, nil, nil, spi.NopLogger{}, db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	token, err := first.Issue(t.Context(), &core.Subject{ID: "opaque-user", ClientID: "client-a"}, []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Validate(t.Context(), token.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err := first.Revoke(t.Context(), token.AccessToken); err != nil {
		t.Fatal(err)
	}
	second, _, _, err := BuildSigningIssuerWithPostgres(cfg, srv, nil, nil, spi.NopLogger{}, db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Validate(t.Context(), token.AccessToken); err == nil {
		t.Fatal("reconstructed real issuer accepted a durably revoked JWT")
	}
}

func TestPostgresRevocationsMissingPoolNoFallback(t *testing.T) {
	cfg := config.SigningConfig{RevocationBackend: " POSTGRES "}
	store, err := BuildRevocationStoreWithPostgres(cfg, nil, nil, pg.DialectPostgres)
	if err == nil || store != nil {
		t.Fatal("missing pool did not reject with nil store", err)
	}
}
