package serverbuildstore

import (
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/config"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// BuildReBACOptions materializes the stock ReBAC tuple store and check engine.
// Disabled configuration returns no options, preserving the route surface of
// a server that does not opt into fine-grained authorization.
func BuildReBACOptions(cfg config.ReBACConfig, logger spi.Logger) ([]sso.Option, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	var store rebac.RelationTupleStore
	switch backend {
	case "", "memory":
		store = rebac.NewMemoryStore()
		if logger != nil {
			logger.Info("rebac tuple store", "backend", "memory (single-replica only)")
		}
	case "sqlite":
		if strings.TrimSpace(cfg.SQLite.DSN) == "" {
			return nil, fmt.Errorf("rebac.sqlite.dsn required when rebac.backend=sqlite")
		}
		sqliteStore, err := sqlitestores.NewReBACStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("rebac sqlite: %w", err)
		}
		store = sqliteStore
		if logger != nil {
			logger.Info("rebac tuple store", "backend", "sqlite (cluster-shared)", "dsn", cfg.SQLite.DSN)
		}
	default:
		return nil, fmt.Errorf("unknown rebac.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
	return []sso.Option{
		sso.WithRebacStore(store),
		sso.WithRebacEngine(rebac.NewEngine(store)),
	}, nil
}
