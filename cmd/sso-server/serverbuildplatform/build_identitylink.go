package serverbuildplatform

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/identitylink"
	identitylinkmemory "github.com/yangwb1123/snaplink/domains/identitylink/memory"
	identitylinksqlite "github.com/yangwb1123/snaplink/domains/identitylink/sqlite"
	identitylinkpostgres "github.com/yangwb1123/snaplink/infrastructure/identitylinkpostgres"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

// BuildIdentityLink builds the identitylink.Store (+ optional MergePolicy)
// backing sso.WithIdentityLinkStore / sso.WithIdentityMergePolicy when
// self_service.identity_link.enabled — the self-service GET/DELETE
// /me/identities surface.
//
// The returned MergePolicy is nil for merge_policy "" / "reject" — the
// package's own safe default (identitylink.Resolve already treats a nil
// policy as identitylink.RejectPolicy{}), so the caller should only append
// sso.WithIdentityMergePolicy when it is non-nil, keeping an unset/"reject"
// config byte-identical to never wiring the option at all. "link_only"
// returns identitylink.NewLinkOnlyMergePolicy bound to the SAME store.
//
// Returns (nil, nil, nil) when disabled — byte-identical to a build without
// the feature. An unrecognized merge_policy value fails loud at boot rather
// than silently falling back to the safe default.
func BuildIdentityLink(cfg config.IdentityLinkConfig) (identitylink.Store, identitylink.MergePolicy, error) {
	return BuildIdentityLinkDurable(cfg, nil, "")
}

// BuildIdentityLinkDurable additionally accepts the process-wide Postgres
// pool used when backend=postgres.
func BuildIdentityLinkDurable(cfg config.IdentityLinkConfig, pg *sql.DB, dialect postgresbackend.Dialect) (identitylink.Store, identitylink.MergePolicy, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	mergePolicy := strings.ToLower(strings.TrimSpace(cfg.MergePolicy))
	if mergePolicy != "" && mergePolicy != "reject" && mergePolicy != "link_only" {
		return nil, nil, fmt.Errorf("self_service.identity_link.merge_policy %q invalid (\"\", \"reject\", or \"link_only\")", cfg.MergePolicy)
	}
	store, err := buildIdentityLinkStore(cfg, pg, dialect)
	if err != nil {
		return nil, nil, err
	}
	switch mergePolicy {
	case "", "reject":
		return store, nil, nil
	case "link_only":
		return store, identitylink.NewLinkOnlyMergePolicy(store), nil
	}
	return nil, nil, fmt.Errorf("self_service.identity_link.merge_policy changed during build")
}

func buildIdentityLinkStore(cfg config.IdentityLinkConfig, pg *sql.DB, dialect postgresbackend.Dialect) (identitylink.Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return identitylinkmemory.New(), nil
	case "sqlite":
		if strings.TrimSpace(cfg.SQLite.DSN) == "" {
			return nil, fmt.Errorf("self_service.identity_link.sqlite.dsn is required")
		}
		return identitylinksqlite.New(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, fmt.Errorf("self_service.identity_link backend postgres requires postgres.dsn")
		}
		return identitylinkpostgres.NewWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("self_service.identity_link.backend %q invalid (memory, sqlite, or postgres)", cfg.Backend)
	}
}
