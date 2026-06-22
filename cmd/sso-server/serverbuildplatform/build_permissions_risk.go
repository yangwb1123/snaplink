package serverbuildplatform

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	"github.com/snaplink/sso/domains/permissions"

	permsqlite "github.com/snaplink/sso/domains/permissions/sqlite"
	postgresbackend "github.com/snaplink/sso/postgres"
)

// BuildPermissionsProvider returns the wired permissions.Provider
// (memory or sqlite per config) seeded with cfg.Permissions.Apps +
// cfg.Permissions.UserRoles. Returns (nil, nil) when permissions
// disabled.
//
// SQLite backend: seed step uses AddRole which returns ErrRoleExists
// on conflict — operators re-running cmd against an already-seeded
// DSN see harmless duplicate-seed warnings rather than wedged
// startup. AssignRoles overwrites (matches the memory peer's SET
// semantics) so re-seeds idempotently re-apply the YAML state.
func BuildPermissionsProvider(cfg *config.Config, logger spi.Logger, pg *sql.DB, dialect postgresbackend.Dialect) (permissions.Provider, error) {
	if !cfg.Permissions.Enabled {
		return nil, nil
	}
	p, err := newPermissionsBackend(cfg, logger, pg, dialect)
	if err != nil {
		return nil, err
	}
	seedPermissions(p, cfg, logger)
	return p, nil
}

func newPermissionsBackend(cfg *config.Config, logger spi.Logger, pg *sql.DB, dialect postgresbackend.Dialect) (permissions.Provider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Permissions.Backend)) {
	case "", "memory":
		logger.Info("permissions provider: memory (single-replica only)")
		return permissions.NewMemoryProvider(), nil
	case "sqlite":
		if cfg.Permissions.SQLite.DSN == "" {
			return nil, errors.New("permissions.sqlite.dsn required when permissions.backend=sqlite")
		}
		sp, err := permsqlite.New(cfg.Permissions.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("permissions sqlite: %w", err)
		}
		logger.Info("permissions provider: sqlite (cluster-shared)", "dsn", cfg.Permissions.SQLite.DSN)
		return sp, nil
	case "postgres":
		if pg == nil {
			return nil, errors.New("permissions.backend=postgres but no postgres block configured (set postgres.dsn)")
		}
		sp, err := postgresbackend.NewPermissionProviderWithDB(pg, dialect)
		if err != nil {
			return nil, fmt.Errorf("permissions postgres: %w", err)
		}
		logger.Info("permissions provider: postgres (cluster-shared)")
		return sp, nil
	default:
		return nil, fmt.Errorf("unknown permissions.backend %q (supported: memory, sqlite, postgres)", cfg.Permissions.Backend)
	}
}

// seedPermissions idempotently loads the YAML-declared roles, menus, and user
// role assignments into the provider. Per-item failures are logged + skipped
// (best-effort seed) so a single bad row doesn't abort boot.
func seedPermissions(p permissions.Provider, cfg *config.Config, logger spi.Logger) {
	ctx := context.Background()
	var seededRoles, seededAssignments int
	for _, app := range cfg.Permissions.Apps {
		seededRoles += seedAppRoles(ctx, p, app, logger)
		if app.Menus != nil {
			if err := p.SetMenus(ctx, app.ClientID, app.Menus); err != nil {
				logger.Error("permissions seed: set menus failed", "client", app.ClientID, "error", err)
			}
		}
	}
	for _, a := range cfg.Permissions.UserRoles {
		if err := p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles); err != nil {
			logger.Error("permissions seed: assign roles failed", "user", a.UserID, "client", a.ClientID, "error", err)
			continue
		}
		seededAssignments++
	}
	logger.Info("permissions seed complete",
		"roles", seededRoles,
		"assignments", seededAssignments)
}

// seedAppRoles seeds one app's roles, falling back to UpdateRole on an existing
// row so re-seeds are idempotent. Returns the count successfully seeded.
func seedAppRoles(ctx context.Context, p permissions.Provider, app config.AppPermissionsConfig, logger spi.Logger) int {
	var seeded int
	for _, role := range app.Roles {
		if err := p.AddRole(ctx, app.ClientID, role); err != nil {
			if errors.Is(err, permissions.ErrRoleExists) {
				// Idempotent re-seed: UpdateRole carries the
				// current permissions list to the existing row.
				if uerr := p.UpdateRole(ctx, app.ClientID, role); uerr != nil {
					logger.Error("permissions seed: role update failed", "client", app.ClientID, "role", role.Code, "error", uerr)
					continue
				}
			} else {
				logger.Error("permissions seed: role add failed", "client", app.ClientID, "role", role.Code, "error", err)
				continue
			}
		}
		seeded++
	}
	return seeded
}

// BuildRiskScorer materializes the reference rule-based
// [defaultimpl.RuleBasedRiskScorer] from RiskConfig. Returns nil
// when risk.enabled=false so cmd skips WithRiskScorer entirely
// (zero overhead on the login path).
//
// Operators with richer risk requirements (impossible-travel,
// device fingerprinting, ML scoring) should fork cmd and call
// sso.WithRiskScorer with their own implementation — the
// RuleBasedRiskScorer is the declarative 80% case, not a
// framework for embedding richer policies.
func BuildRiskScorer(cfg *config.RiskConfig, logger spi.Logger) (spi.RiskScorer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	scorer, err := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList:       cfg.IPDenyList,
		IPAllowList:      cfg.IPAllowList,
		CountryDenyList:  cfg.CountryDenyList,
		CountryAllowList: cfg.CountryAllowList,
		DenyOnGeoMissing: cfg.DenyOnGeoMissing,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("risk scorer enabled (rule-based)",
		"ip_deny", len(cfg.IPDenyList),
		"ip_allow", len(cfg.IPAllowList),
		"country_deny", len(cfg.CountryDenyList),
		"country_allow", len(cfg.CountryAllowList),
		"deny_on_geo_missing", cfg.DenyOnGeoMissing)
	return scorer, nil
}
