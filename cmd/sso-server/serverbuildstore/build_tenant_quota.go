package serverbuildstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	postgrestore "github.com/yangwb1123/snaplink/infrastructure/postgres/tenantquota"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// DefaultTenantQuotaCleanupInterval bounds stale rolling-window retention when
// the operator leaves tenant.resource_quota.cleanup_interval unset.
const DefaultTenantQuotaCleanupInterval = time.Minute

const tenantQuotaReconcileAttempts = 16

// TenantQuotaRuntime owns the configured store and its optional cleanup loop.
// The shared PostgreSQL pool remains owned by app and is not closed here.
type TenantQuotaRuntime struct {
	Store    core.TenantQuotaStore
	interval time.Duration
	cancel   context.CancelFunc
	done     <-chan struct{}
}

// BuildTenantQuotaRuntime selects a quota backend and installs static limit
// seeds. Empty/disabled returns nil so the stock binary stays byte-compatible.
func BuildTenantQuotaRuntime(ctx context.Context, cfg config.TenantResourceQuotaConfig, pg *sql.DB, dialect postgresbackend.Dialect, clients core.ClientStore) (*TenantQuotaRuntime, error) {
	store, err := buildTenantQuotaStore(cfg.Backend, pg, dialect)
	if err != nil || store == nil {
		return nil, err
	}
	if err := seedTenantQuotas(store, cfg.Limits); err != nil {
		return nil, err
	}
	if err := ReconcileTenantClientUsage(ctx, store, clients, cfg.Limits); err != nil {
		return nil, err
	}
	return &TenantQuotaRuntime{Store: store, interval: cfg.CleanupInterval}, nil
}

func buildTenantQuotaStore(backend string, pg *sql.DB, dialect postgresbackend.Dialect) (core.TenantQuotaStore, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "disabled":
		return nil, nil
	case "memory":
		return memorystoreidentity.NewMemoryTenantQuotaStore(), nil
	case "postgres":
		if pg == nil {
			return nil, errors.New("tenant resource quota postgres backend requires the shared postgres pool")
		}
		return postgrestore.NewWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown tenant.resource_quota.backend %q", backend)
	}
}

func seedTenantQuotas(store core.TenantQuotaStore, seeds []config.TenantQuotaSeedConfig) error {
	ctx := context.Background()
	for _, seed := range seeds {
		quota := &core.TenantQuota{MaxClients: seed.MaxClients, MaxUsers: seed.MaxUsers,
			MaxSessions: seed.MaxSessions, MaxTokenRate: seed.MaxTokenRate}
		if err := store.SetQuota(ctx, seed.TenantID, quota); err != nil {
			return fmt.Errorf("seed tenant resource quota %q: %w", seed.TenantID, err)
		}
	}
	return nil
}

// ReconcileTenantClientUsage seeds an exact client count for every configured
// tenant. The generation read happens before ClientStore.List; a concurrent
// DCR/admin mutation advances that generation and makes the CAS fail, so the
// scan is retried instead of overwriting live usage.
func ReconcileTenantClientUsage(ctx context.Context, quotas core.TenantQuotaStore, clients core.ClientStore, seeds []config.TenantQuotaSeedConfig) error {
	if quotas == nil || len(seeds) == 0 {
		return nil
	}
	resources, ok := quotas.(core.TenantQuotaResourceStore)
	if !ok || clients == nil {
		return errors.New("tenant client quota reconciliation requires resource leases and a client store")
	}
	seen := make(map[string]struct{}, len(seeds))
	for _, seed := range seeds {
		if _, duplicate := seen[seed.TenantID]; duplicate {
			continue
		}
		seen[seed.TenantID] = struct{}{}
		if err := reconcileTenantClients(ctx, resources, clients, seed.TenantID); err != nil {
			return fmt.Errorf("reconcile tenant client quota %q: %w", seed.TenantID, err)
		}
	}
	return nil
}

func reconcileTenantClients(ctx context.Context, quotas core.TenantQuotaResourceStore, clients core.ClientStore, tenantID string) error {
	for range tenantQuotaReconcileAttempts {
		usage, err := quotas.GetResourceUsage(ctx, tenantID, core.ResourceClients)
		if err != nil {
			return err
		}
		all, err := clients.List(ctx)
		if err != nil {
			return err
		}
		_, err = quotas.ReconcileUsage(ctx, tenantID, core.ResourceClients,
			countTenantClients(all, tenantID), usage.Generation)
		if !errors.Is(err, core.ErrQuotaRevisionConflict) {
			return err
		}
	}
	return core.ErrQuotaRevisionConflict
}

func countTenantClients(clients []*core.Client, tenantID string) int {
	count := 0
	for _, client := range clients {
		if client != nil && client.TenantID == tenantID {
			count++
		}
	}
	return count
}

// Start launches cleanup after the server has completed all fallible startup
// work, avoiding a leaked goroutine when assembly later fails.
func (r *TenantQuotaRuntime) Start(logger spi.Logger) {
	if r == nil || r.Store == nil || r.cancel != nil {
		return
	}
	cleaner, ok := r.Store.(core.TenantQuotaWindowCleaner)
	if !ok {
		return
	}
	interval := r.interval
	if interval <= 0 {
		interval = DefaultTenantQuotaCleanupInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.cancel, r.done = cancel, done
	go runTenantQuotaCleanup(ctx, done, cleaner, interval, logger)
}

func runTenantQuotaCleanup(ctx context.Context, done chan<- struct{}, cleaner core.TenantQuotaWindowCleaner, interval time.Duration, logger spi.Logger) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			if _, err := cleaner.CleanupTokenRateWindows(ctx, now); err != nil && ctx.Err() == nil {
				logger.Error("tenant quota token-window cleanup failed", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// Stop cancels the cleanup loop and reports whether it drained before ctx.
func (r *TenantQuotaRuntime) Stop(ctx context.Context) bool {
	if r == nil || r.cancel == nil {
		return true
	}
	r.cancel()
	select {
	case <-r.done:
		return true
	case <-ctx.Done():
		return false
	}
}
