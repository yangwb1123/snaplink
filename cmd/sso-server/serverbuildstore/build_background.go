package serverbuildstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/spi"

	auditsqlite "github.com/snaplink/sso/platform/audit/sqlite"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"

	"github.com/snaplink/sso/platform/metrics"

	"github.com/snaplink/sso/interfaces/snapshot"
)

// BuildCIBA wires the CIBA poll-mode subsystem: the request store
// (memory | sqlite via the migrate framework) + the out-of-band
// challenge transport. The transport reuses the push primitives
// (log | webhook); since root sso cannot import defaultimpl, the
// PushTransport is adapted to oauth.CIBATransport via CIBATransportFunc.
// Returns the typed sqlite handle (or nil) for /readyz + prune wiring.
func BuildCIBA(cfg config.CIBAConfig, logger spi.Logger) (oauth.CIBAStore, oauth.CIBATransport, *sqlitestores.CIBAStore, error) {
	var (
		store       oauth.CIBAStore
		sqliteStore *sqlitestores.CIBAStore
	)
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		store = defaultimpl.NewMemoryCIBAStore()
	case "sqlite":
		if cfg.SQLiteDSN == "" {
			return nil, nil, nil, errors.New("ciba.sqlite_dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewCIBAStore(cfg.SQLiteDSN)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ciba.sqlite: %w", err)
		}
		store = s
		sqliteStore = s
	default:
		return nil, nil, nil, fmt.Errorf("unknown ciba.backend %q (supported: memory, sqlite)", cfg.Backend)
	}

	var pt defaultimpl.PushTransport
	switch strings.ToLower(strings.TrimSpace(cfg.Transport)) {
	case "", "log":
		pt = defaultimpl.PushTransportFunc(func(_ context.Context, id, subject string, _ map[string]string) error {
			logger.Info("ciba challenge delivered (log-only transport — set transport=webhook for real push)",
				"auth_req_id", id, "subject", subject)
			return nil
		})
	case "webhook":
		t, err := BuildPushWebhookTransport(cfg.Webhook)
		if err != nil {
			return nil, nil, nil, err
		}
		pt = t
	default:
		return nil, nil, nil, fmt.Errorf("unknown ciba.transport %q (supported: log, webhook)", cfg.Transport)
	}
	return store, oauth.CIBATransportFunc(pt.Send), sqliteStore, nil
}

// RunCIBAPrune wakes every interval and calls CIBAStore.PruneExpired
// to bound the request table. Same shutdown contract as the audit /
// snapshot / push retention loops: close done on exit, errors logged
// but never tear down the loop, first prune fires after the interval.
func RunCIBAPrune(ctx context.Context, done chan<- struct{}, store *sqlitestores.CIBAStore, interval time.Duration, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := store.PruneExpired(ctx)
			if err != nil {
				logger.Error("ciba requests prune failed", "error", err)
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("ciba").Inc()
				}
				continue
			}
			if deleted > 0 {
				logger.Info("ciba requests pruned", "deleted", deleted)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("ciba").Add(float64(deleted))
				}
			}
		}
	}
}

// RunSnapshotRetention is the background loop cmd launches when
// snapshot.retention.enabled wires it. Same shutdown contract as
// RunAuditRetention (close done channel on exit). First prune
// fires after the first interval, not immediately.
//
// PruneOldest errors don't tear down the loop — a transient
// storage outage shouldn't suspend retention forever; the loop
// logs + waits for the next tick.
func RunSnapshotRetention(ctx context.Context, done chan<- struct{}, storage snapshot.Storage, interval time.Duration, keep int, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := snapshot.PruneOldest(ctx, storage, keep)
			if err != nil {
				logger.Error("snapshot retention prune failed", "error", err, "keep", keep)
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("snapshot").Inc()
				}
				continue
			}
			if len(deleted) > 0 {
				logger.Info("snapshot retention pruned envelopes",
					"deleted_count", len(deleted), "keep", keep)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("snapshot").Add(float64(len(deleted)))
				}
			}
		}
	}
}

// RunAuditRetention is the background loop cmd launches when
// audit.retention.enabled wires it. Wakes every interval (after
// the first interval — not at start so short-lived deploys don't
// trigger expensive bulk deletes during boot), calls
// auditsqlite.Sink.Prune(ctx, now-maxAge), logs the result.
//
// Exits on ctx cancellation (cmd shutdown). Closes done channel
// on exit so cmd's Shutdown can bound the wait.
//
// Prune errors are logged but don't stop the loop — a transient
// SQLite contention shouldn't tear down retention forever.
func RunAuditRetention(ctx context.Context, done chan<- struct{}, sink *auditsqlite.Sink, interval, maxAge time.Duration, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-maxAge)
			deleted, err := sink.Prune(ctx, cutoff)
			if err != nil {
				logger.Error("audit retention prune failed", "error", err, "cutoff", cutoff)
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("audit").Inc()
				}
				continue
			}
			if deleted > 0 {
				logger.Info("audit retention pruned events",
					"deleted", deleted, "cutoff", cutoff)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("audit").Add(float64(deleted))
				}
			}
		}
	}
}
