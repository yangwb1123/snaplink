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
	redisbackend "github.com/snaplink/sso/infrastructure/redis"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/platform/metrics"

	"github.com/snaplink/sso/interfaces/snapshot"
)

// BuildCIBA wires the CIBA poll-mode subsystem: the request store
// (memory | sqlite via the migrate framework) + the out-of-band
// challenge transport. The transport reuses the push primitives
// (log | webhook); since root sso cannot import defaultimpl, the
// PushTransport is adapted to oauth.CIBATransport via CIBATransportFunc.
// Returns the typed sqlite handle (or nil) for /readyz + prune wiring.
func BuildCIBA(cfg config.CIBAConfig, logger spi.Logger, rdb goredis.Cmdable) (oauth.CIBAStore, oauth.CIBATransport, *sqlitestores.CIBAStore, error) {
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
	case "redis":
		if rdb == nil {
			return nil, nil, nil, errRedisNotConfigured("ciba")
		}
		store = redisbackend.NewCIBAStore(rdb)
	default:
		return nil, nil, nil, fmt.Errorf("unknown ciba.backend %q (supported: memory, sqlite, redis)", cfg.Backend)
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

// BuildCIBAPushDeadLetter wires the CIBA Core §10.3 push dead-letter store
// that records failed push deliveries for operator replay. It reuses the
// PARENT CIBAConfig's Backend/SQLiteDSN (memory | sqlite) rather than a
// separate config knob — a push failure is a sub-concern of the same CIBA
// storage backend, not something an operator tunes independently. Returns
// the typed sqlite handle (or nil) for schema-check + readiness wiring,
// mirroring BuildCIBA's contract. redis has no dedicated dead-letter
// backend yet, so it falls back to memory (deliveries are retried by the
// notifier itself before ever reaching the dead letter — the store's only
// job is operator visibility into rare persistent failures).
func BuildCIBAPushDeadLetter(cfg config.CIBAConfig) (oauth.CIBAPushDeadLetterStore, *sqlitestores.CIBAPushDeadLetterStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "sqlite":
		if cfg.SQLiteDSN == "" {
			return nil, nil, errors.New("ciba.sqlite_dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewCIBAPushDeadLetterStore(cfg.SQLiteDSN)
		if err != nil {
			return nil, nil, fmt.Errorf("ciba.push deadletter sqlite: %w", err)
		}
		return s, s, nil
	default:
		return defaultimpl.NewMemoryCIBAPushDeadLetterStore(0), nil, nil
	}
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
			pruneCIBASafe(ctx, store, logger, m)
		}
	}
}

// pruneCIBASafe wraps one CIBAStore.PruneExpired call in recover(). The store
// is a config-selected Store implementation (§SPI + Storage, AGENTS.md §3)
// invoked from a PERMANENT background goroutine with no per-request caller to
// isolate a fault — an unrecovered panic here would not just skip one prune
// tick, it would crash the whole process and take every other in-flight
// request down with it. Mirrors tokenanomaly.Detector.processFindingSafe /
// tokenusage.Recorder.recordSafe's rationale for the identical shape.
func pruneCIBASafe(ctx context.Context, store *sqlitestores.CIBAStore, logger spi.Logger, m *metrics.Metrics) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("ciba requests prune panic recovered", "panic", rec)
		}
	}()
	deleted, err := store.PruneExpired(ctx)
	if err != nil {
		logger.Error("ciba requests prune failed", "error", err)
		if m != nil {
			m.RetentionPruneErrorTotal.WithLabelValues("ciba").Inc()
		}
		return
	}
	if deleted > 0 {
		logger.Info("ciba requests pruned", "deleted", deleted)
		if m != nil {
			m.RetentionPrunedTotal.WithLabelValues("ciba").Add(float64(deleted))
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
			pruneSnapshotSafe(ctx, storage, keep, logger, m)
		}
	}
}

// pruneSnapshotSafe wraps one snapshot.PruneOldest call in recover(). storage
// is the operator-selected snapshot.Storage implementation (an SPI a forked
// binary can supply its own backend for — file/inline are only the built-in
// choices) invoked from a PERMANENT background goroutine — an unrecovered
// panic here would crash the whole process, not just this retention tick.
// Same rationale as pruneCIBASafe above.
func pruneSnapshotSafe(ctx context.Context, storage snapshot.Storage, keep int, logger spi.Logger, m *metrics.Metrics) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("snapshot retention prune panic recovered", "panic", rec, "keep", keep)
		}
	}()
	deleted, err := snapshot.PruneOldest(ctx, storage, keep)
	if err != nil {
		logger.Error("snapshot retention prune failed", "error", err, "keep", keep)
		if m != nil {
			m.RetentionPruneErrorTotal.WithLabelValues("snapshot").Inc()
		}
		return
	}
	if len(deleted) > 0 {
		logger.Info("snapshot retention pruned envelopes",
			"deleted_count", len(deleted), "keep", keep)
		if m != nil {
			m.RetentionPrunedTotal.WithLabelValues("snapshot").Add(float64(len(deleted)))
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
			pruneAuditSafe(ctx, sink, maxAge, logger, m)
		}
	}
}

// pruneAuditSafe wraps one auditsqlite.Sink.Prune call in recover(), invoked
// from a PERMANENT background goroutine — an unrecovered panic here would
// crash the whole process, not just this retention tick. Same rationale as
// pruneCIBASafe above.
func pruneAuditSafe(ctx context.Context, sink *auditsqlite.Sink, maxAge time.Duration, logger spi.Logger, m *metrics.Metrics) {
	cutoff := time.Now().Add(-maxAge)
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("audit retention prune panic recovered", "panic", rec, "cutoff", cutoff)
		}
	}()
	deleted, err := sink.Prune(ctx, cutoff)
	if err != nil {
		logger.Error("audit retention prune failed", "error", err, "cutoff", cutoff)
		if m != nil {
			m.RetentionPruneErrorTotal.WithLabelValues("audit").Inc()
		}
		return
	}
	if deleted > 0 {
		logger.Info("audit retention pruned events",
			"deleted", deleted, "cutoff", cutoff)
		if m != nil {
			m.RetentionPrunedTotal.WithLabelValues("audit").Add(float64(deleted))
		}
	}
}
