package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	_ "modernc.org/sqlite"
)

// rateLimitBucketSchema persists per-key token-bucket state.
//
// Composite PK on (bucket_name, key) lets multiple SQLiteLimiter
// instances (one per Policy prefix rule) share a single DB file
// without colliding — operators with three prefix rules can either
// pass three distinct dsn paths (table-per-rule) or pass one dsn
// + three distinct bucket_name strings (rows-per-rule). The
// bucket_name defaults to "" for single-Limiter deployments.
const rateLimitBucketSchema = `
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_name        TEXT    NOT NULL,
    key                TEXT    NOT NULL,
    tokens             REAL    NOT NULL,
    last_refill_at_ns  INTEGER NOT NULL,
    last_seen_at_ns    INTEGER NOT NULL,
    PRIMARY KEY (bucket_name, key)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_last_seen
    ON rate_limit_buckets(last_seen_at_ns);
`

// SQLiteLimiter is the SQLite-backed [Limiter] for multi-replica
// deployments. Token-bucket state is persisted so a request that
// drained the bucket on replica A is visible to replica B before
// it grants the next request — the cross-replica defense memory-
// backed MemoryLimiter cannot give.
//
// Cost: every Allow runs a BEGIN IMMEDIATE transaction + read-
// modify-write + commit. SQLite's WAL mode delivers low-thousands
// writes/sec on a typical SSD — comfortable for SSO server brute-
// force protection (hundreds of login attempts/sec). For higher
// load (auth-heavy multi-tenant SaaS) operators should plug a
// Redis-backed Limiter via sso.WithRateLimit directly.
//
// The bucket is sized by (perSecond, burst) at construction; both
// are immutable across the limiter's lifetime to match the
// MemoryLimiter contract.
type SQLiteLimiter struct {
	perSecond  float64
	burst      int
	bucketName string

	stalePruneAfter time.Duration

	db *sql.DB
}

// NewSQLiteLimiter opens dsn, migrates the schema, and returns the
// limiter. bucketName is the per-policy scope (use "" for a single-
// Limiter deployment; distinct names when multiple Limiters share
// the same DSN).
func NewSQLiteLimiter(dsn string, perSecond float64, burst int, bucketName string) (*SQLiteLimiter, error) {
	if burst < 1 {
		burst = 1
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), rateLimitBucketSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate rate_limit_buckets: %w", err)
	}
	return &SQLiteLimiter{
		perSecond:       perSecond,
		burst:           burst,
		bucketName:      bucketName,
		stalePruneAfter: defaultStalePruneAfter,
		db:              db,
	}, nil
}

// NewSQLiteLimiterWithDB wraps an existing *sql.DB (shared-pool
// deployments — pass the same *sql.DB to multiple Limiters with
// distinct bucket names).
func NewSQLiteLimiterWithDB(db *sql.DB, perSecond float64, burst int, bucketName string) (*SQLiteLimiter, error) {
	if burst < 1 {
		burst = 1
	}
	if _, err := db.ExecContext(context.Background(), rateLimitBucketSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate rate_limit_buckets: %w", err)
	}
	return &SQLiteLimiter{
		perSecond:       perSecond,
		burst:           burst,
		bucketName:      bucketName,
		stalePruneAfter: defaultStalePruneAfter,
		db:              db,
	}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SQLiteLimiter) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Allow implements [Limiter]. Fails open on any SQL error — the
// rate limiter is a defense layer, not a correctness layer, and
// 503-ing during a DB partition would block real users while
// adding zero security value (the underlying authenticator still
// gates credentials).
func (s *SQLiteLimiter) Allow(key string) (bool, time.Duration) {
	ctx := context.Background()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return true, 0
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	nowNs := now.UnixNano()

	var (
		tokens       float64
		lastRefillNs int64
	)
	err = tx.QueryRowContext(ctx, `
        SELECT tokens, last_refill_at_ns
          FROM rate_limit_buckets
         WHERE bucket_name = ? AND key = ?`,
		s.bucketName, key,
	).Scan(&tokens, &lastRefillNs)
	if errors.Is(err, sql.ErrNoRows) {
		// First-ever request for this key — bucket starts full.
		tokens = float64(s.burst)
		lastRefillNs = nowNs
	} else if err != nil {
		return true, 0
	}

	// Refill: elapsed time × perSecond, capped at burst.
	elapsedSec := float64(nowNs-lastRefillNs) / float64(time.Second)
	if elapsedSec > 0 {
		tokens = math.Min(float64(s.burst), tokens+elapsedSec*s.perSecond)
	}

	var (
		allowed    bool
		retryAfter time.Duration
	)
	if tokens >= 1.0 {
		tokens -= 1.0
		allowed = true
	} else if s.perSecond <= 0 {
		// Limiter configured to deny everything; no useful retry-after.
		return false, 0
	} else {
		needed := 1.0 - tokens
		retryAfter = time.Duration(needed / s.perSecond * float64(time.Second))
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO rate_limit_buckets (bucket_name, key, tokens, last_refill_at_ns, last_seen_at_ns)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (bucket_name, key) DO UPDATE SET
            tokens = excluded.tokens,
            last_refill_at_ns = excluded.last_refill_at_ns,
            last_seen_at_ns = excluded.last_seen_at_ns`,
		s.bucketName, key, tokens, nowNs, nowNs,
	); err != nil {
		return true, 0
	}

	// Opportunistic stale prune — cheap because of the last_seen index.
	// Skip when the table is small enough that pruning isn't worth the
	// extra round-trip (1 in 64 calls is a balance between memory
	// pressure and per-request cost).
	if (nowNs/int64(time.Millisecond))%64 == 0 {
		_, _ = tx.ExecContext(ctx, `DELETE FROM rate_limit_buckets WHERE last_seen_at_ns < ?`,
			nowNs-s.stalePruneAfter.Nanoseconds())
	}

	if err := tx.Commit(); err != nil {
		return true, 0
	}
	return allowed, retryAfter
}

var _ Limiter = (*SQLiteLimiter)(nil)
