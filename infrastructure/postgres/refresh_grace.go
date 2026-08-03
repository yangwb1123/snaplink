package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
)

// refreshGraceSchema is the refresh-rotation grace cache: one row per
// consumed token (hashed), storing the successor response as BYTEA (the
// SQLite peer's BLOB shape), keyed by the hex-encoded SHA-256 of the consumed
// token string. The expires_at index enables efficient periodic pruning of
// expired rows.
const refreshGraceSchema = `
CREATE TABLE IF NOT EXISTS refresh_grace_cache (
    consumed_token_hash TEXT PRIMARY KEY,
    successor_response  BYTEA,
    expires_at          BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_grace_cache_expires_at
    ON refresh_grace_cache(expires_at);
`

var refreshGraceMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: refreshGraceSchema},
}

// refreshGraceDefaultCleanupInterval is the default interval between periodic
// expired-row purges when the caller passes 0 for cleanupInterval.
const refreshGraceDefaultCleanupInterval = 5 * time.Minute

// RefreshGraceStore is the Postgres-backed, cluster-shared double-submit grace
// store. It structurally satisfies tokengrant.RefreshGraceStore (same method
// set) WITHOUT importing the handler layer, so the dependency direction stays
// downward, matching the Redis peer.
//
// Lookup is a non-destructive SELECT: every presentation of a just-rotated-
// away token within the grace window replays the SAME cached successor
// (idempotent). A miss (expired, never remembered, or a genuine post-window
// replay) falls through to family-reuse detection (BCP §4.13) — Lookup
// returns false on ANY uncertainty, so the fail-closed contract is never
// weakened.
type RefreshGraceStore struct {
	db     *sql.DB
	window time.Duration
	cancel context.CancelFunc
	done   chan struct{}
}

// NewRefreshGraceStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments), runs the refresh_grace namespace migrations, and starts the
// background cleanup goroutine with the given window duration as TTL.
// cleanupInterval <= 0 uses the default (5 min). The caller owns the pool —
// Close() does NOT close the DB.
func NewRefreshGraceStoreWithDB(db *sql.DB, dialect Dialect, window, cleanupInterval time.Duration) (*RefreshGraceStore, error) {
	if db == nil {
		return nil, errors.New("postgres: refresh grace store: nil db")
	}
	if err := Run(context.Background(), db, "refresh_grace", refreshGraceMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate refresh_grace: %w", err)
	}
	if cleanupInterval <= 0 {
		cleanupInterval = refreshGraceDefaultCleanupInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &RefreshGraceStore{
		db:     db,
		window: window,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go s.cleanupLoop(ctx, cleanupInterval)
	return s, nil
}

// cleanupLoop periodically purges expired rows from the cache. Runs until ctx
// is cancelled (i.e. Close is called). Errors are swallowed — the purge is
// best-effort and the next tick retries.
func (s *RefreshGraceStore) cleanupLoop(ctx context.Context, interval time.Duration) {
	defer close(s.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.db.ExecContext(ctx,
				`DELETE FROM refresh_grace_cache WHERE expires_at <= $1`,
				time.Now().UnixNano())
		}
	}
}

// Close stops the background cleanup goroutine. The shared pool is owned by
// the caller. Idempotent.
func (s *RefreshGraceStore) Close() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done
	}
	s.db = nil
	return nil
}

// CleanupStop returns the context cancel func that stops the background
// cleanup goroutine. Used during process shutdown.
func (s *RefreshGraceStore) CleanupStop() context.CancelFunc {
	if s == nil {
		return nil
	}
	return s.cancel
}

// CleanupDone returns the channel that closes when the cleanup goroutine
// exits. Used during process shutdown.
func (s *RefreshGraceStore) CleanupDone() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

// Ping reports connection health for /readyz wiring.
func (s *RefreshGraceStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: refresh grace store closed")
	}
	return s.db.PingContext(ctx)
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *RefreshGraceStore) DB() *sql.DB { return s.db }

// PruneExpired deletes every entry whose expires_at has passed. Exported for
// the background cleanup loop and for operator-facing admin endpoints.
func (s *RefreshGraceStore) PruneExpired(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres: refresh grace store closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_grace_cache WHERE expires_at <= $1`,
		time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("postgres: prune refresh_grace_cache: %w", err)
	}
	return res.RowsAffected()
}

// refreshGraceHash computes a hex-encoded SHA-256 hash of the consumed token.
// Using a fixed-size hash as the primary key avoids issues with long tokens
// and provides a stable, efficient index. One-way: the cache stores only the
// hash, never the secret.
func refreshGraceHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// -- tokengrant.RefreshGraceStore interface (structural typing) --

// Remember caches resp as the successor for the just-consumed token. The
// response is JSON-marshalled and stored with an expiry of now+window.
// ON CONFLICT DO UPDATE makes it idempotent — a concurrent duplicate call
// silently overwrites with the same successor. Best-effort: marshal/DB errors
// degrade to strict single-use (the double-submit then trips family-reuse
// detection). A best-effort lazy GC runs before the insert to keep the table
// bounded by the active-window key count, matching the SQLite peer.
func (s *RefreshGraceStore) Remember(token string, resp map[string]any, now time.Time) {
	if s == nil || s.db == nil || token == "" || s.window <= 0 {
		return
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		return
	}
	hash := refreshGraceHash(token)
	expiresAt := now.Add(s.window).UnixNano()
	ctx := context.Background()
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM refresh_grace_cache WHERE expires_at <= $1`, now.UnixNano())
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO refresh_grace_cache (consumed_token_hash, successor_response, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (consumed_token_hash) DO UPDATE
            SET successor_response = excluded.successor_response,
                expires_at = excluded.expires_at`,
		hash, blob, expiresAt)
}

// Lookup returns the cached successor for token if it was rotated within the
// grace window, or (nil, false) on ANY uncertainty — miss, expiry, backend
// error, or decode failure. The row is NOT deleted on fetch: Lookup MUST be
// idempotently replayable for every presentation within the window (a
// multi-tab SPA retry storm presents the same token more than twice inside
// one window; every presentation must replay the identical cached successor
// instead of tripping a self-inflicted family kill). Expired/never-remembered
// rows are pruned by the background cleanupLoop and Remember's lazy GC, not
// by Lookup.
func (s *RefreshGraceStore) Lookup(token string, now time.Time) (map[string]any, bool) {
	if s == nil || s.db == nil || token == "" {
		return nil, false
	}
	hash := refreshGraceHash(token)
	var blob []byte
	var expiresAt int64
	err := s.db.QueryRowContext(context.Background(),
		`SELECT successor_response, expires_at FROM refresh_grace_cache WHERE consumed_token_hash = $1`,
		hash).Scan(&blob, &expiresAt)
	if err != nil {
		// sql.ErrNoRows or any other error — all fall through to reuse detection
		return nil, false
	}
	// Expiry check: expired-at-exactly-now is treated as expired.
	if !now.Before(time.Unix(0, expiresAt)) {
		return nil, false
	}
	var resp map[string]any
	if err := json.Unmarshal(blob, &resp); err != nil {
		return nil, false
	}
	return resp, true
}

// RefreshGraceMaxVersion returns the highest migration version declared for
// the refresh_grace namespace — the boot-gate input for the postgres branch.
func RefreshGraceMaxVersion() int { return migrate.MaxVersion(refreshGraceMigrations) }

// Compile-time interface check (structural).
var _ interface {
	Remember(string, map[string]any, time.Time)
	Lookup(string, time.Time) (map[string]any, bool)
} = (*RefreshGraceStore)(nil)
