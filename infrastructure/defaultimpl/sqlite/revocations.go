package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/migrate"
)

// revocationSchema is the v1 baseline for the access-token revocation deny-set:
// one row per revoked token, keyed by the full token string, valued by its
// `exp` (unix seconds). A row is only needed until exp passes (the token is
// rejected on expiry anyway), so the store prunes lazily. Backs
// defaultimpl.RevocationStore so a revocation survives a process restart /
// rolling deploy — on boot each replica re-seeds its in-process deny-set from
// here (defaultimpl issuer SeedRevocations).
const revocationSchema = `
CREATE TABLE IF NOT EXISTS revocations (
    token TEXT    PRIMARY KEY,
    exp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_exp ON revocations(exp);
`

var revocationMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: revocationSchema},
}

// RevocationStore is the SQLite-backed defaultimpl.RevocationStore. On a SHARED
// database it is a multi-replica durable deny-set: every replica re-seeds its
// in-process map from here at boot, so a token revoked before a restart stays
// revoked. (Live cross-replica propagation is the separate cluster bus; this
// closes the orthogonal restart/late-join gap.)
type RevocationStore struct {
	db *sql.DB
}

// NewRevocationStore opens dsn, migrates, and returns the store.
func NewRevocationStore(dsn string) (*RevocationStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "revocations", revocationMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate revocations: %w", err)
	}
	return &RevocationStore{db: db}, nil
}

// NewRevocationStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewRevocationStoreWithDB(db *sql.DB) *RevocationStore {
	_ = migrate.Run(context.Background(), db, "revocations", revocationMigrations)
	return &RevocationStore{db: db}
}

// Close releases the connection. Idempotent.
func (s *RevocationStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *RevocationStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *RevocationStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: revocation store closed")
	}
	return s.db.PingContext(ctx)
}

// Revoke records token revoked until expUnix (idempotent upsert).
func (s *RevocationStore) Revoke(ctx context.Context, token string, expUnix int64) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO revocations (token, exp) VALUES (?, ?)
		 ON CONFLICT(token) DO UPDATE SET exp = excluded.exp`,
		token, expUnix); err != nil {
		return fmt.Errorf("sqlite: insert revocation: %w", err)
	}
	return nil
}

// Load returns every still-valid revocation (exp >= now), pruning expired rows
// first so the table + the returned map stay bounded.
func (s *RevocationStore) Load(ctx context.Context) (map[string]int64, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM revocations WHERE exp < ?`, now); err != nil {
		return nil, fmt.Errorf("sqlite: prune revocations: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT token, exp FROM revocations WHERE exp >= ?`, now)
	if err != nil {
		return nil, fmt.Errorf("sqlite: load revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]int64)
	for rows.Next() {
		var token string
		var exp int64
		if err := rows.Scan(&token, &exp); err != nil {
			return nil, fmt.Errorf("sqlite: scan revocation: %w", err)
		}
		out[token] = exp
	}
	return out, rows.Err()
}

// Prune drops entries whose exp is strictly before nowUnix.
func (s *RevocationStore) Prune(ctx context.Context, nowUnix int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM revocations WHERE exp < ?`, nowUnix); err != nil {
		return fmt.Errorf("sqlite: prune revocations: %w", err)
	}
	return nil
}

// === RefreshGraceStore (appended from refresh_grace.go) ===

const createRefreshGraceSQL = `
CREATE TABLE IF NOT EXISTS refresh_grace_cache (
    consumed_token_hash TEXT PRIMARY KEY,
    successor_response  BLOB,
    expires_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_grace_cache_expires_at
    ON refresh_grace_cache(expires_at);
`

// refreshGraceDefaultCleanupInterval is the default interval between periodic
// expired-row purges when the caller passes 0 for cleanupInterval.
const refreshGraceDefaultCleanupInterval = 5 * time.Minute

// RefreshGraceStore is the SQLite-backed, cluster-shared double-submit grace
// store. It structurally satisfies tokengrant.RefreshGraceStore (same method
// set) WITHOUT importing the handler layer, so the dependency direction stays
// downward, matching the Redis peer in infrastructure/redis/refresh_grace.go.
//
// SQLite in WAL mode with BEGIN IMMEDIATE semantics (via DELETE ... RETURNING)
// ensures cross-replica safety: only one replica can claim a consumed token's
// successor, and a miss falls through to family-reuse detection (BCP §4.13).
//
// Background cleanup runs at the configured interval (default 5 min) and is
// stoppable via context cancellation (Close).
type RefreshGraceStore struct {
	db     *sql.DB
	window time.Duration
	ownDB  bool // true when we opened the DB (Close releases it)
	cancel context.CancelFunc
	done   chan struct{}
}

// NewRefreshGraceStoreWithDSN opens a dedicated SQLite connection, ensures the
// schema, and starts the background cleanup goroutine with the given window
// duration as TTL. cleanupInterval <= 0 disables the background goroutine
// (lazy cleanup on write only). Caller must call Close() at shutdown.
func NewRefreshGraceStoreWithDSN(dsn string, window, cleanupInterval time.Duration) (*RefreshGraceStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open refresh_grace: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping refresh_grace: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	store, err := NewRefreshGraceStore(db, window, cleanupInterval)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store.ownDB = true
	return store, nil
}

// NewRefreshGraceStore wraps an existing *sql.DB, ensures the schema, and
// starts the background cleanup goroutine. cleanupInterval <= 0 disables the
// background goroutine. The caller owns the *sql.DB lifecycle — Close() will
// NOT close the DB.
func NewRefreshGraceStore(db *sql.DB, window, cleanupInterval time.Duration) (*RefreshGraceStore, error) {
	if err := ensureSchema(db, "refresh_grace_cache", createRefreshGraceSQL); err != nil {
		return nil, fmt.Errorf("sqlite: migrate refresh_grace_cache: %w", err)
	}
	// Default cleanup interval if not specified
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
				`DELETE FROM refresh_grace_cache WHERE expires_at <= ?`,
				time.Now().UnixNano())
		}
	}
}

// Close stops the background cleanup goroutine and, if the store owns the DB
// (created via NewRefreshGraceStoreWithDSN), releases the SQLite connection.
// Idempotent.
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
	var err error
	if s.ownDB && s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	return err
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

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *RefreshGraceStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: refresh grace store closed")
	}
	return s.db.PingContext(ctx)
}

// DB exposes the underlying *sql.DB for an operator-facing schema reporter
// (sso.WithStorageHealth via migrate.Status). Nil after Close when ownDB=true;
// callers MUST NOT close it.
func (s *RefreshGraceStore) DB() *sql.DB { return s.db }

// PruneExpired deletes every entry whose expires_at has passed. Exported for
// the background cleanup loop and for operator-facing admin endpoints.
func (s *RefreshGraceStore) PruneExpired(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("sqlite: refresh grace store closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_grace_cache WHERE expires_at <= ?`,
		time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune refresh_grace_cache: %w", err)
	}
	return res.RowsAffected()
}

// refreshGraceHash computes a hex-encoded SHA-256 hash of the consumed token.
// Using a fixed-size hash as the primary key avoids issues with long tokens and
// provides a stable, efficient index.
func refreshGraceHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// -- tokengrant.RefreshGraceStore interface (structural typing) --

// Remember caches resp as the successor for the just-consumed token. The
// response is JSON-marshalled and stored with an expiry of now+window. INSERT
// OR REPLACE makes it idempotent — a concurrent duplicate call silently
// overwrites with the same successor. Best-effort: marshal/DB errors degrade
// to strict single-use (the double-submit then trips family-reuse detection).
//
// A best-effort lazy GC runs before the insert to keep the table bounded by
// the active-window key count, matching the memory backend's prune contract.
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

	// Lazy GC: sweep expired rows before writing to keep the table bounded.
	// Cheap: indexed by expires_at, runs in O(expired count).
	_, _ = s.db.ExecContext(context.Background(),
		`DELETE FROM refresh_grace_cache WHERE expires_at <= ?`, now.UnixNano())

	_, _ = s.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO refresh_grace_cache (consumed_token_hash, successor_response, expires_at) VALUES (?, ?, ?)`,
		hash, blob, expiresAt)
}

// Lookup returns the cached successor for token if it was rotated within the
// grace window, or (nil, false) on ANY uncertainty — miss, expiry, backend
// error, or decode failure. The row is atomically deleted on fetch (single-use
// semantics via DELETE ... RETURNING) so a post-window replay falls through to
// family-reuse detection (BCP §4.13 preserved: fail-closed on miss/expiry/
// error).
//
// The atomic DELETE ... RETURNING replaces what would be a SELECT+DELETE
// transaction. In SQLite WAL mode this serialises writers, so a cross-replica
// race yields exactly one winner; the second caller gets sql.ErrNoRows and
// correctly falls through.
func (s *RefreshGraceStore) Lookup(token string, now time.Time) (map[string]any, bool) {
	if s == nil || s.db == nil || token == "" {
		return nil, false
	}
	hash := refreshGraceHash(token)

	var blob []byte
	var expiresAt int64
	err := s.db.QueryRowContext(context.Background(),
		`DELETE FROM refresh_grace_cache WHERE consumed_token_hash = ? RETURNING successor_response, expires_at`,
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

// Compile-time interface check (structural).
var _ interface {
	Remember(string, map[string]any, time.Time)
	Lookup(string, time.Time) (map[string]any, bool)
} = (*RefreshGraceStore)(nil)
