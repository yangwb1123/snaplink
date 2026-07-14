package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// passwordResetSchema is the forgot-password reset-token store: a server-issued
// opaque token bound to a user, short-lived and single-use-on-reset
// (Consume = DELETE … RETURNING).
const passwordResetSchema = `
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at
    ON password_reset_tokens(expires_at);
`

// PasswordResetStore is the SQLite-backed core.PasswordResetStore — durable
// across restarts and safe for multi-replica (every replica issues + consumes
// against the same DB; the single-use DELETE…RETURNING is atomic).
type PasswordResetStore struct {
	db *sql.DB
}

// NewPasswordResetStore opens dsn, migrates the schema, and returns the store.
func NewPasswordResetStore(dsn string) (*PasswordResetStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "password_reset_tokens", passwordResetSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate password_reset_tokens: %w", err)
	}
	return &PasswordResetStore{db: db}, nil
}

// NewPasswordResetStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewPasswordResetStoreWithDB(db *sql.DB) (*PasswordResetStore, error) {
	if err := ensureSchema(db, "password_reset_tokens", passwordResetSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate password_reset_tokens: %w", err)
	}
	return &PasswordResetStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PasswordResetStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *PasswordResetStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *PasswordResetStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: password reset store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores a token. INSERT OR REPLACE keeps it idempotent by token value.
func (s *PasswordResetStore) Issue(ctx context.Context, rt *core.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO password_reset_tokens (token, user_id, expires_at)
        VALUES (?, ?, ?)`,
		rt.Token, rt.UserID, rt.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: issue password_reset_token: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the token. Missing/expired/
// already-consumed all return core.ErrResetTokenNotFound (oracle-safe — the
// row is gone either way).
func (s *PasswordResetStore) Consume(ctx context.Context, token string) (*core.PasswordResetToken, error) {
	var userID string
	var expNanos int64
	err := s.db.QueryRowContext(ctx, `
        DELETE FROM password_reset_tokens WHERE token = ?
        RETURNING user_id, expires_at`, token).
		Scan(&userID, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrResetTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume password_reset_token: %w", err)
	}
	rt := &core.PasswordResetToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Unix(0, expNanos),
	}
	if rt.IsExpired() {
		return nil, core.ErrResetTokenNotFound
	}
	return rt, nil
}

// RevokeByUser deletes all pending reset tokens bound to userID (admin-plane
// invalidation) and returns the count removed.
func (s *PasswordResetStore) RevokeByUser(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM password_reset_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke password_reset_tokens by user: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListByUser returns all pending reset tokens bound to userID (admin-plane
// read; the caller projects safe metadata only).
func (s *PasswordResetStore) ListByUser(ctx context.Context, userID string) ([]*core.PasswordResetToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token, expires_at FROM password_reset_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list password_reset_tokens by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.PasswordResetToken
	for rows.Next() {
		var token string
		var expNanos int64
		if err := rows.Scan(&token, &expNanos); err != nil {
			return nil, fmt.Errorf("sqlite: scan password_reset_token: %w", err)
		}
		out = append(out, &core.PasswordResetToken{Token: token, UserID: userID, ExpiresAt: time.Unix(0, expNanos)})
	}
	return out, rows.Err()
}

var (
	_ core.PasswordResetStore   = (*PasswordResetStore)(nil)
	_ core.PasswordResetRevoker = (*PasswordResetStore)(nil)
	_ core.PasswordResetLister  = (*PasswordResetStore)(nil)
)

// ---------------------------------------------------------------------
// TrustedDeviceStore
//
// Bundled into this file rather than its own trusted_device.go because
// infrastructure/defaultimpl/sqlite is already at its frozen
// directory_fanout_test.go file-count ceiling (dirFileCountExemptions —
// 36 non-test .go files, and the exemption-map itself is at its own
// count cap) — adding a 37th non-test file here would regress a
// committed gate. This mirrors the precedent already set at the memory
// layer: memorystorecredential/recovery_code.go bundles
// MemoryRecoveryCodeStore + MemoryTrustedDeviceStore as two self-service
// credential concerns in one file for the same reason of cohesion; this
// file already holds one self-service token+expiry+owner-scoped store
// (password reset), making it the closest structural sibling for a
// second one.
// ---------------------------------------------------------------------

// trustedDevicesSchema is the "remember this device" MFA-skip grant store —
// see core.TrustedDeviceStore's doc comment for the full anti-enumeration
// contract this schema/queries must uphold.
//
// token_hash is the SHA-256 hex digest of the bearer token (see
// hashTrustedDeviceToken below) — the plaintext is NEVER persisted, only
// returned once from Trust. The algorithm matches
// memorystorecredential.hashTrustedDeviceToken exactly, so the two backends
// apply identical hashing semantics to the same kind of credential. The
// (user_id, token_hash) unique index backs Verify's exact-match lookup;
// user_id alone backs ListByUser/Revoke/RevokeAll.
const trustedDevicesSchema = `
CREATE TABLE IF NOT EXISTS trusted_devices (
    id           TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL,
    client_id    TEXT    NOT NULL,
    token_hash   TEXT    NOT NULL,
    label        TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_trusted_devices_user
    ON trusted_devices(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_devices_user_hash
    ON trusted_devices(user_id, token_hash);
`

// TrustedDeviceStore is the SQLite-backed core.TrustedDeviceStore — durable
// across restarts and shared across replicas, unlike
// memorystorecredential.MemoryTrustedDeviceStore (in-process only: every
// "remember this device" MFA-skip grant is lost on restart or replica
// failover, forcing every user back through MFA).
type TrustedDeviceStore struct {
	db *sql.DB
}

// NewTrustedDeviceStore opens dsn, migrates the schema, and returns the store.
func NewTrustedDeviceStore(dsn string) (*TrustedDeviceStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "trusted_devices", trustedDevicesSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate trusted_devices: %w", err)
	}
	return &TrustedDeviceStore{db: db}, nil
}

// NewTrustedDeviceStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewTrustedDeviceStoreWithDB(db *sql.DB) (*TrustedDeviceStore, error) {
	if err := ensureSchema(db, "trusted_devices", trustedDevicesSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate trusted_devices: %w", err)
	}
	return &TrustedDeviceStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *TrustedDeviceStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *TrustedDeviceStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *TrustedDeviceStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: trusted device store closed")
	}
	return s.db.PingContext(ctx)
}

// Trust mints a new grant for (userID, clientID), persists only the token's
// SHA-256 hash, and returns the plaintext token exactly once. ttl <= 0
// applies core.DefaultTrustedDeviceTTL.
func (s *TrustedDeviceStore) Trust(ctx context.Context, userID, clientID, label string, ttl time.Duration) (string, *core.TrustedDevice, error) {
	if userID == "" {
		return "", nil, fmt.Errorf("sqlite: trust: empty user id")
	}
	if ttl <= 0 {
		ttl = core.DefaultTrustedDeviceTTL
	}
	token, err := newTrustedDeviceToken()
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: generate device token: %w", err)
	}
	id, err := newTrustedDeviceID()
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: generate device id: %w", err)
	}

	now := time.Now()
	dev := core.TrustedDevice{
		ID:        id,
		UserID:    userID,
		ClientID:  clientID,
		Label:     label,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO trusted_devices (id, user_id, client_id, token_hash, label, created_at, expires_at, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, userID, clientID, hashTrustedDeviceToken(token), label, now.UnixNano(), dev.ExpiresAt.UnixNano())
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: insert trusted_device: %w", err)
	}
	return token, &dev, nil
}

// Verify reports whether token is a live grant for EXACTLY (userID,
// clientID). Unknown hash, wrong user (the query is scoped to userID, so a
// hash minted for a different user simply never matches a row), wrong
// client, and expired all collapse to the same (false, nil): callers MUST
// NOT distinguish any of the four (anti-enumeration, mirrors
// MemoryTrustedDeviceStore.Verify exactly). A true result updates
// last_used_at best-effort; Verify never extends expires_at.
func (s *TrustedDeviceStore) Verify(ctx context.Context, userID, clientID, token string) (bool, error) {
	if userID == "" || token == "" {
		return false, nil
	}
	hash := hashTrustedDeviceToken(token)
	var id, gotClientID string
	var expiresAtNs int64
	err := s.db.QueryRowContext(ctx, `
        SELECT id, client_id, expires_at FROM trusted_devices
         WHERE user_id = ? AND token_hash = ?`, userID, hash).
		Scan(&id, &gotClientID, &expiresAtNs)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: verify trusted_device: %w", err)
	}
	if time.Now().After(time.Unix(0, expiresAtNs)) {
		// Lazily prune the expired grant rather than requiring a sweeper
		// goroutine — same discipline as the memory peer.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM trusted_devices WHERE id = ?`, id)
		return false, nil
	}
	if gotClientID != clientID {
		// Right token, wrong client: the grant exists but does not cover
		// this login — same "no" as an unknown token to the caller.
		return false, nil
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE trusted_devices SET last_used_at = ? WHERE id = ?`, time.Now().UnixNano(), id)
	return true, nil
}

// ListByUser returns metadata only — token_hash is never selected, so it
// never leaves this file — for the self-service GET /me/devices surface.
func (s *TrustedDeviceStore) ListByUser(ctx context.Context, userID string) ([]core.TrustedDevice, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, client_id, label, created_at, expires_at, last_used_at
          FROM trusted_devices WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list trusted_devices by user: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []core.TrustedDevice
	for rows.Next() {
		var d core.TrustedDevice
		var createdNs, expiresNs, lastUsedNs int64
		if err := rows.Scan(&d.ID, &d.ClientID, &d.Label, &createdNs, &expiresNs, &lastUsedNs); err != nil {
			return nil, fmt.Errorf("sqlite: scan trusted_device: %w", err)
		}
		d.UserID = userID
		d.CreatedAt = time.Unix(0, createdNs).UTC()
		d.ExpiresAt = time.Unix(0, expiresNs).UTC()
		if lastUsedNs > 0 {
			d.LastUsedAt = time.Unix(0, lastUsedNs).UTC()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Revoke deletes one grant, scoped to userID so a cross-user id can never
// touch someone else's grant. Idempotent: an unknown or already-revoked
// (userID, id) is a no-op.
func (s *TrustedDeviceStore) Revoke(ctx context.Context, userID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM trusted_devices WHERE user_id = ? AND id = ?`, userID, id)
	if err != nil {
		return fmt.Errorf("sqlite: revoke trusted_device: %w", err)
	}
	return nil
}

// RevokeAll deletes every grant for userID and returns the count removed —
// called on password change and other account-compromise signals so a
// stolen "remember this device" grant can't outlive the credential it was
// minted under.
func (s *TrustedDeviceStore) RevokeAll(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM trusted_devices WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke-all trusted_devices: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// newTrustedDeviceToken mints a cryptographically random base64url-encoded
// bearer-equivalent MFA-skip token. core.TrustedDeviceTokenBytes (32 bytes /
// 256 bits) matches oauth refresh-token entropy.
func newTrustedDeviceToken() (string, error) {
	buf := make([]byte, core.TrustedDeviceTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// newTrustedDeviceID mints a random opaque record id — distinct from the
// token: safe to log or return in a list response, unlike the token.
func newTrustedDeviceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashTrustedDeviceToken returns the SHA-256 hex digest of token — the only
// form of the token ever persisted, matching
// memorystorecredential.hashTrustedDeviceToken's algorithm exactly.
func hashTrustedDeviceToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

var _ core.TrustedDeviceStore = (*TrustedDeviceStore)(nil)
