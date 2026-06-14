package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// deviceSecretSchema is the OpenID Connect Native SSO 1.0 device-secret store:
// a server-issued opaque secret bound to (subject, sid, client), short-lived
// and single-use-on-exchange (Consume = DELETE … RETURNING).
const deviceSecretSchema = `
CREATE TABLE IF NOT EXISTS device_secrets (
    secret     TEXT    PRIMARY KEY,
    subject    TEXT    NOT NULL,
    sid        TEXT    NOT NULL DEFAULT '',
    client_id  TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_secrets_expires_at
    ON device_secrets(expires_at);
`

// DeviceSecretStore is the SQLite-backed core.DeviceSecretStore — durable
// across restarts and safe for multi-replica (every replica issues + consumes
// against the same DB).
type DeviceSecretStore struct {
	db *sql.DB
}

// NewDeviceSecretStore opens dsn, migrates the schema, and returns the store.
func NewDeviceSecretStore(dsn string) (*DeviceSecretStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "device_secrets", deviceSecretSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate device_secrets: %w", err)
	}
	return &DeviceSecretStore{db: db}, nil
}

// NewDeviceSecretStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewDeviceSecretStoreWithDB(db *sql.DB) (*DeviceSecretStore, error) {
	if err := ensureSchema(db, "device_secrets", deviceSecretSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate device_secrets: %w", err)
	}
	return &DeviceSecretStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *DeviceSecretStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *DeviceSecretStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *DeviceSecretStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: device secret store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores a binding. INSERT OR REPLACE keeps it idempotent by secret.
func (s *DeviceSecretStore) Issue(ctx context.Context, ds *core.DeviceSecret) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO device_secrets (secret, subject, sid, client_id, expires_at)
        VALUES (?, ?, ?, ?, ?)`,
		ds.Secret, ds.Subject, ds.SID, ds.ClientID, ds.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: issue device_secret: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the binding. Missing/expired/
// already-consumed all return core.ErrDeviceSecretNotFound (oracle-safe — the
// row is gone either way).
func (s *DeviceSecretStore) Consume(ctx context.Context, secret string) (*core.DeviceSecret, error) {
	var subject, sid, clientID string
	var expNanos int64
	err := s.db.QueryRowContext(ctx, `
        DELETE FROM device_secrets WHERE secret = ?
        RETURNING subject, sid, client_id, expires_at`, secret).
		Scan(&subject, &sid, &clientID, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrDeviceSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume device_secret: %w", err)
	}
	ds := &core.DeviceSecret{
		Secret:    secret,
		Subject:   subject,
		SID:       sid,
		ClientID:  clientID,
		ExpiresAt: time.Unix(0, expNanos),
	}
	if ds.IsExpired() {
		return nil, core.ErrDeviceSecretNotFound
	}
	return ds, nil
}

// RevokeBySubject deletes every binding for subject (admin lockout of a lost or
// compromised device's Native SSO access) and returns the count removed.
func (s *DeviceSecretStore) RevokeBySubject(ctx context.Context, subject string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_secrets WHERE subject = ?`, subject)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke device_secrets by subject: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

var (
	_ core.DeviceSecretStore   = (*DeviceSecretStore)(nil)
	_ core.DeviceSecretRevoker = (*DeviceSecretStore)(nil)
)
