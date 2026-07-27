package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// deviceSecretSchema is the OpenID Connect Native SSO 1.0 device-secret store
// (Postgres dialect): a server-issued opaque secret bound to (subject, sid,
// client), short-lived and single-use-on-exchange (Consume = DELETE … RETURNING).
// expires_at is Unix nanoseconds in a BIGINT (NOT timestamptz — preserves the
// exact nanosecond round-trip and the oracle-resistant "expired is
// indistinguishable from missing" expiry semantics, matching the SQLite peer).
const deviceSecretSchema = `
CREATE TABLE IF NOT EXISTS device_secrets (
    secret     TEXT   PRIMARY KEY,
    subject    TEXT   NOT NULL,
    sid        TEXT   NOT NULL DEFAULT '',
    client_id  TEXT   NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_secrets_expires_at
    ON device_secrets(expires_at);
`

var deviceSecretMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: deviceSecretSchema},
}

// DeviceSecretStore is the Postgres-backed [core.DeviceSecretStore] — durable
// across restarts and safe for multi-replica (every replica issues + consumes
// against the same DB).
type DeviceSecretStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewDeviceSecretStore opens cfg.DSN, migrates the schema, and returns the store.
func NewDeviceSecretStore(cfg Config) (*DeviceSecretStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewDeviceSecretStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewDeviceSecretStoreWithDB wraps an existing shared *sql.DB. The caller owns
// the connection lifecycle (shared-pool deployments).
func NewDeviceSecretStoreWithDB(db *sql.DB, dialect Dialect) (*DeviceSecretStore, error) {
	if err := Run(context.Background(), db, "device_secrets", deviceSecretMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate device_secrets: %w", err)
	}
	return &DeviceSecretStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewDeviceSecretStoreWithDB should be closed by whoever owns the pool, not here
// — but Close is safe either way (database/sql Close is idempotent).
func (s *DeviceSecretStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *DeviceSecretStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *DeviceSecretStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: device secret store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores a binding. The upsert keeps it idempotent by secret (an existing
// row is replaced in full), atomically via ON CONFLICT.
func (s *DeviceSecretStore) Issue(ctx context.Context, ds *core.DeviceSecret) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO device_secrets (secret, subject, sid, client_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (secret)
        DO UPDATE SET subject = EXCLUDED.subject, sid = EXCLUDED.sid,
                      client_id = EXCLUDED.client_id, expires_at = EXCLUDED.expires_at`,
		ds.Secret, ds.Subject, ds.SID, ds.ClientID, ds.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("postgres: issue device_secret: %w", err)
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
        DELETE FROM device_secrets WHERE secret = $1
        RETURNING subject, sid, client_id, expires_at`, secret).
		Scan(&subject, &sid, &clientID, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrDeviceSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume device_secret: %w", err)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_secrets WHERE subject = $1`, subject)
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke device_secrets by subject: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

var (
	_ core.DeviceSecretStore   = (*DeviceSecretStore)(nil)
	_ core.DeviceSecretRevoker = (*DeviceSecretStore)(nil)
)
