package sqlite

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// deviceCodeSchema captures the RFC 8628 device flow state machine.
// user_code carries its own UNIQUE constraint since /device/verify
// keys off it (and the user_code form is short — collision risk is
// non-zero, the UNIQUE index makes a colliding Issue fail loudly
// rather than silently overwrite). Interval stored as nanoseconds
// to round-trip Go's time.Duration without precision loss.
const deviceCodeSchema = `
CREATE TABLE IF NOT EXISTS device_codes (
    device_code TEXT    PRIMARY KEY,
    user_code   TEXT    NOT NULL UNIQUE,
    client_id   TEXT    NOT NULL,
    scopes      TEXT    NOT NULL DEFAULT '[]',
    nonce       TEXT    NOT NULL DEFAULT '',
    user_id     TEXT    NOT NULL DEFAULT '',
    provider    TEXT    NOT NULL DEFAULT '',
    attributes  TEXT    NOT NULL DEFAULT '{}',
    approved    INTEGER NOT NULL DEFAULT 0,
    denied      INTEGER NOT NULL DEFAULT 0,
    last_poll   INTEGER NOT NULL DEFAULT 0,
    interval_ns INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at
    ON device_codes(expires_at);
`

// oauth.DeviceCodeStore is the SQLite-backed [oauth.DeviceCodeStore].
type DeviceCodeStore struct {
	db *sql.DB
}

func NewDeviceCodeStore(dsn string) (*DeviceCodeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := ensureSchema(db, "device_codes", deviceCodeSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate device_codes: %w", err)
	}
	return &DeviceCodeStore{db: db}, nil
}

func NewDeviceCodeStoreWithDB(db *sql.DB) *DeviceCodeStore {
	return &DeviceCodeStore{db: db}
}

func (s *DeviceCodeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *DeviceCodeStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *DeviceCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: device code store closed")
	}
	return s.db.PingContext(ctx)
}

func (s *DeviceCodeStore) Issue(ctx context.Context, dc *oauth.DeviceCode) error {
	if dc == nil || dc.DeviceCode == "" || dc.UserCode == "" {
		return oauth.ErrDeviceCodeNotFound
	}
	scopes, err := json.Marshal(dc.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scopes: %w", err)
	}
	attrs, err := json.Marshal(dc.Attributes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO device_codes (device_code, user_code, client_id, scopes,
            nonce, user_id, provider, attributes, approved, denied,
            last_poll, interval_ns, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dc.DeviceCode, dc.UserCode, dc.ClientID, string(scopes),
		dc.Nonce, dc.UserID, dc.Provider, string(attrs),
		boolToInt(dc.Approved), boolToInt(dc.Denied),
		dc.LastPoll.UnixNano(), int64(dc.Interval),
		dc.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert device_code: %w", err)
	}
	return nil
}

func (s *DeviceCodeStore) GetByDeviceCode(ctx context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	row := s.db.QueryRowContext(ctx, deviceCodeSelectByCol("device_code"), deviceCode)
	return s.fetch(ctx, row)
}

func (s *DeviceCodeStore) GetByUserCode(ctx context.Context, userCode string) (*oauth.DeviceCode, error) {
	row := s.db.QueryRowContext(ctx, deviceCodeSelectByCol("user_code"), userCode)
	return s.fetch(ctx, row)
}

func (s *DeviceCodeStore) fetch(ctx context.Context, row *sql.Row) (*oauth.DeviceCode, error) {
	out, err := scanDeviceCode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: fetch device_code: %w", err)
	}
	if out.IsExpired() {
		// Opportunistic GC of the expired entry so retries don't see
		// stale state. Errors here are non-fatal — the caller already
		// got "not found" semantics.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE device_code = ?`, out.DeviceCode)
		return nil, oauth.ErrDeviceCodeNotFound
	}
	return out, nil
}

func (s *DeviceCodeStore) Approve(ctx context.Context, userCode, userID, provider string, attributes map[string]string) error {
	attrs, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
        UPDATE device_codes SET approved = 1, user_id = ?, provider = ?,
               attributes = ?
        WHERE user_code = ? AND expires_at > ?`,
		userID, provider, string(attrs), userCode, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: approve device_code: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return oauth.ErrDeviceCodeNotFound
	}
	return nil
}

func (s *DeviceCodeStore) Deny(ctx context.Context, userCode string) error {
	res, err := s.db.ExecContext(ctx, `
        UPDATE device_codes SET denied = 1
        WHERE user_code = ? AND expires_at > ?`,
		userCode, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: deny device_code: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return oauth.ErrDeviceCodeNotFound
	}
	return nil
}

func (s *DeviceCodeStore) UpdateLastPoll(ctx context.Context, deviceCode string, t time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET last_poll = ? WHERE device_code = ?`,
		t.UnixNano(), deviceCode)
	if err != nil {
		return fmt.Errorf("sqlite: update last_poll: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return oauth.ErrDeviceCodeNotFound
	}
	return nil
}

func (s *DeviceCodeStore) Delete(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE device_code = ?`, deviceCode)
	if err != nil {
		return fmt.Errorf("sqlite: delete device_code: %w", err)
	}
	return nil
}

// deviceCodeSelectByCol returns a select-by-{column} statement.
// Column name is a code constant, never user input — no SQLi risk.
func deviceCodeSelectByCol(col string) string {
	return `
        SELECT device_code, user_code, client_id, scopes, nonce,
               user_id, provider, attributes, approved, denied,
               last_poll, interval_ns, expires_at
        FROM device_codes WHERE ` + col + ` = ?`
}

func scanDeviceCode(s scanner) (*oauth.DeviceCode, error) {
	var (
		out                                         oauth.DeviceCode
		nonce, provider, scopesJSON, attrsJSON      string
		approvedInt, deniedInt                      int64
		lastPollUnixNs, intervalNs, expiresAtUnixNs int64
	)
	if err := s.Scan(
		&out.DeviceCode, &out.UserCode, &out.ClientID, &scopesJSON, &nonce,
		&out.UserID, &provider, &attrsJSON,
		&approvedInt, &deniedInt,
		&lastPollUnixNs, &intervalNs, &expiresAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.Nonce = nonce
	out.Provider = provider
	out.Approved = approvedInt != 0
	out.Denied = deniedInt != 0
	out.LastPoll = time.Unix(0, lastPollUnixNs).UTC()
	out.Interval = time.Duration(intervalNs)
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &out.Scopes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal scopes: %w", err)
		}
	}
	if attrsJSON != "" && attrsJSON != "{}" {
		if err := json.Unmarshal([]byte(attrsJSON), &out.Attributes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal attributes: %w", err)
		}
	}
	return &out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var _ oauth.DeviceCodeStore = (*DeviceCodeStore)(nil)
