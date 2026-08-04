package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

// deviceCodeSchema captures the RFC 8628 device flow state machine.
// user_code carries its own UNIQUE constraint since /device/verify keys off
// it (and the user_code form is short — collision risk is non-zero, the
// UNIQUE index makes a colliding Issue fail loudly rather than silently
// overwrite). Interval stored as nanoseconds to round-trip Go's
// time.Duration without precision loss.
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
    last_poll   BIGINT  NOT NULL DEFAULT 0,
    interval_ns BIGINT  NOT NULL DEFAULT 0,
    expires_at  BIGINT  NOT NULL,
    resources   TEXT    NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at
    ON device_codes(expires_at);
`

var deviceCodeMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: deviceCodeSchema},
}

// DeviceCodeStore is the Postgres-backed implementation of
// [oauthspi.DeviceCodeStore]. Suitable for multi-replica deployments: a
// device_code issued on one replica is pollable on every other.
type DeviceCodeStore struct {
	db             *sql.DB
	dialect        Dialect
	lookupHMACKeys [][]byte
	reaper         *memreaper.Reaper
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for rolling migration. Keys are copied before retention.
func (s *DeviceCodeStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// NewDeviceCodeStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments) and runs the device_codes namespace migrations. The caller
// owns the pool — Close never releases it.
func NewDeviceCodeStoreWithDB(db *sql.DB, dialect Dialect) (*DeviceCodeStore, error) {
	if db == nil {
		return nil, errors.New("postgres: device code store: nil db")
	}
	if err := Run(context.Background(), db, "device_codes", deviceCodeMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate device_codes: %w", err)
	}
	return &DeviceCodeStore{db: db, dialect: dialect}, nil
}

// Close stops the reaper. The shared pool is owned by the caller. Idempotent.
func (s *DeviceCodeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_ = s.reaper.Close()
	s.db = nil
	return nil
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *DeviceCodeStore) DB() *sql.DB { return s.db }

// Ping reports connection health for /readyz wiring.
func (s *DeviceCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: device code store closed")
	}
	return s.db.PingContext(ctx)
}

// StartReaper runs a background sweep of expired codes; interval <= 0
// disables it (lazy fetch-time deletion still bounds growth).
func (s *DeviceCodeStore) StartReaper(interval time.Duration) {
	replaceReaper(&s.reaper, memreaper.Start(interval, func(now time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), postgresExpirySweepTimeout)
		defer cancel()
		_, _ = s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE expires_at < $1`, now.UnixNano())
	}))
}

func (s *DeviceCodeStore) Issue(ctx context.Context, dc *oauthspi.DeviceCode) error {
	if dc == nil || dc.DeviceCode == "" || dc.UserCode == "" {
		return oauthspi.ErrDeviceCodeNotFound
	}
	scopes, err := json.Marshal(dc.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: marshal scopes: %w", err)
	}
	attrs, err := json.Marshal(dc.Attributes)
	if err != nil {
		return fmt.Errorf("postgres: marshal attributes: %w", err)
	}
	resources, err := json.Marshal(dc.Resources)
	if err != nil {
		return fmt.Errorf("postgres: marshal resources: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO device_codes (device_code, user_code, client_id, scopes,
            nonce, user_id, provider, attributes, approved, denied,
            last_poll, interval_ns, expires_at, resources)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "device_code", dc.DeviceCode),
		opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "user_code", dc.UserCode),
		dc.ClientID, string(scopes),
		dc.Nonce, dc.UserID, dc.Provider, string(attrs),
		boolToInt(dc.Approved), boolToInt(dc.Denied),
		dc.LastPoll.UnixNano(), int64(dc.Interval),
		dc.ExpiresAt.UnixNano(), string(resources),
	)
	if err != nil {
		return fmt.Errorf("postgres: insert device_code: %w", err)
	}
	return nil
}

func (s *DeviceCodeStore) GetByDeviceCode(ctx context.Context, deviceCode string) (*oauthspi.DeviceCode, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "device_code", deviceCode) {
		row := s.db.QueryRowContext(ctx, deviceCodeSelectByCol("device_code", "$1"), candidate)
		out, err := s.fetch(ctx, row)
		if !errors.Is(err, oauthspi.ErrDeviceCodeNotFound) {
			// Re-stamp the RAW presented code onto the returned record — the
			// stored value is the opaque h1: lookup key and must never leak
			// into audit/claims (SQLite peer parity).
			if out != nil {
				out.DeviceCode = deviceCode
			}
			return out, err
		}
	}
	return nil, oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) GetByUserCode(ctx context.Context, userCode string) (*oauthspi.DeviceCode, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "user_code", userCode) {
		row := s.db.QueryRowContext(ctx, deviceCodeSelectByCol("user_code", "$1"), candidate)
		out, err := s.fetch(ctx, row)
		if !errors.Is(err, oauthspi.ErrDeviceCodeNotFound) {
			if out != nil {
				out.UserCode = userCode
			}
			return out, err
		}
	}
	return nil, oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) fetch(ctx context.Context, row *sql.Row) (*oauthspi.DeviceCode, error) {
	out, err := scanDeviceCode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauthspi.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: fetch device_code: %w", err)
	}
	if out.IsExpired() {
		// Opportunistic GC of the expired entry so retries don't see stale
		// state. Errors here are non-fatal — the caller already got
		// "not found" semantics. Deletes by the STORED value.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE device_code = $1`, out.DeviceCode)
		return nil, oauthspi.ErrDeviceCodeNotFound
	}
	return out, nil
}

func (s *DeviceCodeStore) Approve(ctx context.Context, userCode, userID, provider string, attributes map[string]string) error {
	attrs, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("postgres: marshal attributes: %w", err)
	}
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "user_code", userCode) {
		res, err := s.db.ExecContext(ctx, `
        UPDATE device_codes SET approved = 1, user_id = $1, provider = $2,
               attributes = $3
        WHERE user_code = $4 AND expires_at > $5`,
			userID, provider, string(attrs), candidate, time.Now().UnixNano())
		if err != nil {
			return fmt.Errorf("postgres: approve device_code: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
	}
	return oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) Deny(ctx context.Context, userCode string) error {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "user_code", userCode) {
		res, err := s.db.ExecContext(ctx, `
        UPDATE device_codes SET denied = 1
        WHERE user_code = $1 AND expires_at > $2`,
			candidate, time.Now().UnixNano())
		if err != nil {
			return fmt.Errorf("postgres: deny device_code: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
	}
	return oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) UpdateLastPoll(ctx context.Context, deviceCode string, t time.Time) error {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "device_code", deviceCode) {
		res, err := s.db.ExecContext(ctx,
			`UPDATE device_codes SET last_poll = $1 WHERE device_code = $2`,
			t.UnixNano(), candidate)
		if err != nil {
			return fmt.Errorf("postgres: update last_poll: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
	}
	return oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) Delete(ctx context.Context, deviceCode string) error {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "device_code", deviceCode) {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE device_code = $1`, candidate); err != nil {
			return fmt.Errorf("postgres: delete device_code: %w", err)
		}
	}
	return nil
}

// ConsumeIfApproved atomically deletes + returns the row IFF approved, via a
// single DELETE ... WHERE approved = 1 RETURNING. The DELETE is the atomic
// claim (MVCC row lock), so of N concurrent token-exchange polls of one
// approved device_code exactly ONE wins; no matching row ->
// ErrDeviceCodeNotFound.
func (s *DeviceCodeStore) ConsumeIfApproved(ctx context.Context, deviceCode string) (*oauthspi.DeviceCode, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "device_code", deviceCode) {
		out, err := s.consumeIfApproved(ctx, candidate)
		if !errors.Is(err, oauthspi.ErrDeviceCodeNotFound) {
			if out != nil {
				out.DeviceCode = deviceCode
			}
			return out, err
		}
	}
	return nil, oauthspi.ErrDeviceCodeNotFound
}

func (s *DeviceCodeStore) consumeIfApproved(ctx context.Context, lookup string) (*oauthspi.DeviceCode, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM device_codes WHERE device_code = $1 AND approved = 1
        RETURNING device_code, user_code, client_id, scopes, nonce,
                  user_id, provider, attributes, approved, denied,
                  last_poll, interval_ns, expires_at, resources`, lookup)
	out, err := scanDeviceCode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauthspi.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume_if_approved device_code: %w", err)
	}
	if out.IsExpired() {
		return nil, oauthspi.ErrDeviceCodeNotFound
	}
	return out, nil
}

// deviceCodeSelectByCol returns a select-by-{column} statement. Column name
// and placeholder are code constants, never user input — no SQLi risk.
func deviceCodeSelectByCol(col, placeholder string) string {
	return `
        SELECT device_code, user_code, client_id, scopes, nonce,
               user_id, provider, attributes, approved, denied,
               last_poll, interval_ns, expires_at, resources
        FROM device_codes WHERE ` + col + ` = ` + placeholder
}

func scanDeviceCode(s scanner) (*oauthspi.DeviceCode, error) {
	var (
		out                                         oauthspi.DeviceCode
		nonce, provider, scopesJSON, attrsJSON      string
		resourcesJSON                               string
		approvedInt, deniedInt                      int64
		lastPollUnixNs, intervalNs, expiresAtUnixNs int64
	)
	if err := s.Scan(
		&out.DeviceCode, &out.UserCode, &out.ClientID, &scopesJSON, &nonce,
		&out.UserID, &provider, &attrsJSON,
		&approvedInt, &deniedInt,
		&lastPollUnixNs, &intervalNs, &expiresAtUnixNs, &resourcesJSON,
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
			return nil, fmt.Errorf("postgres: unmarshal scopes: %w", err)
		}
	}
	if attrsJSON != "" && attrsJSON != "{}" {
		if err := json.Unmarshal([]byte(attrsJSON), &out.Attributes); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal attributes: %w", err)
		}
	}
	if resourcesJSON != "" && resourcesJSON != "[]" {
		if err := json.Unmarshal([]byte(resourcesJSON), &out.Resources); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal resources: %w", err)
		}
	}
	return &out, nil
}

// DeviceCodesMaxVersion returns the highest migration version declared for
// the device_codes namespace — the boot-gate input for the postgres branch.
func DeviceCodesMaxVersion() int { return migrate.MaxVersion(deviceCodeMigrations) }

var _ oauthspi.DeviceCodeStore = (*DeviceCodeStore)(nil)
