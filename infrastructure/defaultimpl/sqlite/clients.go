package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/migrate"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security/clientrotation"

	_ "modernc.org/sqlite"
)

// clientMigrations is the versioned schema history for the clients store.
// v1: baseline schema (the original 10-column table).
// v2: ADD COLUMN for security-load-bearing fields: JWKS, AllowedResources,
//
//	AllowedRequestURIs, RegistrationAccessToken, JWE alg/enc,
//	Federation, PostLogoutRedirectURIs, FrontchannelLogoutURI,
//	RequireSignedRequestObject, RequirePAR, AllowedAuthorizationDetailsTypes,
//	BackchannelLogoutURI, SubjectType, SectorIdentifierURI, TTL overrides,
//	Attributes, AllowedPKCEMethods, UserinfoSignedResponseAlg, CAEP attrs.
//
// All new columns default to empty/0 so existing rows are backward-compatible.
var clientMigrations = []migrate.Migration{
	{
		Version: 1,
		SQL: `
CREATE TABLE IF NOT EXISTS clients (
    id                      TEXT    PRIMARY KEY,
    secret                  TEXT    NOT NULL,
    name                    TEXT    NOT NULL DEFAULT '',
    redirect_uris           TEXT    NOT NULL DEFAULT '[]',
    allowed_scopes          TEXT    NOT NULL DEFAULT '[]',
    allowed_authenticators  TEXT    NOT NULL DEFAULT '[]',
    token_strategy          TEXT    NOT NULL DEFAULT '',
    active                  INTEGER NOT NULL DEFAULT 1,
    tenant_id               TEXT    NOT NULL DEFAULT '',
    require_pkce            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clients_tenant
    ON clients(tenant_id)
    WHERE tenant_id <> '';`,
	},
	{
		Version: 2,
		SQL: `
ALTER TABLE clients ADD COLUMN jwks                            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_resources               TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_request_uris            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN registration_access_token       TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris       TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_authorization_details   TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN refresh_token_ttl               INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN access_token_ttl                INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN allowed_pkce_methods            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN require_signed_request_object   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN require_par                     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN device_code_ttl                 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN device_code_poll_interval       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN userinfo_signed_response_alg    TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN idtoken_encrypted_response_alg  TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN idtoken_encrypted_response_enc  TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_alg TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_enc TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_uri          TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN subject_type                    TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN sector_identifier_uri           TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN frontchannel_logout_uri         TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN federation                      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN attributes                      TEXT    NOT NULL DEFAULT '{}';`,
	},
	{
		// v3: secret_rotated_at backs the scheduled client-secret rotation
		// sweep (clientrotation.ClientSecretRotator.ListDueForRotation).
		// Default 0 (unix-nanos "unknown") on existing rows means every
		// pre-migration client is NEVER due until its secret is next
		// rotated (Add/RotateSecret stamp it then) — see
		// core.Client.SecretRotatedAt for why zero must not mean "overdue".
		Version: 3,
		SQL:     `ALTER TABLE clients ADD COLUMN secret_rotated_at INTEGER NOT NULL DEFAULT 0;`,
	},
}

// ClientStore is the SQLite-backed [sso.ClientStore], including the
// optional [sso.TenantScopedClientStore] extension via the
// idx_clients_tenant partial index.
type ClientStore struct {
	db *sql.DB
}

func NewClientStore(dsn string) (*ClientStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "clients", clientMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate clients: %w", err)
	}
	return &ClientStore{db: db}, nil
}

// NewClientStoreWithDB wraps an already-open shared *sql.DB (the
// cluster-shared-DB path — see refresh_tokens.go's NewRefreshTokenStoreWithDB
// for the same pattern). Best-effort on this path (mirrors the historical
// contract — this constructor never returned an error): a fresh shared DB
// still needs its clients table created before any Get/Add call, so this
// runs the same migration NewClientStore's own-DB path does.
func NewClientStoreWithDB(db *sql.DB) *ClientStore {
	_ = migrate.Run(context.Background(), db, "clients", clientMigrations)
	return &ClientStore{db: db}
}

func (s *ClientStore) Close() error {
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
func (s *ClientStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *ClientStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: client store closed")
	}
	return s.db.PingContext(ctx)
}

func (s *ClientStore) Get(ctx context.Context, clientID string) (*sso.Client, error) {
	row := s.db.QueryRowContext(ctx, clientSelectByCol("id"), clientID)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrNoSuchClient
	}
	return c, err
}

func (s *ClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.Get(ctx, clientID)
	if err != nil {
		return err
	}
	if !compareClientSecret(c.Secret, clientSecret) {
		return errors.New("invalid client secret")
	}
	// Parity with MemoryClientStore.ValidateSecret: a deactivated
	// confidential client MUST NOT mint tokens. The /token grant path
	// relies solely on ValidateSecret for the active gate, and the
	// invalid_client collapse at /token keeps this oracle-safe.
	if !c.Active {
		return errors.New("client is inactive")
	}
	return nil
}

// List returns every registered client. Order: ascending id (stable,
// cheap via the PRIMARY KEY index).
func (s *ClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	rows, err := s.db.QueryContext(ctx, clientSelectAll()+" ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*sso.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Stats satisfies [sso.ClientStoreStats]: a cheap, order-independent
// fingerprint of the client set so the discovery-doc cache can skip its
// full List() + re-projection when nothing discovery-relevant changed.
func (s *ClientStore) Stats(ctx context.Context) (int, string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, allowed_scopes FROM clients`)
	if err != nil {
		return 0, "", fmt.Errorf("sqlite: stats clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var clients []*sso.Client
	for rows.Next() {
		var (
			id     string
			scopes string
		)
		if err := rows.Scan(&id, &scopes); err != nil {
			return 0, "", fmt.Errorf("sqlite: stats scan: %w", err)
		}
		c := &sso.Client{ID: id}
		if scopes != "" && scopes != "[]" {
			if err := json.Unmarshal([]byte(scopes), &c.AllowedScopes); err != nil {
				return 0, "", fmt.Errorf("sqlite: stats unmarshal allowed_scopes: %w", err)
			}
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("sqlite: stats rows: %w", err)
	}
	return len(clients), core.ClientSetFingerprint(clients), nil
}

// ListByTenant implements [sso.TenantScopedClientStore] using the
// partial index — empty tenant_id rows aren't indexed (they belong
// to no tenant) so a tenant-scoped read never touches them.
func (s *ClientStore) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Client, error) {
	rows, err := s.db.QueryContext(ctx, clientSelectByCol("tenant_id")+" ORDER BY id ASC", tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*sso.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// clientInsertSQL / clientUpsertSQL share the same column list +
// VALUES shape; only the conflict verb differs (plain INSERT vs INSERT
// OR REPLACE), so the upsert is derived from the insert.
const clientInsertSQL = `
        INSERT INTO clients (
            id, secret, name, redirect_uris, allowed_scopes,
            allowed_authenticators, token_strategy, active, tenant_id, require_pkce,
            jwks, allowed_resources, allowed_request_uris, registration_access_token,
            post_logout_redirect_uris, allowed_authorization_details,
            refresh_token_ttl, access_token_ttl, allowed_pkce_methods,
            require_signed_request_object, require_par,
            device_code_ttl, device_code_poll_interval,
            userinfo_signed_response_alg,
            idtoken_encrypted_response_alg, idtoken_encrypted_response_enc,
            userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
            backchannel_logout_uri, subject_type, sector_identifier_uri,
            frontchannel_logout_uri, federation, attributes, secret_rotated_at
        ) VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?
        )`

func (s *ClientStore) Add(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	// SecretRotatedAt baselines at creation time (parity with
	// MemoryClientStore.Add) so a freshly-added confidential client is
	// immediately eligible for scheduled rotation once it ages past the
	// configured interval — see ListDueForRotation. A secretless client
	// (federation-derived / public) has nothing to rotate, so its
	// timestamp stays zero (never due).
	if c.Secret != "" {
		c.SecretRotatedAt = time.Now()
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, clientInsertSQL, args...); err != nil {
		if isUniqueViolation(err) {
			return sso.ErrClientExists
		}
		return fmt.Errorf("sqlite: insert client: %w", err)
	}
	return nil
}

// Put is an upsert (INSERT OR REPLACE). Used by the admin gRPC service and
// the bootstrap seeder when an exact-overwrite is needed.
func (s *ClientStore) Put(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	upsertSQL := strings.Replace(clientInsertSQL,
		"INSERT INTO clients", "INSERT OR REPLACE INTO clients", 1)
	if _, err := s.db.ExecContext(ctx, upsertSQL, args...); err != nil {
		return fmt.Errorf("sqlite: put client: %w", err)
	}
	return nil
}

const clientUpdateSQL = `
        UPDATE clients SET
            secret = ?, name = ?, redirect_uris = ?,
            allowed_scopes = ?, allowed_authenticators = ?,
            token_strategy = ?, active = ?, tenant_id = ?, require_pkce = ?,
            jwks = ?, allowed_resources = ?, allowed_request_uris = ?,
            registration_access_token = ?,
            post_logout_redirect_uris = ?, allowed_authorization_details = ?,
            refresh_token_ttl = ?, access_token_ttl = ?, allowed_pkce_methods = ?,
            require_signed_request_object = ?, require_par = ?,
            device_code_ttl = ?, device_code_poll_interval = ?,
            userinfo_signed_response_alg = ?,
            idtoken_encrypted_response_alg = ?, idtoken_encrypted_response_enc = ?,
            userinfo_encrypted_response_alg = ?, userinfo_encrypted_response_enc = ?,
            backchannel_logout_uri = ?, subject_type = ?, sector_identifier_uri = ?,
            frontchannel_logout_uri = ?, federation = ?, attributes = ?, secret_rotated_at = ?
        WHERE id = ?`

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	// The UPDATE binds the same column projection minus the leading id
	// (which moves to the trailing WHERE clause), so drop args[0] and
	// re-append c.ID.
	args = append(args[1:], c.ID)
	res, err := s.db.ExecContext(ctx, clientUpdateSQL, args...)
	if err != nil {
		return fmt.Errorf("sqlite: update client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sso.ErrNoSuchClient
	}
	return nil
}

// Delete is idempotent — missing ids return nil (matches the
// interface contract).
func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("sqlite: delete client: %w", err)
	}
	return nil
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	plain, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plain)
	if err != nil {
		return "", fmt.Errorf("sqlite: hash rotated secret: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE clients SET secret = ?, secret_rotated_at = ? WHERE id = ?`,
		hashed, unixNanoOrZero(time.Now()), clientID)
	if err != nil {
		return "", fmt.Errorf("sqlite: rotate secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sso.ErrNoSuchClient
	}
	return plain, nil
}

// ListDueForRotation implements clientrotation.ClientRotationLister: every
// active, secret-bearing client last rotated at or before olderThan. A zero
// secret_rotated_at (never tracked) is excluded by the `> 0` guard — see
// core.Client.SecretRotatedAt for why zero must not mean "overdue".
func (s *ClientStore) ListDueForRotation(ctx context.Context, olderThan time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM clients
		 WHERE active = 1 AND secret <> '' AND secret_rotated_at > 0 AND secret_rotated_at <= ?
		 ORDER BY id ASC`,
		unixNanoOrZero(olderThan))
	if err != nil {
		return nil, fmt.Errorf("sqlite: list clients due for rotation: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("sqlite: scan client id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// clientSelectAll keeps the column list in one place so Add / Update /
// scan can't drift.
func clientSelectAll() string {
	return `SELECT id, secret, name, redirect_uris, allowed_scopes,
        allowed_authenticators, token_strategy, active, tenant_id, require_pkce,
        jwks, allowed_resources, allowed_request_uris, registration_access_token,
        post_logout_redirect_uris, allowed_authorization_details,
        refresh_token_ttl, access_token_ttl, allowed_pkce_methods,
        require_signed_request_object, require_par,
        device_code_ttl, device_code_poll_interval,
        userinfo_signed_response_alg,
        idtoken_encrypted_response_alg, idtoken_encrypted_response_enc,
        userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
        backchannel_logout_uri, subject_type, sector_identifier_uri,
        frontchannel_logout_uri, federation, attributes, secret_rotated_at
        FROM clients`
}

func clientSelectByCol(col string) string {
	return clientSelectAll() + ` WHERE ` + col + ` = ?`
}

func scanClient(s scanner) (*sso.Client, error) {
	var r clientScanRow
	if err := r.scanInto(s); err != nil {
		return nil, err
	}
	r.scalars()
	if err := r.jsonFields(); err != nil {
		return nil, err
	}
	return &r.c, nil
}

// generateClientSecret matches defaultimpl.MemoryClientStore — 32-byte
// base64url ≈ 256 bits of entropy.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sqlite: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE-constraint
// violation. modernc.org/sqlite returns SQLITE_CONSTRAINT_PRIMARYKEY
// or SQLITE_CONSTRAINT_UNIQUE — both rendered as part of the message
// in the absence of a typed code we can switch on without CGO.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint") ||
		strings.Contains(s, "PRIMARY KEY") ||
		strings.Contains(s, "constraint failed")
}

var (
	_ sso.ClientStore                     = (*ClientStore)(nil)
	_ sso.TenantScopedClientStore         = (*ClientStore)(nil)
	_ core.ClientStoreStats               = (*ClientStore)(nil)
	_ clientrotation.ClientRotationLister = (*ClientStore)(nil)
)
