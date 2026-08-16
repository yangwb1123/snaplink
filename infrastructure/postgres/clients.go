package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// clientSchema is the Postgres baseline for the clients table. Unlike the
// SQLite peer (which grew the table across v1+v2 ALTER migrations) the Postgres
// backend starts fresh, so all columns land in one baseline. Booleans are
// INTEGER 0/1 (kept, not BOOLEAN, so the scan path matches sqlite byte-for-byte)
// and TTLs are BIGINT nanoseconds. The partial index excludes tenant-less rows.
const clientSchema = `
CREATE TABLE IF NOT EXISTS clients (
    id                              TEXT    PRIMARY KEY,
    secret                          TEXT    NOT NULL,
    name                            TEXT    NOT NULL DEFAULT '',
    redirect_uris                   TEXT    NOT NULL DEFAULT '[]',
    allowed_scopes                  TEXT    NOT NULL DEFAULT '[]',
    allowed_authenticators          TEXT    NOT NULL DEFAULT '[]',
    token_strategy                  TEXT    NOT NULL DEFAULT '',
    active                          INTEGER NOT NULL DEFAULT 1,
    tenant_id                       TEXT    NOT NULL DEFAULT '',
    require_pkce                    INTEGER NOT NULL DEFAULT 0,
    jwks                            TEXT    NOT NULL DEFAULT '[]',
    allowed_resources               TEXT    NOT NULL DEFAULT '[]',
    allowed_request_uris            TEXT    NOT NULL DEFAULT '[]',
    registration_access_token       TEXT    NOT NULL DEFAULT '',
    post_logout_redirect_uris       TEXT    NOT NULL DEFAULT '[]',
    allowed_authorization_details   TEXT    NOT NULL DEFAULT '[]',
    refresh_token_ttl               BIGINT  NOT NULL DEFAULT 0,
    access_token_ttl                BIGINT  NOT NULL DEFAULT 0,
    allowed_pkce_methods            TEXT    NOT NULL DEFAULT '[]',
    require_signed_request_object   INTEGER NOT NULL DEFAULT 0,
    require_par                     INTEGER NOT NULL DEFAULT 0,
    device_code_ttl                 BIGINT  NOT NULL DEFAULT 0,
    device_code_poll_interval       BIGINT  NOT NULL DEFAULT 0,
    userinfo_signed_response_alg    TEXT    NOT NULL DEFAULT '',
    idtoken_encrypted_response_alg  TEXT    NOT NULL DEFAULT '',
    idtoken_encrypted_response_enc  TEXT    NOT NULL DEFAULT '',
    userinfo_encrypted_response_alg TEXT    NOT NULL DEFAULT '',
    userinfo_encrypted_response_enc TEXT    NOT NULL DEFAULT '',
    backchannel_logout_uri          TEXT    NOT NULL DEFAULT '',
    subject_type                    TEXT    NOT NULL DEFAULT '',
    sector_identifier_uri           TEXT    NOT NULL DEFAULT '',
    frontchannel_logout_uri         TEXT    NOT NULL DEFAULT '',
    federation                      INTEGER NOT NULL DEFAULT 0,
    attributes                      TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id) WHERE tenant_id <> '';
`

// clientSchemaV2 backs two features the SQLite peer already tracks (v3/v4
// there) that this backend's baseline never picked up: scheduled client-secret
// rotation (shared/security/clientrotation.ClientRotationLister needs
// secret_rotated_at to know which clients are due) and the rule-based client
// trust scorer (platform/lifecycle/clienttrust needs client_trust_score /
// client_trust_set_at to persist scores across restarts/replicas). Without
// this column set, both features silently no-op against a Postgres-backed
// ClientStore: rotation never lists anything due (Postgres never implemented
// ClientRotationLister at all) and a trust score set by UpdateAndAlert is lost
// the moment it's re-read. DEFAULT 0 on existing rows reads as "never tracked"
// / "never scored" — see core.Client.SecretRotatedAt / ClientTrustSetAt for why
// zero must not be treated as "overdue" / "distrusted".
const clientSchemaV2 = `
ALTER TABLE clients ADD COLUMN IF NOT EXISTS secret_rotated_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS client_trust_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS client_trust_set_at BIGINT NOT NULL DEFAULT 0;
`

const clientSchemaV3 = `
ALTER TABLE clients ADD COLUMN IF NOT EXISTS previous_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS secret_overlap_until BIGINT NOT NULL DEFAULT 0;
`

const clientSchemaV4 = `
ALTER TABLE clients ADD COLUMN IF NOT EXISTS secret_expires_at BIGINT NOT NULL DEFAULT 0;
`

const clientSchemaV5 = `
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_token_signed_response_alg TEXT NOT NULL DEFAULT '';
`

var clientMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: clientSchema},
	{Version: 2, Name: "secret_rotation_and_trust_score", SQL: clientSchemaV2},
	{Version: 3, Name: "client_secret_overlap", SQL: clientSchemaV3},
	{Version: 4, Name: "client_secret_expiry", SQL: clientSchemaV4},
	{Version: 5, Name: "client_id_token_signed_response_alg", SQL: clientSchemaV5},
}

// Statements derived once from clientColumns so the INSERT / upsert / UPDATE /
// SELECT placeholder numbering can never drift from the column projection.
var (
	clientSelectStmt = "SELECT " + strings.Join(clientColumns, ", ") + " FROM clients"
	clientInsertStmt = buildClientInsert()
	clientUpsertStmt = clientInsertStmt + " ON CONFLICT (id) DO UPDATE SET " + buildClientUpdateSet(0)
	clientUpdateStmt = "UPDATE clients SET " + buildClientUpdateSet(1) +
		" WHERE id = $" + strconv.Itoa(len(clientColumns))
)

func buildClientInsert() string {
	ph := make([]string, len(clientColumns))
	for i := range clientColumns {
		ph[i] = "$" + strconv.Itoa(i+1)
	}
	return "INSERT INTO clients (" + strings.Join(clientColumns, ", ") +
		") VALUES (" + strings.Join(ph, ", ") + ")"
}

// buildClientUpdateSet builds the "col = ..." list for every column except id.
// numbered>0 uses positional placeholders ($1.. for the UPDATE, whose args are
// clientWriteArgs minus id); numbered==0 uses EXCLUDED.col for the upsert.
func buildClientUpdateSet(numbered int) string {
	sets := make([]string, 0, len(clientColumns)-1)
	for i, col := range clientColumns[1:] {
		if numbered > 0 {
			sets = append(sets, col+" = $"+strconv.Itoa(i+1))
		} else {
			sets = append(sets, col+" = EXCLUDED."+col)
		}
	}
	return strings.Join(sets, ", ")
}

// ClientStore is the Postgres-backed [sso.ClientStore], including the optional
// [sso.TenantScopedClientStore] extension via the idx_clients_tenant partial
// index and [core.ClientStoreStats].
type ClientStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewClientStore opens cfg.DSN, migrates the schema, and returns the store.
func NewClientStore(cfg Config) (*ClientStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewClientStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewClientStoreWithDB wraps an existing shared *sql.DB. The caller owns the
// connection lifecycle (shared-pool deployments).
func NewClientStoreWithDB(db *sql.DB, dialect Dialect) (*ClientStore, error) {
	if err := Run(context.Background(), db, "clients", clientMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate clients: %w", err)
	}
	return &ClientStore{db: db, dialect: dialect.normalized()}, nil
}

func (s *ClientStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *ClientStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *ClientStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: client store closed")
	}
	return s.db.PingContext(ctx)
}

func (s *ClientStore) Get(ctx context.Context, clientID string) (*sso.Client, error) {
	row := s.db.QueryRowContext(ctx, clientSelectStmt+" WHERE id = $1", clientID)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrNoSuchClient
	}
	return c, err
}

// ValidateSecret mirrors the other backends: compare via shared/security, then
// gate on Active. The invalid_client collapse at /token keeps this oracle-safe.
func (s *ClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.Get(ctx, clientID)
	if err != nil {
		return err
	}
	current := security.CompareClientSecret(c.Secret, clientSecret)
	previous := time.Now().Before(c.SecretOverlapUntil) && security.CompareClientSecret(c.PreviousSecret, clientSecret)
	if !current && !previous {
		return errors.New("invalid client secret")
	}
	if !c.SecretExpiresAt.IsZero() && !time.Now().Before(c.SecretExpiresAt) {
		return errors.New("client secret expired")
	}
	if !c.Active {
		return errors.New("client is inactive")
	}
	return nil
}

func (s *ClientStore) queryClients(ctx context.Context, query string, args ...any) ([]*sso.Client, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: query clients: %w", err)
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

// List returns every registered client, ascending id.
func (s *ClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	return s.queryClients(ctx, clientSelectStmt+" ORDER BY id ASC")
}

// ListByTenant implements [sso.TenantScopedClientStore] using the partial
// index — empty tenant_id rows aren't indexed so a tenant read never sees them.
func (s *ClientStore) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Client, error) {
	return s.queryClients(ctx, clientSelectStmt+" WHERE tenant_id = $1 ORDER BY id ASC", tenantID)
}

// Stats satisfies [core.ClientStoreStats]: a cheap order-independent
// fingerprint of the client set so the discovery-doc cache can skip a full
// re-projection when nothing discovery-relevant changed.
func (s *ClientStore) Stats(ctx context.Context) (int, string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, allowed_scopes FROM clients`)
	if err != nil {
		return 0, "", fmt.Errorf("postgres: stats clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var clients []*sso.Client
	for rows.Next() {
		var id, scopes string
		if err := rows.Scan(&id, &scopes); err != nil {
			return 0, "", fmt.Errorf("postgres: stats scan: %w", err)
		}
		c := &sso.Client{ID: id}
		if scopes != "" && scopes != "[]" {
			if err := json.Unmarshal([]byte(scopes), &c.AllowedScopes); err != nil {
				return 0, "", fmt.Errorf("postgres: stats unmarshal allowed_scopes: %w", err)
			}
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("postgres: stats rows: %w", err)
	}
	return len(clients), core.ClientSetFingerprint(clients), nil
}

func (s *ClientStore) Add(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("postgres: client.ID required")
	}
	// SecretRotatedAt baselines at creation time (parity with the sqlite/memory
	// peers) so a freshly-added confidential client is immediately eligible for
	// scheduled rotation once it ages past the configured interval — see
	// ListDueForRotation. A secretless client (federation-derived/public) has
	// nothing to rotate, so its timestamp stays zero (never due).
	if c.Secret != "" {
		now := time.Now()
		c.SecretRotatedAt = now
		if c.SecretExpiresAt.IsZero() {
			c.SecretExpiresAt = now.Add(clientrotation.DefaultLifetime)
		}
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, clientInsertStmt, args...); err != nil {
		if isUniqueViolation(err) {
			return sso.ErrClientExists
		}
		return fmt.Errorf("postgres: insert client: %w", err)
	}
	return nil
}

// Put is an upsert (ON CONFLICT DO UPDATE). Used by the admin gRPC service and
// the bootstrap seeder when an exact-overwrite is needed.
func (s *ClientStore) Put(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("postgres: client.ID required")
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, clientUpsertStmt, args...); err != nil {
		return fmt.Errorf("postgres: put client: %w", err)
	}
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("postgres: client.ID required")
	}
	args, err := clientWritePrep(c)
	if err != nil {
		return err
	}
	// The UPDATE binds clientColumns minus id ($1..$N-1) then id in the
	// trailing WHERE ($N) — drop args[0] and re-append c.ID.
	args = append(args[1:], c.ID)
	res, err := s.db.ExecContext(ctx, clientUpdateStmt, args...)
	if err != nil {
		return fmt.Errorf("postgres: update client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sso.ErrNoSuchClient
	}
	return nil
}

// Delete is idempotent — missing ids return nil.
func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = $1`, clientID); err != nil {
		return fmt.Errorf("postgres: delete client: %w", err)
	}
	return nil
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, 0, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithOverlap(ctx context.Context, clientID string, overlap time.Duration) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, overlap, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithLifecycle(ctx context.Context, clientID string, overlap, lifetime time.Duration) (string, error) {
	plain, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plain)
	if err != nil {
		return "", fmt.Errorf("postgres: hash rotated secret: %w", err)
	}
	now := time.Now()
	var until int64
	if overlap > 0 {
		until = now.Add(overlap).UnixNano()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET
		previous_secret = CASE WHEN $1::BIGINT > 0 THEN secret ELSE '' END,
		secret_overlap_until = $2, secret = $3, secret_rotated_at = $4,
		secret_expires_at = $5 WHERE id = $6`,
		int64(overlap), until, hashed, now.UnixNano(), unixNanoOrZero(clientrotation.ExpiresAt(now, lifetime)), clientID)
	if err != nil {
		return "", fmt.Errorf("postgres: rotate secret: %w", err)
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
		 WHERE active = 1 AND secret <> '' AND secret_rotated_at > 0 AND secret_rotated_at <= $1
		 ORDER BY id ASC`,
		olderThan.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("postgres: list clients due for rotation: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("postgres: scan client id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// isUniqueViolation reports a Postgres/CRDB unique_violation (SQLSTATE 23505),
// reachable through the pgx stdlib driver via errors.As.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var (
	_ sso.ClientStore                             = (*ClientStore)(nil)
	_ sso.TenantScopedClientStore                 = (*ClientStore)(nil)
	_ core.ClientStoreStats                       = (*ClientStore)(nil)
	_ clientrotation.ClientRotationLister         = (*ClientStore)(nil)
	_ clientrotation.ClientSecretOverlapRotator   = (*ClientStore)(nil)
	_ clientrotation.ClientSecretLifecycleRotator = (*ClientStore)(nil)
)
