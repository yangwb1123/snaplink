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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

// clientSchema mirrors the in-memory shape — slices + maps are
// JSON blobs since the SDK only ever reads whole rows, never WHERE
// clauses over their internals. The tenant_id index is for
// ListByTenant; otherwise lookups are by id only.
const clientSchema = `
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
    WHERE tenant_id <> '';
`

// clientMigrations is the schema history. v1 is the original ~10-column
// baseline; v2 backfills the SECURITY-LOAD-BEARING fields that earlier
// rounds-tripped only through the in-memory store (so a restart on
// identity.backend=sqlite silently reverted them to zero). Each ADD COLUMN
// carries a NOT NULL DEFAULT matching the field's zero value, so existing
// rows migrate cleanly and an empty/zero client round-trips byte-identically
// to the v1 schema. Forward-only, applied in one BEGIN IMMEDIATE txn by the
// runner.
var clientMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: clientSchema},
	{Version: 2, Name: "client_security_fields", SQL: `
ALTER TABLE clients ADD COLUMN registration_access_token TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN jwks                       TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_resources         TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_request_uris      TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN id_token_enc_alg          TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN id_token_enc_enc          TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_enc_alg          TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_enc_enc          TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN federation                INTEGER NOT NULL DEFAULT 0;
`},
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
	if err := migrate.Run(context.Background(), db, "clients", clientMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate clients: %w", err)
	}
	return &ClientStore{db: db}, nil
}

func NewClientStoreWithDB(db *sql.DB) *ClientStore {
	// Best-effort on the shared-DB path (mirrors the historical contract —
	// this constructor never returned an error).
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
	// compareClientSecret uses bcrypt.CompareHashAndPassword when stored
	// starts with "$2" (a bcrypt hash), falling back to constant-time string
	// compare for plaintext secrets in pre-migration stores. See client_secret.go.
	if !compareClientSecret(c.Secret, clientSecret) {
		return errors.New("invalid client secret")
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
	defer rows.Close()
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
//
// Only id + allowed_scopes are projected — the other discovery-relevant
// client fields (RequirePAR, RequireSignedRequestObject,
// FrontchannelLogoutURI, AllowedAuthorizationDetailsTypes) have no
// column in this backend's schema, so they round-trip as zero values
// and contribute a constant to the digest. Decoding minimal clients
// (no secret, no JSON blobs beyond scopes) keeps Stats strictly cheaper
// than List, and feeding them through the shared
// core.ClientSetFingerprint guarantees the same logical set yields the
// same hash regardless of row order.
func (s *ClientStore) Stats(ctx context.Context) (int, string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, allowed_scopes FROM clients`)
	if err != nil {
		return 0, "", fmt.Errorf("sqlite: stats clients: %w", err)
	}
	defer rows.Close()
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
	defer rows.Close()
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

func (s *ClientStore) Add(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	secret := c.Secret
	if secret != "" && !isBcryptHash(secret) {
		h, err := hashClientSecret(secret)
		if err != nil {
			return fmt.Errorf("sqlite: hash secret: %w", err)
		}
		secret = h
	}
	rat := c.RegistrationAccessToken
	if rat != "" && !isBcryptHash(rat) {
		h, err := hashClientSecret(rat)
		if err != nil {
			return fmt.Errorf("sqlite: hash registration token: %w", err)
		}
		rat = h
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	requestURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO clients (id, secret, name, redirect_uris, allowed_scopes,
            allowed_authenticators, token_strategy, active, tenant_id, require_pkce,
            registration_access_token, jwks, allowed_resources, allowed_request_uris,
            post_logout_redirect_uris, id_token_enc_alg, id_token_enc_enc,
            userinfo_enc_alg, userinfo_enc_enc, federation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		rat, string(jwks), string(resources), string(requestURIs),
		string(postLogout), c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc, boolToInt(c.Federation),
	)
	if err != nil {
		// modernc.org/sqlite returns the constraint code in the error
		// message; UNIQUE on PRIMARY KEY → ErrClientExists per contract.
		if isUniqueViolation(err) {
			return sso.ErrClientExists
		}
		return fmt.Errorf("sqlite: insert client: %w", err)
	}
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	secret := c.Secret
	if secret != "" && !isBcryptHash(secret) {
		h, err := hashClientSecret(secret)
		if err != nil {
			return fmt.Errorf("sqlite: hash secret: %w", err)
		}
		secret = h
	}
	rat := c.RegistrationAccessToken
	if rat != "" && !isBcryptHash(rat) {
		h, err := hashClientSecret(rat)
		if err != nil {
			return fmt.Errorf("sqlite: hash registration token: %w", err)
		}
		rat = h
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	requestURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	res, err := s.db.ExecContext(ctx, `
        UPDATE clients SET secret = ?, name = ?, redirect_uris = ?,
            allowed_scopes = ?, allowed_authenticators = ?,
            token_strategy = ?, active = ?, tenant_id = ?, require_pkce = ?,
            registration_access_token = ?, jwks = ?, allowed_resources = ?,
            allowed_request_uris = ?, post_logout_redirect_uris = ?,
            id_token_enc_alg = ?, id_token_enc_enc = ?, userinfo_enc_alg = ?,
            userinfo_enc_enc = ?, federation = ?
        WHERE id = ?`,
		secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		rat, string(jwks), string(resources),
		string(requestURIs), string(postLogout),
		c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc, boolToInt(c.Federation),
		c.ID,
	)
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
	plaintext, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plaintext)
	if err != nil {
		return "", fmt.Errorf("sqlite: hash rotated secret: %w", err)
	}
	// Store the hash; return the plaintext (one-time reveal to the caller).
	res, err := s.db.ExecContext(ctx,
		`UPDATE clients SET secret = ? WHERE id = ?`, hashed, clientID)
	if err != nil {
		return "", fmt.Errorf("sqlite: rotate secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sso.ErrNoSuchClient
	}
	return plaintext, nil
}

// clientSelectAll keeps the column list in one place so Add / Update /
// scan can't drift.
func clientSelectAll() string {
	return `SELECT id, secret, name, redirect_uris, allowed_scopes,
        allowed_authenticators, token_strategy, active, tenant_id, require_pkce,
        registration_access_token, jwks, allowed_resources, allowed_request_uris,
        post_logout_redirect_uris, id_token_enc_alg, id_token_enc_enc,
        userinfo_enc_alg, userinfo_enc_enc, federation
        FROM clients`
}

func clientSelectByCol(col string) string {
	return clientSelectAll() + ` WHERE ` + col + ` = ?`
}

func scanClient(s scanner) (*sso.Client, error) {
	var (
		c                                     sso.Client
		redirects, scopes, auths              string
		activeInt, requirePKCEInt             int64
		secret, name, tokenStrategy, tenantID string
		jwks, resources, requestURIs          string
		postLogout, regToken                  string
		idTokenEncAlg, idTokenEncEnc          string
		userinfoEncAlg, userinfoEncEnc        string
		federationInt                         int64
	)
	if err := s.Scan(
		&c.ID, &secret, &name,
		&redirects, &scopes, &auths,
		&tokenStrategy, &activeInt, &tenantID, &requirePKCEInt,
		&regToken, &jwks, &resources, &requestURIs,
		&postLogout, &idTokenEncAlg, &idTokenEncEnc,
		&userinfoEncAlg, &userinfoEncEnc, &federationInt,
	); err != nil {
		return nil, err
	}
	c.Secret = secret
	c.Name = name
	c.TokenStrategy = tokenStrategy
	c.TenantID = tenantID
	c.Active = activeInt != 0
	c.RequirePKCE = requirePKCEInt != 0
	c.RegistrationAccessToken = regToken
	c.IDTokenEncryptedResponseAlg = idTokenEncAlg
	c.IDTokenEncryptedResponseEnc = idTokenEncEnc
	c.UserinfoEncryptedResponseAlg = userinfoEncAlg
	c.UserinfoEncryptedResponseEnc = userinfoEncEnc
	c.Federation = federationInt != 0
	if redirects != "" && redirects != "[]" {
		if err := json.Unmarshal([]byte(redirects), &c.RedirectURIs); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal redirect_uris: %w", err)
		}
	}
	if scopes != "" && scopes != "[]" {
		if err := json.Unmarshal([]byte(scopes), &c.AllowedScopes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_scopes: %w", err)
		}
	}
	if auths != "" && auths != "[]" {
		if err := json.Unmarshal([]byte(auths), &c.AllowedAuthenticators); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_authenticators: %w", err)
		}
	}
	if jwks != "" && jwks != "[]" {
		if err := json.Unmarshal([]byte(jwks), &c.JWKS); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal jwks: %w", err)
		}
	}
	if resources != "" && resources != "[]" {
		if err := json.Unmarshal([]byte(resources), &c.AllowedResources); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_resources: %w", err)
		}
	}
	if requestURIs != "" && requestURIs != "[]" {
		if err := json.Unmarshal([]byte(requestURIs), &c.AllowedRequestURIs); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_request_uris: %w", err)
		}
	}
	if postLogout != "" && postLogout != "[]" {
		if err := json.Unmarshal([]byte(postLogout), &c.PostLogoutRedirectURIs); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal post_logout_redirect_uris: %w", err)
		}
	}
	return &c, nil
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
	_ sso.ClientStore             = (*ClientStore)(nil)
	_ sso.TenantScopedClientStore = (*ClientStore)(nil)
	_ core.ClientStoreStats       = (*ClientStore)(nil)
)
