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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/migrate"

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

func NewClientStoreWithDB(db *sql.DB) *ClientStore {
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
	if !isBcryptHash(secret) && secret != "" {
		h, err := hashClientSecret(secret)
		if err != nil {
			return fmt.Errorf("sqlite: hash secret: %w", err)
		}
		secret = h
	}
	rat := c.RegistrationAccessToken
	if !isBcryptHash(rat) && rat != "" {
		h, err := hashClientSecret(rat)
		if err != nil {
			return fmt.Errorf("sqlite: hash rat: %w", err)
		}
		rat = h
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	reqURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	authzDetails, _ := json.Marshal(c.AllowedAuthorizationDetailsTypes)
	pkceM, _ := json.Marshal(c.AllowedPKCEMethods)
	attrs, _ := json.Marshal(c.Attributes)

	_, err := s.db.ExecContext(ctx, `
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
            frontchannel_logout_uri, federation, attributes
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
            ?, ?, ?
        )`,
		c.ID, secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		string(jwks), string(resources), string(reqURIs), rat,
		string(postLogout), string(authzDetails),
		int64(c.RefreshTokenTTL), int64(c.AccessTokenTTL), string(pkceM),
		boolToInt(c.RequireSignedRequestObject), boolToInt(c.RequirePAR),
		int64(c.DeviceCodeTTL), int64(c.DeviceCodePollInterval),
		c.UserinfoSignedResponseAlg,
		c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc,
		c.BackchannelLogoutURI, c.SubjectType, c.SectorIdentifierURI,
		c.FrontchannelLogoutURI, boolToInt(c.Federation), string(attrs),
	)
	if err != nil {
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
	// Re-hash only when the value isn't already a bcrypt hash.
	secret := c.Secret
	if !isBcryptHash(secret) && secret != "" {
		h, err := hashClientSecret(secret)
		if err != nil {
			return fmt.Errorf("sqlite: hash secret: %w", err)
		}
		secret = h
	}
	rat := c.RegistrationAccessToken
	if !isBcryptHash(rat) && rat != "" {
		h, err := hashClientSecret(rat)
		if err != nil {
			return fmt.Errorf("sqlite: hash rat: %w", err)
		}
		rat = h
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	reqURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	authzDetails, _ := json.Marshal(c.AllowedAuthorizationDetailsTypes)
	pkceM, _ := json.Marshal(c.AllowedPKCEMethods)
	attrs, _ := json.Marshal(c.Attributes)

	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO clients (
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
            frontchannel_logout_uri, federation, attributes
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
            ?, ?, ?
        )`,
		c.ID, secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		string(jwks), string(resources), string(reqURIs), rat,
		string(postLogout), string(authzDetails),
		int64(c.RefreshTokenTTL), int64(c.AccessTokenTTL), string(pkceM),
		boolToInt(c.RequireSignedRequestObject), boolToInt(c.RequirePAR),
		int64(c.DeviceCodeTTL), int64(c.DeviceCodePollInterval),
		c.UserinfoSignedResponseAlg,
		c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc,
		c.BackchannelLogoutURI, c.SubjectType, c.SectorIdentifierURI,
		c.FrontchannelLogoutURI, boolToInt(c.Federation), string(attrs),
	)
	if err != nil {
		return fmt.Errorf("sqlite: put client: %w", err)
	}
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	secret := c.Secret
	if !isBcryptHash(secret) && secret != "" {
		h, err := hashClientSecret(secret)
		if err != nil {
			return fmt.Errorf("sqlite: hash secret: %w", err)
		}
		secret = h
	}
	rat := c.RegistrationAccessToken
	if !isBcryptHash(rat) && rat != "" {
		h, err := hashClientSecret(rat)
		if err != nil {
			return fmt.Errorf("sqlite: hash rat: %w", err)
		}
		rat = h
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	reqURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	authzDetails, _ := json.Marshal(c.AllowedAuthorizationDetailsTypes)
	pkceM, _ := json.Marshal(c.AllowedPKCEMethods)
	attrs, _ := json.Marshal(c.Attributes)

	res, err := s.db.ExecContext(ctx, `
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
            frontchannel_logout_uri = ?, federation = ?, attributes = ?
        WHERE id = ?`,
		secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		string(jwks), string(resources), string(reqURIs), rat,
		string(postLogout), string(authzDetails),
		int64(c.RefreshTokenTTL), int64(c.AccessTokenTTL), string(pkceM),
		boolToInt(c.RequireSignedRequestObject), boolToInt(c.RequirePAR),
		int64(c.DeviceCodeTTL), int64(c.DeviceCodePollInterval),
		c.UserinfoSignedResponseAlg,
		c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc,
		c.BackchannelLogoutURI, c.SubjectType, c.SectorIdentifierURI,
		c.FrontchannelLogoutURI, boolToInt(c.Federation), string(attrs),
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
	plain, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plain)
	if err != nil {
		return "", fmt.Errorf("sqlite: hash rotated secret: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE clients SET secret = ? WHERE id = ?`, hashed, clientID)
	if err != nil {
		return "", fmt.Errorf("sqlite: rotate secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sso.ErrNoSuchClient
	}
	return plain, nil
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
        frontchannel_logout_uri, federation, attributes
        FROM clients`
}

func clientSelectByCol(col string) string {
	return clientSelectAll() + ` WHERE ` + col + ` = ?`
}

func scanClient(s scanner) (*sso.Client, error) {
	var (
		c                                                      sso.Client
		redirects, scopes, auths                               string
		jwksBlob, resources, reqURIs, postLogout, authzDetails string
		pkceM, attrsBlob                                       string
		activeInt, requirePKCEInt                              int64
		requireSROInt, requirePARInt, federationInt            int64
		secret, name, tokenStrategy, tenantID                  string
		rat                                                    string
		refreshTTL, accessTTL, dcTTL, dcPoll                   int64
		userinfoSigAlg                                         string
		idtEncAlg, idtEncEnc, uiEncAlg, uiEncEnc               string
		bclURI, subjectType, sectorURI, fclURI                 string
	)
	if err := s.Scan(
		&c.ID, &secret, &name,
		&redirects, &scopes, &auths,
		&tokenStrategy, &activeInt, &tenantID, &requirePKCEInt,
		&jwksBlob, &resources, &reqURIs, &rat,
		&postLogout, &authzDetails,
		&refreshTTL, &accessTTL, &pkceM,
		&requireSROInt, &requirePARInt,
		&dcTTL, &dcPoll,
		&userinfoSigAlg,
		&idtEncAlg, &idtEncEnc, &uiEncAlg, &uiEncEnc,
		&bclURI, &subjectType, &sectorURI, &fclURI,
		&federationInt, &attrsBlob,
	); err != nil {
		return nil, err
	}
	c.Secret = secret
	c.RegistrationAccessToken = rat
	c.Name = name
	c.TokenStrategy = tokenStrategy
	c.TenantID = tenantID
	c.Active = activeInt != 0
	c.RequirePKCE = requirePKCEInt != 0
	c.RequireSignedRequestObject = requireSROInt != 0
	c.RequirePAR = requirePARInt != 0
	c.Federation = federationInt != 0
	c.RefreshTokenTTL = time.Duration(refreshTTL)
	c.AccessTokenTTL = time.Duration(accessTTL)
	c.DeviceCodeTTL = time.Duration(dcTTL)
	c.DeviceCodePollInterval = time.Duration(dcPoll)
	c.UserinfoSignedResponseAlg = userinfoSigAlg
	c.IDTokenEncryptedResponseAlg = idtEncAlg
	c.IDTokenEncryptedResponseEnc = idtEncEnc
	c.UserinfoEncryptedResponseAlg = uiEncAlg
	c.UserinfoEncryptedResponseEnc = uiEncEnc
	c.BackchannelLogoutURI = bclURI
	c.SubjectType = subjectType
	c.SectorIdentifierURI = sectorURI
	c.FrontchannelLogoutURI = fclURI

	unmarshalJSON := func(blob string, dst any, field string) error {
		if blob == "" || blob == "[]" || blob == "{}" || blob == "null" {
			return nil
		}
		if err := json.Unmarshal([]byte(blob), dst); err != nil {
			return fmt.Errorf("sqlite: unmarshal %s: %w", field, err)
		}
		return nil
	}
	if err := unmarshalJSON(redirects, &c.RedirectURIs, "redirect_uris"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(scopes, &c.AllowedScopes, "allowed_scopes"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(auths, &c.AllowedAuthenticators, "allowed_authenticators"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(jwksBlob, &c.JWKS, "jwks"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(resources, &c.AllowedResources, "allowed_resources"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(reqURIs, &c.AllowedRequestURIs, "allowed_request_uris"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(postLogout, &c.PostLogoutRedirectURIs, "post_logout_redirect_uris"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(authzDetails, &c.AllowedAuthorizationDetailsTypes, "allowed_authorization_details"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(pkceM, &c.AllowedPKCEMethods, "allowed_pkce_methods"); err != nil {
		return nil, err
	}
	if err := unmarshalJSON(attrsBlob, &c.Attributes, "attributes"); err != nil {
		return nil, err
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
