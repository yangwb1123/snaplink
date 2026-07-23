package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/connections/provider"
	"github.com/snaplink/sso/platform/lifecycle/rebac"
	"github.com/snaplink/sso/platform/migrate"
)

// ============================================================================
// ReBAC (Relationship-Based Access Control) Tuple Store
// ============================================================================

const rebacSchema = `
CREATE TABLE IF NOT EXISTS rebac_tuples (
    object   TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject  TEXT NOT NULL,
    PRIMARY KEY (object, relation, subject)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_rebac_tuples_subject ON rebac_tuples(subject);
`

var rebacMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: rebacSchema},
}

// ReBACStore is a SQLite-backed [rebac.RelationTupleStore].
type ReBACStore struct{ db *sql.DB }

// NewReBACStore opens or creates a SQLite ReBAC tuple store at dsn.
func NewReBACStore(dsn string) (*ReBACStore, error) {
	db, err := SharedDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("rebac sqlite: shared db: %w", err)
	}
	s := &ReBACStore{db: db}
	if err := migrate.Run(context.Background(), s.db, "rebac_tuples", rebacMigrations); err != nil {
		return nil, fmt.Errorf("rebac sqlite: migrate: %w", err)
	}
	return s, nil
}

func (s *ReBACStore) Write(_ context.Context, t rebac.Tuple) error {
	if err := t.Validate(); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO rebac_tuples (object, relation, subject) VALUES (?, ?, ?)`,
		t.Object, t.Relation, t.Subject,
	)
	return err
}

func (s *ReBACStore) Delete(_ context.Context, t rebac.Tuple) error {
	_, err := s.db.Exec(
		`DELETE FROM rebac_tuples WHERE object = ? AND relation = ? AND subject = ?`,
		t.Object, t.Relation, t.Subject,
	)
	return err
}

func (s *ReBACStore) Read(_ context.Context, filter rebac.TupleFilter) ([]rebac.Tuple, error) {
	var clauses []string
	var args []any
	if filter.Object != "" {
		clauses = append(clauses, "object = ?")
		args = append(args, filter.Object)
	}
	if filter.Relation != "" {
		clauses = append(clauses, "relation = ?")
		args = append(args, filter.Relation)
	}
	if filter.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, filter.Subject)
	}
	q := `SELECT object, relation, subject FROM rebac_tuples`
	if len(clauses) > 0 {
		q += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rebac.Tuple
	for rows.Next() {
		var t rebac.Tuple
		if err := rows.Scan(&t.Object, &t.Relation, &t.Subject); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []rebac.Tuple{}
	}
	return out, rows.Err()
}

var _ rebac.RelationTupleStore = (*ReBACStore)(nil)

// ============================================================================
// Provider (third-party login) Store
// ============================================================================

const providerSchema = `
CREATE TABLE IF NOT EXISTS providers (
    id           TEXT NOT NULL PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    type         TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    icon_url     TEXT NOT NULL DEFAULT '',
    button_label TEXT NOT NULL DEFAULT '',
    button_color TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    config       TEXT NOT NULL DEFAULT '{}',
    created_at   INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_providers_tenant ON providers(tenant_id);
`

var providerMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: providerSchema},
}

// ProviderStore is a SQLite-backed [provider.Store].
type ProviderStore struct{ db *sql.DB }

// NewProviderStore opens or creates a SQLite provider store at dsn.
func NewProviderStore(dsn string) (*ProviderStore, error) {
	db, err := SharedDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("provider sqlite: shared db: %w", err)
	}
	s := &ProviderStore{db: db}
	if err := migrate.Run(context.Background(), s.db, "providers", providerMigrations); err != nil {
		return nil, fmt.Errorf("provider sqlite: migrate: %w", err)
	}
	return s, nil
}

func (s *ProviderStore) Create(_ context.Context, p *provider.Provider) error {
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO providers (id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.TenantID, string(p.Type), p.DisplayName,
		p.IconURL, p.ButtonLabel, p.ButtonColor, btoi(p.Enabled),
		string(cfg), now, now,
	)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return provider.ErrProviderExists
	}
	return err
}

func (s *ProviderStore) Get(_ context.Context, id string) (*provider.Provider, error) {
	row := s.db.QueryRow(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE id = ?`, id,
	)
	return scanProvider(row)
}

func (s *ProviderStore) Update(_ context.Context, p *provider.Provider) error {
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE providers SET type=?, display_name=?, icon_url=?, button_label=?, button_color=?, enabled=?, config=?, updated_at=?
		 WHERE id=?`,
		string(p.Type), p.DisplayName, p.IconURL, p.ButtonLabel, p.ButtonColor,
		btoi(p.Enabled), string(cfg), now, p.ID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return provider.ErrNoSuchProvider
	}
	return nil
}

func (s *ProviderStore) Delete(_ context.Context, id string) error {
	_, err := s.db.Exec(`DELETE FROM providers WHERE id = ?`, id)
	return err
}

func (s *ProviderStore) ListByTenant(_ context.Context, tenantID string) ([]*provider.Provider, error) {
	rows, err := s.db.Query(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE tenant_id = ? OR tenant_id = '' ORDER BY display_name`, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func (s *ProviderStore) ListGlobal(_ context.Context) ([]*provider.Provider, error) {
	rows, err := s.db.Query(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE tenant_id = '' ORDER BY display_name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func (s *ProviderStore) ListByIDs(_ context.Context, ids []string) ([]*provider.Provider, error) {
	if len(ids) == 0 {
		return []*provider.Provider{}, nil
	}
	args := make([]any, len(ids))
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	q := fmt.Sprintf(
		`SELECT id, tenant_id, type, display_name, icon_url, button_label, button_color, enabled, config, created_at, updated_at
		 FROM providers WHERE id IN (%s)`, strings.Join(ph, ","))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func scanProvider(scanner interface{ Scan(dest ...any) error }) (*provider.Provider, error) {
	var (
		id, tid, ptype, dn, iurl, bl, bc string
		enabled                          int
		cj                               string
		cat, uat                         int64
	)
	if err := scanner.Scan(&id, &tid, &ptype, &dn, &iurl, &bl, &bc, &enabled, &cj, &cat, &uat); err != nil {
		if err == sql.ErrNoRows {
			return nil, provider.ErrNoSuchProvider
		}
		return nil, err
	}
	cfg := make(map[string]string)
	if cj != "" && cj != "{}" {
		json.Unmarshal([]byte(cj), &cfg)
	}
	return &provider.Provider{
		ID: id, TenantID: tid, Type: provider.ProviderType(ptype),
		DisplayName: dn, IconURL: iurl, ButtonLabel: bl, ButtonColor: bc,
		Enabled: enabled != 0, Config: cfg,
		CreatedAt: time.Unix(cat, 0), UpdatedAt: time.Unix(uat, 0),
	}, nil
}

func scanProviders(rows *sql.Rows) ([]*provider.Provider, error) {
	var out []*provider.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []*provider.Provider{}
	}
	return out, rows.Err()
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
