// Package sqlite is the SQLite-backed threataction.ThreatPolicyStore — the
// multi-replica durable peer of threataction/memory.ThreatPolicyStore. The
// memory store loses every admin-authored policy on restart; this backend
// persists them so a threat-response policy list survives a redeploy and is
// shared across replicas pointed at the same database file.
//
// A single table holds the whole ThreatPolicy as a JSON blob keyed by name:
// ThreatPolicy nests two optional sub-structs (RateLimit, Conditions) that
// nothing ever queries by SQL WHERE clause (the executor loads the full list
// via List and matches in Go — see threataction/executor.go), so normalizing
// them into columns would only add migration surface with no query benefit.
// This mirrors how sibling stores (domains/connections/sqlite, .../
// permissions/sqlite) push slice/map-shaped fields (domains, config,
// permissions_json) into a JSON column rather than a joined table.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite" // register the "sqlite" driver name (pure-Go, no CGO).
)

const policySchema = `
CREATE TABLE IF NOT EXISTS threat_policies (
    name        TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL DEFAULT '{}'
);
`

var policyMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: policySchema},
}

// ThreatPolicyStore is the SQLite threataction.ThreatPolicyStore.
type ThreatPolicyStore struct {
	db *sql.DB
}

var _ threataction.ThreatPolicyStore = (*ThreatPolicyStore)(nil)

// New opens dsn, migrates, and returns the store.
func New(dsn string) (*ThreatPolicyStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("threataction/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("threataction/sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "threat_policies", policyMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("threataction/sqlite: migrate: %w", err)
	}
	return &ThreatPolicyStore{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB (shared-pool deployments). Caller owns
// the connection lifecycle.
func NewWithDB(db *sql.DB) (*ThreatPolicyStore, error) {
	if err := migrate.Run(context.Background(), db, "threat_policies", policyMigrations); err != nil {
		return nil, fmt.Errorf("threataction/sqlite: migrate: %w", err)
	}
	return &ThreatPolicyStore{db: db}, nil
}

// Close releases the connection. Idempotent.
func (s *ThreatPolicyStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the *sql.DB for the storage-health schema reporter.
func (s *ThreatPolicyStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *ThreatPolicyStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("threataction/sqlite: store closed")
	}
	return s.db.PingContext(ctx)
}

// List returns every policy, sorted by name (deterministic ordering for
// first-match-wins evaluation) — matches memory.ThreatPolicyStore.List.
func (s *ThreatPolicyStore) List(ctx context.Context) ([]threataction.ThreatPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_json FROM threat_policies ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("threataction/sqlite: list policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]threataction.ThreatPolicy, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("threataction/sqlite: scan policy: %w", err)
		}
		p, err := unmarshalPolicy(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get returns a single policy by name. Returns threataction.ErrPolicyNotFound
// when the policy doesn't exist — matches memory.ThreatPolicyStore.Get.
func (s *ThreatPolicyStore) Get(ctx context.Context, name string) (*threataction.ThreatPolicy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT policy_json FROM threat_policies WHERE name = ?`, name)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threataction.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("threataction/sqlite: get policy: %w", err)
	}
	p, err := unmarshalPolicy(raw)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Put upserts a policy by name. If a policy with the same name already
// exists, it is replaced — matches memory.ThreatPolicyStore.Put.
func (s *ThreatPolicyStore) Put(ctx context.Context, policy threataction.ThreatPolicy) error {
	b, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("threataction/sqlite: marshal policy: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
        INSERT INTO threat_policies (name, policy_json)
        VALUES (?, ?)
        ON CONFLICT(name) DO UPDATE SET policy_json = excluded.policy_json`,
		policy.Name, string(b)); err != nil {
		return fmt.Errorf("threataction/sqlite: put policy: %w", err)
	}
	return nil
}

// Delete removes a policy by name. Returns threataction.ErrPolicyNotFound
// when the policy doesn't exist — matches memory.ThreatPolicyStore.Delete.
func (s *ThreatPolicyStore) Delete(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_policies WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("threataction/sqlite: delete policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("threataction/sqlite: rows affected: %w", err)
	}
	if n == 0 {
		return threataction.ErrPolicyNotFound
	}
	return nil
}

func unmarshalPolicy(raw string) (threataction.ThreatPolicy, error) {
	var p threataction.ThreatPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return threataction.ThreatPolicy{}, fmt.Errorf("threataction/sqlite: unmarshal policy: %w", err)
	}
	return p, nil
}
