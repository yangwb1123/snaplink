// Package sqlite is the SQLite-backed tokenexchange.ChainStore — the
// multi-replica durable peer of tokenexchange/memory.ChainStore. The memory
// store loses every recorded RFC 8693 delegation hop on restart; this
// backend persists them so an operator can still answer "what produced
// token X" or "how deep did any chain in this deployment ever get" after a
// redeploy, and so the recorded history is shared across replicas pointed
// at the same database file.
//
// One row per hop, columns rather than a JSON blob (unlike
// domains/threataction/sqlite): every field is a flat scalar the admin read
// endpoint queries by by parent_jti (GetDescendants) or by jti (GetChain),
// so normalizing into columns + an index gives a real query benefit here,
// unlike ThreatPolicy's nested RateLimit/Conditions sub-structs.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite" // register the "sqlite" driver name (pure-Go, no CGO).
)

const chainSchema = `
CREATE TABLE IF NOT EXISTS tokenexchange_chain_hops (
    jti           TEXT PRIMARY KEY,
    parent_jti    TEXT NOT NULL DEFAULT '',
    subject_id    TEXT NOT NULL DEFAULT '',
    actor_subject TEXT NOT NULL DEFAULT '',
    client_id     TEXT NOT NULL DEFAULT '',
    chain_depth   INTEGER NOT NULL DEFAULT 0,
    recorded_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokenexchange_chain_hops_parent
    ON tokenexchange_chain_hops(parent_jti);
`

var chainMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: chainSchema},
}

// maxChainWalk bounds both GetChain's backward walk and GetDescendants'
// forward walk — a defensive safety net against a corrupted/cyclic
// parent_jti graph (RecordHop never creates one; a store populated by
// direct writes outside this package could). Generously above
// tokengrant.MaxActChainDepth (10) since a store may outlive many
// re-wirings of that cap.
const maxChainWalk = 1000

// ChainStore is the SQLite tokenexchange.ChainStore.
type ChainStore struct {
	db *sql.DB
}

var _ tokenexchange.ChainStore = (*ChainStore)(nil)

// New opens dsn, migrates, and returns the store.
func New(dsn string) (*ChainStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tokenexchange/sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "tokenexchange_chain_hops", chainMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tokenexchange/sqlite: migrate: %w", err)
	}
	return &ChainStore{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB (shared-pool deployments). Caller owns
// the connection lifecycle.
func NewWithDB(db *sql.DB) (*ChainStore, error) {
	if err := migrate.Run(context.Background(), db, "tokenexchange_chain_hops", chainMigrations); err != nil {
		return nil, fmt.Errorf("tokenexchange/sqlite: migrate: %w", err)
	}
	return &ChainStore{db: db}, nil
}

// Close releases the connection. Idempotent.
func (s *ChainStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the *sql.DB for the storage-health schema reporter.
func (s *ChainStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *ChainStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("tokenexchange/sqlite: store closed")
	}
	return s.db.PingContext(ctx)
}

// RecordHop implements [tokenexchange.ChainStore]. Upserts on jti — JTIs are
// unique per mint so this should always be a fresh INSERT, but ON CONFLICT
// keeps a retried RecordHop call idempotent rather than erroring.
func (s *ChainStore) RecordHop(ctx context.Context, hop tokenexchange.ChainHop) error {
	if hop.JTI == "" {
		return errors.New("tokenexchange/sqlite: ChainHop.JTI is required")
	}
	recordedAt := hop.RecordedAt
	if recordedAt.IsZero() {
		recordedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO tokenexchange_chain_hops
            (jti, parent_jti, subject_id, actor_subject, client_id, chain_depth, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(jti) DO UPDATE SET
            parent_jti = excluded.parent_jti,
            subject_id = excluded.subject_id,
            actor_subject = excluded.actor_subject,
            client_id = excluded.client_id,
            chain_depth = excluded.chain_depth,
            recorded_at = excluded.recorded_at`,
		hop.JTI, hop.ParentJTI, hop.SubjectID, hop.ActorSubject, hop.ClientID, hop.ChainDepth, recordedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("tokenexchange/sqlite: record hop: %w", err)
	}
	return nil
}

// GetChain implements [tokenexchange.ChainStore]: walks parent_jti backward
// from jti to the root, one row lookup per hop (bounded by maxChainWalk),
// then reverses so the result reads oldest (root) first.
func (s *ChainStore) GetChain(ctx context.Context, jti string) ([]tokenexchange.ChainHop, error) {
	var chain []tokenexchange.ChainHop
	seen := make(map[string]bool)
	cur := jti
	for cur != "" && !seen[cur] && len(chain) < maxChainWalk {
		seen[cur] = true
		hop, ok, err := s.getHop(ctx, cur)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		chain = append(chain, hop)
		cur = hop.ParentJTI
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// getHop reads one row by jti. ok=false (no error) when jti isn't recorded.
func (s *ChainStore) getHop(ctx context.Context, jti string) (tokenexchange.ChainHop, bool, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT jti, parent_jti, subject_id, actor_subject, client_id, chain_depth, recorded_at
        FROM tokenexchange_chain_hops WHERE jti = ?`, jti)
	hop, nanos, err := scanHop(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tokenexchange.ChainHop{}, false, nil
		}
		return tokenexchange.ChainHop{}, false, fmt.Errorf("tokenexchange/sqlite: get hop: %w", err)
	}
	hop.RecordedAt = time.Unix(0, nanos)
	return hop, true, nil
}

// GetDescendants implements [tokenexchange.ChainStore]: a breadth-first walk
// forward over parent_jti (one query per visited node, bounded by
// maxChainWalk total visited nodes), collecting every hop transitively
// descended from jti, newest-recorded first, bounded to at most limit rows
// (limit <= 0 = no cap).
func (s *ChainStore) GetDescendants(ctx context.Context, jti string, limit int) ([]tokenexchange.ChainHop, error) {
	visited := map[string]bool{jti: true}
	queue := []string{jti}
	var out []tokenexchange.ChainHop
	for len(queue) > 0 && len(visited) < maxChainWalk {
		cur := queue[0]
		queue = queue[1:]
		children, err := s.getChildren(ctx, cur)
		if err != nil {
			return nil, err
		}
		for _, hop := range children {
			if visited[hop.JTI] {
				continue
			}
			visited[hop.JTI] = true
			out = append(out, hop)
			queue = append(queue, hop.JTI)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RecordedAt.After(out[j].RecordedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// getChildren returns every recorded hop whose parent_jti is parentJTI.
func (s *ChainStore) getChildren(ctx context.Context, parentJTI string) ([]tokenexchange.ChainHop, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT jti, parent_jti, subject_id, actor_subject, client_id, chain_depth, recorded_at
        FROM tokenexchange_chain_hops WHERE parent_jti = ?`, parentJTI)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange/sqlite: get children: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []tokenexchange.ChainHop
	for rows.Next() {
		hop, nanos, serr := scanHop(rows)
		if serr != nil {
			return nil, fmt.Errorf("tokenexchange/sqlite: scan child: %w", serr)
		}
		hop.RecordedAt = time.Unix(0, nanos)
		out = append(out, hop)
	}
	return out, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanHop scans the 7-column hop projection shared by getHop/getChildren.
// recorded_at comes back as raw UnixNano — callers convert to time.Time.
func scanHop(row rowScanner) (tokenexchange.ChainHop, int64, error) {
	var hop tokenexchange.ChainHop
	var nanos int64
	err := row.Scan(&hop.JTI, &hop.ParentJTI, &hop.SubjectID, &hop.ActorSubject, &hop.ClientID, &hop.ChainDepth, &nanos)
	return hop, nanos, err
}
