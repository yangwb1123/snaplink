package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
)

// connectionDomainClaimsSchema is migration v2: the per-(connection,domain)
// ownership-claim table. connection_domains remains the verified-only routing
// index (written solely by promoteDomainTx); this table records every claim's
// pending/verified status and its challenge token.
const connectionDomainClaimsSchema = `
CREATE TABLE IF NOT EXISTS connection_domain_claims (
    connection_id TEXT NOT NULL,
    domain        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    token         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    verified_at   TEXT,
    PRIMARY KEY (connection_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_connection_domain_claims_domain ON connection_domain_claims(domain);
`

// reconcileDomainsTx aligns connID's claims + routing with the declared domains,
// inside the caller's Upsert transaction. Default mode claims-and-promotes every
// declared domain (byte-identical last-write-wins routing); hardened mode leaves
// a new claim pending so an unproven Upsert cannot steal a verified owner.
func (s *Store) reconcileDomainsTx(ctx context.Context, tx *sql.Tx, connID string, domains []string) error {
	desired := normalizedDomainSet(domains)
	if err := dropUndeclaredClaimsTx(ctx, tx, connID, desired); err != nil {
		return err
	}
	for d := range desired {
		if err := ensureClaimTx(ctx, tx, connID, d); err != nil {
			return err
		}
		if !s.cfg.DomainVerificationRequired {
			if err := promoteDomainTx(ctx, tx, connID, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropUndeclaredClaimsTx removes connID's claims for domains it no longer
// declares and clears any routing entry it owned for them.
func dropUndeclaredClaimsTx(ctx context.Context, tx *sql.Tx, connID string, desired map[string]struct{}) error {
	rows, err := tx.QueryContext(ctx, `SELECT domain FROM connection_domain_claims WHERE connection_id = ?`, connID)
	if err != nil {
		return fmt.Errorf("sqlite: list claims: %w", err)
	}
	var existing []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite: scan claim domain: %w", err)
		}
		existing = append(existing, d)
	}
	// Close the cursor before issuing writes on the same single-connection tx.
	if err := rows.Close(); err != nil {
		return err
	}
	for _, d := range existing {
		if _, ok := desired[d]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM connection_domain_claims WHERE connection_id=? AND domain=?`, connID, d); err != nil {
			return fmt.Errorf("sqlite: drop claim: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM connection_domains WHERE domain=? AND connection_id=?`, d, connID); err != nil {
			return fmt.Errorf("sqlite: drop routing: %w", err)
		}
	}
	return nil
}

// ensureClaimTx inserts a fresh pending claim (new token) for (connID, domain)
// if none exists; an existing claim is left untouched (idempotent re-Upsert).
func ensureClaimTx(ctx context.Context, tx *sql.Tx, connID, domain string) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM connection_domain_claims WHERE connection_id=? AND domain=?`, connID, domain).Scan(&one)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("sqlite: claim lookup: %w", err)
	}
	tok, err := connections.GenerateDomainToken()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO connection_domain_claims (connection_id, domain, status, token, created_at) VALUES (?,?,?,?,?)`,
		connID, domain, string(connections.DomainPending), tok, nowRFC3339()); err != nil {
		return fmt.Errorf("sqlite: insert claim: %w", err)
	}
	return nil
}

// promoteDomainTx marks connID's claim verified, demotes any other verified
// owner of the domain, and installs connID as the routing owner.
func promoteDomainTx(ctx context.Context, tx *sql.Tx, connID, domain string) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE connection_domain_claims SET status=?, verified_at=NULL WHERE domain=? AND connection_id<>? AND status=?`,
		string(connections.DomainPending), domain, connID, string(connections.DomainVerified)); err != nil {
		return fmt.Errorf("sqlite: demote claims: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE connection_domain_claims SET status=?, verified_at=? WHERE connection_id=? AND domain=?`,
		string(connections.DomainVerified), nowRFC3339(), connID, domain); err != nil {
		return fmt.Errorf("sqlite: verify claim: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO connection_domains (domain, connection_id) VALUES (?, ?)
		 ON CONFLICT(domain) DO UPDATE SET connection_id=excluded.connection_id`,
		domain, connID); err != nil {
		return fmt.Errorf("sqlite: route domain: %w", err)
	}
	return nil
}

func (s *Store) DomainClaim(ctx context.Context, connID, domain string) (*connections.DomainVerification, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT connection_id, domain, status, token, created_at, verified_at
		 FROM connection_domain_claims WHERE connection_id=? AND domain=?`, connID, normDomain(domain))
	claim, err := s.scanClaim(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connections.ErrNoDomainClaim
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: domain claim: %w", err)
	}
	return claim, nil
}

func (s *Store) DomainClaims(ctx context.Context, connID string) ([]*connections.DomainVerification, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT connection_id, domain, status, token, created_at, verified_at
		 FROM connection_domain_claims WHERE connection_id=? ORDER BY domain`, connID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: domain claims: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*connections.DomainVerification
	for rows.Next() {
		claim, err := s.scanClaim(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan claim: %w", err)
		}
		out = append(out, claim)
	}
	return out, rows.Err()
}

func (s *Store) VerifyDomain(ctx context.Context, connID, domain string) error {
	d := normDomain(domain)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM connection_domain_claims WHERE connection_id=? AND domain=?`, connID, d).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return connections.ErrNoDomainClaim
	}
	if err != nil {
		return fmt.Errorf("sqlite: claim lookup: %w", err)
	}
	if err := promoteDomainTx(ctx, tx, connID, d); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyDomainWithToken uses a conditional claim update before promotion so
// the DNS proof can only authorize the claim carrying the proven token. The
// conditional update and routing changes commit as one transaction.
func (s *Store) VerifyDomainWithToken(ctx context.Context, connID, domain, token string) (bool, error) {
	d := normDomain(domain)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx,
		`UPDATE connection_domain_claims SET status=?, verified_at=?
		 WHERE connection_id=? AND domain=? AND token=?`,
		string(connections.DomainVerified), nowRFC3339(), connID, d, token)
	if err != nil {
		return false, fmt.Errorf("sqlite: verify claim token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlite: verify claim token rows: %w", err)
	}
	if affected == 0 {
		var one int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM connection_domain_claims WHERE connection_id=? AND domain=?`, connID, d).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return false, connections.ErrNoDomainClaim
		}
		if err != nil {
			return false, fmt.Errorf("sqlite: claim lookup: %w", err)
		}
		return false, nil
	}
	if err := promoteDomainTx(ctx, tx, connID, d); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// scanClaim reads a claim row and derives its public Record from the store's
// configured prefix.
func (s *Store) scanClaim(sc scanner) (*connections.DomainVerification, error) {
	var (
		claim             connections.DomainVerification
		status, createdAt string
		verifiedAt        sql.NullString
	)
	if err := sc.Scan(&claim.ConnectionID, &claim.Domain, &status, &claim.Token, &createdAt, &verifiedAt); err != nil {
		return nil, err
	}
	claim.Status = connections.DomainStatus(status)
	claim.CreatedAt = parseTime(createdAt)
	if verifiedAt.Valid {
		claim.VerifiedAt = parseTime(verifiedAt.String)
	}
	claim.Record = connections.DomainVerificationRecordName(s.cfg.RecordPrefix, claim.Domain)
	return &claim, nil
}

func normDomain(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func normalizedDomainSet(domains []string) map[string]struct{} {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if nd := normDomain(d); nd != "" {
			set[nd] = struct{}{}
		}
	}
	return set
}
