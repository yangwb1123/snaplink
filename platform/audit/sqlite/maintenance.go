package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// Prune deletes events with ts_unix_ns < olderThan and returns the
// number of rows removed. Use for audit retention policies — without
// it the table grows monotonically, and after a year of moderate
// traffic the file is large enough to slow Query down even with the
// ts index. Operators typically run this from a cron / systemd
// timer against the same DSN the live server uses (SQLite is
// concurrent-reader / single-writer; Prune blocks new Record calls
// briefly).
//
// Hash-chain caveat: when [audit.WithHashChain] is in use, every
// retained Event's PrevHash points at its predecessor's Hash.
// Pruning the predecessor leaves the FIRST surviving event with
// a dangling PrevHash → [audit.VerifyChain] sees a break at that
// boundary and returns an error. Operators have three options:
//
//  1. Skip Prune entirely (the chain stays whole; the SQLite DB
//     grows; cold-storage offload via Query + delete-by-id outside
//     this helper is the alternative).
//  2. Prune knowing the chain will report a discontinuity at the
//     retention boundary — VerifyChain returns the broken-link
//     error, which operators interpret as "everything after this
//     point is verifiable; everything before was pruned by
//     policy." This is the most common posture for compliance
//     regimes that retain N days of events.
//  3. Pair Prune with re-chaining: dump the surviving events,
//     re-stamp PrevHash on the oldest survivor to point at the
//     [audit.GenesisHash], re-Record. Loses the historical
//     chain-of-custody linkage but produces a clean post-prune
//     state. Not exposed as an API here — operators run a custom
//     migration when they want that posture.
//
// olderThan in the past prunes events older than the timestamp;
// olderThan in the future returns rows-affected=total-row-count
// (the table is wiped). Pass time.Time{} for a no-op (returns 0).
func (s *Sink) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("audit/sqlite: closed")
	}
	if olderThan.IsZero() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE ts_unix_ns < ?`, olderThan.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("audit/sqlite: prune: %w", err)
	}
	return res.RowsAffected()
}

// LastHash returns the Hash of the most recently recorded event so an
// audit.Recorder constructed with audit.WithHashChain() can RESUME the
// tamper-evident chain across a process restart instead of starting a
// fresh genesis at every boot (which audit.VerifyChain would read as a
// chain break at the restart seam). Returns "" on an empty table so the
// chain seeds at genesis.
//
// "Most recent" is ts_unix_ns DESC tie-broken by rowid DESC: the chain
// is stamped in Record order, and rowid is SQLite's monotonic insertion
// counter, so the tie-break recovers true insertion order when two
// events share a nanosecond (back-to-back records under a coarse clock).
// Implements the optional audit.ChainTip extension.
func (s *Sink) LastHash(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("audit/sqlite: closed")
	}
	var hash sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_events ORDER BY ts_unix_ns DESC, rowid DESC LIMIT 1`,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("audit/sqlite: last hash: %w", err)
	}
	return hash.String, nil
}

// Append implements audit.CheckpointStore. Sequence is the durable unique
// key; a conflict is returned instead of replacing an existing attestation.
func (s *Sink) Append(ctx context.Context, c *audit.SignedCheckpoint) error {
	if s == nil || s.db == nil {
		return errors.New("audit/sqlite: checkpoint store closed")
	}
	if c == nil {
		return errors.New("audit/sqlite: nil checkpoint")
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO audit_checkpoints (
            sequence, ts_unix_ns, head_hash, prev_hash, signature, signer_key
        ) VALUES (?, ?, ?, ?, ?, ?)`,
		c.Checkpoint.Sequence, c.Checkpoint.Timestamp.UnixNano(),
		c.Checkpoint.HeadHash, c.Checkpoint.PrevHash, c.Signature, c.SignerKey)
	if err != nil {
		return fmt.Errorf("audit/sqlite: append checkpoint sequence %d: %w", c.Checkpoint.Sequence, err)
	}
	return nil
}

// Latest returns the checkpoint with the greatest durable sequence, or nil
// when the checkpoint table is empty.
func (s *Sink) Latest(ctx context.Context) (*audit.SignedCheckpoint, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: checkpoint store closed")
	}
	row := s.db.QueryRowContext(ctx, checkpointSelect+` ORDER BY sequence DESC LIMIT 1`)
	c, err := scanCheckpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: latest checkpoint: %w", err)
	}
	return c, nil
}

// List returns checkpoints in ascending sequence order. The since bound is
// inclusive and a non-positive limit leaves the result unbounded.
func (s *Sink) List(ctx context.Context, since time.Time, limit int) ([]*audit.SignedCheckpoint, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: checkpoint store closed")
	}
	query := checkpointSelect
	var args []any
	if !since.IsZero() {
		query += ` WHERE ts_unix_ns >= ?`
		args = append(args, since.UnixNano())
	}
	query += ` ORDER BY sequence ASC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: list checkpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*audit.SignedCheckpoint, 0)
	for rows.Next() {
		c, err := scanCheckpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("audit/sqlite: scan checkpoint: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit/sqlite: checkpoint rows: %w", err)
	}
	return out, nil
}

const checkpointSelect = `SELECT sequence, ts_unix_ns, head_hash, prev_hash, signature, signer_key FROM audit_checkpoints`

type checkpointScanner interface {
	Scan(dest ...any) error
}

func scanCheckpoint(row checkpointScanner) (*audit.SignedCheckpoint, error) {
	var (
		sequence, timestamp  int64
		headHash, prevHash   string
		signature, signerKey []byte
	)
	if err := row.Scan(&sequence, &timestamp, &headHash, &prevHash, &signature, &signerKey); err != nil {
		return nil, err
	}
	return &audit.SignedCheckpoint{
		Checkpoint: audit.Checkpoint{
			Sequence: sequence, Timestamp: time.Unix(0, timestamp).UTC(),
			HeadHash: headHash, PrevHash: prevHash,
		},
		Signature: cloneBytes(signature), SignerKey: cloneBytes(signerKey),
	}, nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte{}, in...)
}

// newEventID — same shape as audit.MemorySink uses, kept private
// here so the sink package doesn't depend on an exported helper.
func newEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Compile-time interface assertions.
var (
	_ audit.Sink            = (*Sink)(nil)
	_ audit.FacetQuerier    = (*Sink)(nil)
	_ audit.BatchSink       = (*Sink)(nil)
	_ audit.ChainTip        = (*Sink)(nil)
	_ audit.CheckpointStore = (*Sink)(nil)
)
