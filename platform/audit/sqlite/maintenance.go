package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/audit"
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

// newEventID — same shape as audit.MemorySink uses, kept private
// here so the sink package doesn't depend on an exported helper.
func newEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Compile-time interface assertions.
var (
	_ audit.Sink         = (*Sink)(nil)
	_ audit.FacetQuerier = (*Sink)(nil)
	_ audit.BatchSink    = (*Sink)(nil)
	_ audit.ChainTip     = (*Sink)(nil)
)
