package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/oauth"
)

// cibaSchema persists poll-mode CIBA backchannel auth requests across
// the Issue → out-of-band confirm → /token poll lifecycle. Same
// single-replica-only fallback the in-memory peer suffers from; this
// peer makes cluster deploys workable — an Issue on replica A is
// resolvable by the callback on replica B and the poll on replica C.
//
// Status transitions are enforced in SetStatus via UPDATE ... WHERE
// status = 'pending' (only pending entries can change), matching the
// push-approval store's "refuse re-resolution" behavior.
const cibaSchema = `
CREATE TABLE IF NOT EXISTS ciba_requests (
    auth_req_id     TEXT    PRIMARY KEY,
    client_id       TEXT    NOT NULL,
    subject_id      TEXT    NOT NULL,
    provider        TEXT    NOT NULL,
    scopes          TEXT    NOT NULL,
    acr_values      TEXT    NOT NULL,
    binding_message TEXT    NOT NULL,
    resources       TEXT    NOT NULL,
    nonce           TEXT    NOT NULL,
    request_context BLOB,
    status          TEXT    NOT NULL,
    interval_ns     INTEGER NOT NULL,
    last_poll       INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciba_requests_expires_at
    ON ciba_requests(expires_at);
`

// cibaMigrations is the versioned schema history for the CIBA store.
// v1 = the baseline above; append v2+ (SQL or Func) for future column
// or index changes per the §4 migrate framework.
var cibaMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: cibaSchema},
}

// CIBAStore is the SQLite-backed [oauth.CIBAStore]. Suitable for
// multi-replica deployments — every replica reads + writes the same
// table so the issue / callback / poll legs can land on any replica.
type CIBAStore struct {
	db *sql.DB
}

// NewCIBAStore opens dsn, migrates the schema, returns the store.
// Caller owns Close().
func NewCIBAStore(dsn string) (*CIBAStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "ciba_requests", cibaMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate ciba_requests: %w", err)
	}
	return &CIBAStore{db: db}, nil
}

// NewCIBAStoreWithDB wraps an existing *sql.DB. Caller owns the
// connection lifecycle.
func NewCIBAStoreWithDB(db *sql.DB) (*CIBAStore, error) {
	if err := migrate.Run(context.Background(), db, "ciba_requests", cibaMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate ciba_requests: %w", err)
	}
	return &CIBAStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *CIBAStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *CIBAStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: ciba store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue mints an auth_req_id, persists a PENDING request. SubjectID +
// ClientID required; either empty → ErrCIBARequestInvalid.
func (s *CIBAStore) Issue(ctx context.Context, req *oauth.CIBARequest) (string, error) {
	if req == nil || req.SubjectID == "" || req.ClientID == "" {
		return "", oauth.ErrCIBARequestInvalid
	}
	id, err := defaultimpl.GenerateCIBAAuthReqID()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO ciba_requests (
            auth_req_id, client_id, subject_id, provider, scopes,
            acr_values, binding_message, resources, nonce,
            request_context, status, interval_ns, last_poll,
            created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.ClientID, req.SubjectID, req.Provider,
		strings.Join(req.Scopes, " "), req.ACRValues, req.BindingMessage,
		strings.Join(req.Resources, " "), req.Nonce, req.RequestContext,
		string(oauth.CIBAPending), int64(req.Interval), int64(0),
		req.CreatedAt.UnixNano(), req.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return "", fmt.Errorf("sqlite: insert ciba_request: %w", err)
	}
	return id, nil
}

// Get returns the request; missing / expired collapse to
// ErrCIBARequestNotFound (anti-enumeration parity).
func (s *CIBAStore) Get(ctx context.Context, authReqID string) (*oauth.CIBARequest, error) {
	if authReqID == "" {
		return nil, oauth.ErrCIBARequestNotFound
	}
	row := s.db.QueryRowContext(ctx, `
        SELECT client_id, subject_id, provider, scopes, acr_values,
               binding_message, resources, nonce, request_context,
               status, interval_ns, last_poll, created_at, expires_at
        FROM ciba_requests WHERE auth_req_id = ?`, authReqID)
	var (
		clientID, subjectID, provider, scopes, acr, binding, resources, nonce, status string
		reqCtx                                                                        []byte
		intervalNs, lastPoll, createdNs, expiresNs                                    int64
	)
	if err := row.Scan(&clientID, &subjectID, &provider, &scopes, &acr,
		&binding, &resources, &nonce, &reqCtx, &status,
		&intervalNs, &lastPoll, &createdNs, &expiresNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth.ErrCIBARequestNotFound
		}
		return nil, fmt.Errorf("sqlite: get ciba_request: %w", err)
	}
	expiresAt := time.Unix(0, expiresNs).UTC()
	if time.Now().After(expiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM ciba_requests WHERE auth_req_id = ?`, authReqID)
		return nil, oauth.ErrCIBARequestNotFound
	}
	var lp time.Time
	if lastPoll != 0 {
		lp = time.Unix(0, lastPoll).UTC()
	}
	return &oauth.CIBARequest{
		AuthReqID:      authReqID,
		ClientID:       clientID,
		SubjectID:      subjectID,
		Provider:       provider,
		Scopes:         splitNonEmpty(scopes),
		ACRValues:      acr,
		BindingMessage: binding,
		Resources:      splitNonEmpty(resources),
		Nonce:          nonce,
		RequestContext: reqCtx,
		Status:         oauth.CIBAStatus(status),
		Interval:       time.Duration(intervalNs),
		LastPoll:       lp,
		CreatedAt:      time.Unix(0, createdNs).UTC(),
		ExpiresAt:      expiresAt,
	}, nil
}

// SetStatus advances Pending → terminal via UPDATE ... WHERE status =
// 'pending' (atomic re-resolution guard). Same-status no-op;
// already-resolved → ErrCIBARequestResolved; missing →
// ErrCIBARequestNotFound.
func (s *CIBAStore) SetStatus(ctx context.Context, authReqID string, status oauth.CIBAStatus) error {
	if authReqID == "" {
		return oauth.ErrCIBARequestNotFound
	}
	current, err := s.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	if current.Status == status {
		return nil
	}
	if current.Status != oauth.CIBAPending {
		return oauth.ErrCIBARequestResolved
	}
	res, err := s.db.ExecContext(ctx, `
        UPDATE ciba_requests SET status = ?
        WHERE auth_req_id = ? AND status = 'pending'`,
		string(status), authReqID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update ciba_request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: update ciba_request rowsaffected: %w", err)
	}
	if n == 0 {
		return oauth.ErrCIBARequestResolved
	}
	return nil
}

// UpdateLastPoll records the most recent poll for slow_down.
func (s *CIBAStore) UpdateLastPoll(ctx context.Context, authReqID string, t time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE ciba_requests SET last_poll = ? WHERE auth_req_id = ?`,
		t.UnixNano(), authReqID); err != nil {
		return fmt.Errorf("sqlite: update ciba_request last_poll: %w", err)
	}
	return nil
}

// Delete drops the entry. Idempotent — missing id → nil.
func (s *CIBAStore) Delete(ctx context.Context, authReqID string) error {
	if authReqID == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ciba_requests WHERE auth_req_id = ?`, authReqID); err != nil {
		return fmt.Errorf("sqlite: delete ciba_request: %w", err)
	}
	return nil
}

// PruneExpired deletes every entry whose expires_at has passed.
// Returns the row count for operators wiring a cron prune loop.
func (s *CIBAStore) PruneExpired(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("sqlite: ciba store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ciba_requests WHERE expires_at < ?`, time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune expired ciba_requests: %w", err)
	}
	return res.RowsAffected()
}

// splitNonEmpty splits a space-joined list, returning nil for the
// empty string (so a round-tripped empty slice stays nil, not [""]).
func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}

var _ oauth.CIBAStore = (*CIBAStore)(nil)
