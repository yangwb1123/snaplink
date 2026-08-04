package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

const sessionIDBytes = 32

// sessionMigrations is the versioned schema history for the session store
// (TokenStrategySession opaque-token state). The ID is an opaque hex string the
// client sees as its bearer token, so this is effectively the access-token store
// for the session strategy; multi-replica deployments need it so a session
// minted on replica A is redeemable on replica B.
//
// v1: baseline (matches the original ensureSchema schema byte-for-byte, so a DB
//
//	already stamped v1 by ensureSchema is a no-op here).
//
// v2: ADD COLUMN ip + user_agent — best-effort device/location context for the
//
//	self-service session list. Default '' so existing rows are unaffected.
//
// v3: ADD COLUMN tenant_id + index — binds a session to its owning tenant so
//
//	DeleteByTenant (sso.SessionTenantIndex) can revoke every session of a
//	suspended/deleted tenant in one query. Default '' so existing rows are
//	unaffected (they fall back to roster-based revocation).
var sessionMigrations = []migrate.Migration{
	{
		Version: 1,
		Name:    "baseline",
		SQL: `
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
`,
	},
	{
		Version: 2,
		Name:    "session-device-context",
		SQL: `
ALTER TABLE sessions ADD COLUMN ip         TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';`,
	},
	{
		Version: 3,
		Name:    "session-tenant-binding",
		SQL: `
ALTER TABLE sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id
    ON sessions(tenant_id);`,
	},
	{
		// v4: ADD COLUMN trust_score + trust_set_at + step_up_required — the
		// zero-trust session-trust-decay state (WithSessionTrustDecay). Defaults
		// (0 / 0 / 0) mean "no trust bound", so existing rows read the feature-off
		// zero value and the decay/gate fail-open on them (byte-identical). No
		// index: the continuous-verification agent scans the full live set on a
		// slow cadence, not a keyed lookup.
		Version: 4,
		Name:    "session-trust-decay",
		SQL: `
ALTER TABLE sessions ADD COLUMN trust_score      REAL    NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN trust_set_at     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN step_up_required INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		Version: 5,
		Name:    "session-authorization-context",
		SQL: `
ALTER TABLE sessions ADD COLUMN client_id         TEXT    NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN authorized_scopes TEXT    NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN auth_time         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN device_id         TEXT    NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN kind              TEXT    NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_subject_client
    ON sessions(user_id, client_id);`,
	},
}

// sessionCols is the SELECT/RETURNING projection shared by every read path, kept
// in one place so the v4 trust-decay columns can't drift between the queries and
// scanSession's field order.
const sessionCols = "id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id, trust_score, trust_set_at, step_up_required, client_id, authorized_scopes, auth_time, device_id, kind"

// SessionManager is the SQLite-backed implementation of
// [sso.SessionManager]. Suitable for multi-replica deployments and
// session-strategy clients.
type SessionManager struct {
	db  *sql.DB
	ttl time.Duration
}

// NewSessionManager opens dsn, migrates the schema, and returns the
// manager. ttl is the lifetime applied on Create + Refresh; pass 0
// to take [sso.DefaultSessionDuration].
func NewSessionManager(dsn string, ttl time.Duration) (*SessionManager, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "sessions", sessionMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate sessions: %w", err)
	}
	if ttl <= 0 {
		ttl = sso.DefaultSessionDuration
	}
	return &SessionManager{db: db, ttl: ttl}, nil
}

// NewSessionManagerWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle (shared-pool deployments).
func NewSessionManagerWithDB(db *sql.DB, ttl time.Duration) (*SessionManager, error) {
	if err := migrate.Run(context.Background(), db, "sessions", sessionMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate sessions: %w", err)
	}
	if ttl <= 0 {
		ttl = sso.DefaultSessionDuration
	}
	return &SessionManager{db: db, ttl: ttl}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SessionManager) Close() error {
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
func (s *SessionManager) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *SessionManager) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: session manager closed")
	}
	return s.db.PingContext(ctx)
}

func (s *SessionManager) Create(ctx context.Context, userID string) (*sso.Session, error) {
	return s.CreateWithMeta(ctx, userID, sso.SessionMeta{})
}

// CreateWithMeta implements sso.SessionMetaCreator: it persists the device/
// location context (IP, user-agent) on the new session for the self-service
// session list.
func (s *SessionManager) CreateWithMeta(ctx context.Context, userID string, meta sso.SessionMeta) (*sso.Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, fmt.Errorf("sqlite: random session id: %w", err)
	}
	now := time.Now().UTC()
	session := &sso.Session{
		ID:               id,
		UserID:           userID,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.ttl),
		IP:               meta.IP,
		UserAgent:        meta.UserAgent,
		TenantID:         meta.TenantID,
		DeviceID:         meta.DeviceID,
		ClientID:         meta.ClientID,
		AuthorizedScopes: append([]string(nil), meta.AuthorizedScopes...),
		AuthTime:         meta.AuthTime,
		Kind:             meta.Kind,
		TrustScore:       meta.TrustScore,
		TrustSetAt:       meta.TrustSetAt,
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO sessions (id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id, trust_score, trust_set_at, step_up_required, client_id, authorized_scopes, auth_time, device_id, kind)
        VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.CreatedAt.UnixNano(), session.ExpiresAt.UnixNano(),
		session.IP, session.UserAgent, session.TenantID, session.TrustScore, unixNanoOrZero(session.TrustSetAt),
		session.ClientID, strings.Join(session.AuthorizedScopes, " "), unixNanoOrZero(session.AuthTime), session.DeviceID, session.Kind,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insert session: %w", err)
	}
	return session, nil
}

func (s *SessionManager) Get(ctx context.Context, sessionID string) (*sso.Session, error) {
	now := time.Now().UnixNano()
	row := s.db.QueryRowContext(ctx, `
        SELECT `+sessionCols+`
          FROM sessions WHERE id = ? AND revoked = 0 AND expires_at > ?`, sessionID, now)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: destroy session: %w", err)
	}
	return nil
}

// Refresh extends ExpiresAt by ttl. Returns ErrSessionNotFound when
// the row is missing — matches MemorySessionManager's contract.
// UPDATE ... RETURNING gives us the post-update row in one round-
// trip + atomically tests existence.
func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (*sso.Session, error) {
	// Refresh MUST NOT resurrect expired or revoked sessions —
	// otherwise a captured session id is valid forever to anyone
	// who can call Refresh. The WHERE clause filters out both
	// failure modes BEFORE the UPDATE fires; combined with
	// RETURNING, an attempted resurrect surfaces as sql.ErrNoRows
	// (mapped to ErrSessionNotFound) instead of silent extension.
	now := time.Now()
	row := s.db.QueryRowContext(ctx, `
        UPDATE sessions SET expires_at = ?
          WHERE id = ? AND revoked = 0 AND expires_at > ?
        RETURNING `+sessionCols,
		now.Add(s.ttl).UnixNano(), sessionID, now.UnixNano(),
	)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: refresh session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) ListByUser(ctx context.Context, userID string) ([]*sso.Session, error) {
	now := time.Now().UnixNano()
	rows, err := s.db.QueryContext(ctx, `
        SELECT `+sessionCols+`
          FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ?`, userID, now)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) ListAll(ctx context.Context) ([]*sso.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT `+sessionCols+`
          FROM sessions`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list all: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) TrackActivity(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_active_at = ? WHERE id = ?`, time.Now().Unix(), sessionID)
	return err
}

// ListByTenant implements sso.SessionTenantLister — returns every session
// stamped with tenantID. Empty tenantID returns empty list (no wildcard).
func (s *SessionManager) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Session, error) {
	if tenantID == "" {
		return []*sso.Session{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT `+sessionCols+`
          FROM sessions WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

// DeleteByTenant implements sso.SessionTenantIndex — removes every session
// stamped with tenantID across all users, returning the count deleted. Backs
// proactive revocation on tenant suspension/deletion so a session minted while
// the tenant was Active can't outlive the suspension. Empty tenantID is a no-op
// (not a wildcard) — wiping the table on an empty argument would be a footgun.
func (s *SessionManager) DeleteByTenant(ctx context.Context, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete sessions by tenant: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkStepUp implements sso.SessionTrustManager: it sets step_up_required so the
// next request through a min-trust gate is challenged for step-up. A missing row
// affects zero rows (not an error) — the session may have expired between the
// agent's List and this call. Best-effort advisory state, never a hard deny.
func (s *SessionManager) MarkStepUp(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET step_up_required = 1 WHERE id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: mark session step-up: %w", err)
	}
	return nil
}

// SetTrust implements sso.SessionTrustManager: it (re)binds the session's trust
// baseline and clears any prior step-up flag (a fresh baseline supersedes a
// below-floor decision so a re-verified session isn't perpetually challenged). A
// missing row affects zero rows (not an error).
func (s *SessionManager) SetTrust(ctx context.Context, sessionID string, score float64, setAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET trust_score = ?, trust_set_at = ?, step_up_required = 0 WHERE id = ?`,
		score, unixNanoOrZero(setAt), sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: set session trust: %w", err)
	}
	return nil
}

func (s *SessionManager) SetAuthorizedScopes(ctx context.Context, sessionID string, scopes []string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET authorized_scopes = ? WHERE id = ?`, strings.Join(scopes, " "), sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: set session authorized scopes: %w", err)
	}
	return nil
}

func (s *SessionManager) SetKind(ctx context.Context, sessionID, kind string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET kind = ? WHERE id = ?`, kind, sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: set session kind: %w", err)
	}
	return nil
}

func scanSession(s scanner) (*sso.Session, error) {
	var (
		out                              sso.Session
		createdAtUnixNs, expiresAtUnixNs int64
		revokedInt                       int64
		trustSetAtUnixNs                 int64
		stepUpInt                        int64
		authorizedScopes                 string
		authTimeUnixNs                   int64
	)
	if err := s.Scan(&out.ID, &out.UserID, &createdAtUnixNs, &expiresAtUnixNs, &revokedInt,
		&out.IP, &out.UserAgent, &out.TenantID, &out.TrustScore, &trustSetAtUnixNs, &stepUpInt,
		&out.ClientID, &authorizedScopes, &authTimeUnixNs, &out.DeviceID, &out.Kind); err != nil {
		return nil, err
	}
	out.CreatedAt = time.Unix(0, createdAtUnixNs).UTC()
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	out.Revoked = revokedInt != 0
	// trust_set_at stores 0 for "no baseline bound" (the feature-off default);
	// map it back to a zero time so DecayedScore/gate fail-open rather than
	// treating the Unix epoch as a real, very-stale baseline.
	if trustSetAtUnixNs != 0 {
		out.TrustSetAt = time.Unix(0, trustSetAtUnixNs).UTC()
	}
	out.StepUpRequired = stepUpInt != 0
	out.AuthorizedScopes = strings.Fields(authorizedScopes)
	if authTimeUnixNs != 0 {
		out.AuthTime = time.Unix(0, authTimeUnixNs).UTC()
	}
	return &out, nil
}

// unixNanoOrZero renders a trust baseline for storage: a zero time maps to the
// sentinel 0 (no baseline bound), never a huge negative UnixNano, so scanSession
// can round-trip "unset" faithfully.
func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func scanSessionList(rows *sql.Rows) ([]*sso.Session, error) {
	out := make([]*sso.Session, 0)
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows iter: %w", err)
	}
	return out, nil
}

func randomSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var (
	_ sso.SessionManager               = (*SessionManager)(nil)
	_ sso.SessionMetaCreator           = (*SessionManager)(nil)
	_ sso.SessionTenantIndex           = (*SessionManager)(nil)
	_ sso.SessionTenantLister          = (*SessionManager)(nil)
	_ sso.SessionTrustManager          = (*SessionManager)(nil)
	_ core.SessionAuthorizationManager = (*SessionManager)(nil)
	_ core.SessionKindManager          = (*SessionManager)(nil)
)
