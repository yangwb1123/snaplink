package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ensureSchema runs a store's baseline schema through the migration
// runner under its own namespace, recording schema version 1. Each
// store gets its own namespace because the §4 backend toggles let
// different stores live in different databases — a store's New must
// only create its own tables + version table.
//
// A store that later needs to evolve its schema replaces this call with
// an explicit migrate.Run carrying a v2+ Migration slice (see
// refresh_tokens.go's column history for the kind of change that
// motivates it).
func ensureSchema(db *sql.DB, namespace, schema string) error {
	return migrate.Run(context.Background(), db, namespace, []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: schema},
	})
}

const notificationSchema = `
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
 type TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, severity TEXT NOT NULL,
 channel TEXT NOT NULL, created_at INTEGER NOT NULL, read_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_notifications_subject_created
 ON notifications(subject_id, created_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS notification_preferences (
 subject_id TEXT NOT NULL, type TEXT NOT NULL, channel TEXT NOT NULL, enabled INTEGER NOT NULL,
 PRIMARY KEY(subject_id, type, channel)
);
`

const notificationReadRetention = 90 * 24 * time.Hour

// NotificationStore is the durable SQLite in-app inbox.
type NotificationStore struct {
	db   *sql.DB
	owns bool
}

func NewNotificationStore(dsn string) (*NotificationStore, error) {
	db, err := openNotificationDB(dsn)
	if err != nil {
		return nil, err
	}
	return &NotificationStore{db: db, owns: true}, nil
}

func NewNotificationStoreWithDB(db *sql.DB) (*NotificationStore, error) {
	if err := ensureSchema(db, "notifications", notificationSchema); err != nil {
		return nil, err
	}
	return &NotificationStore{db: db}, nil
}

func (s *NotificationStore) Create(ctx context.Context, event *core.NotificationEvent) error {
	if event == nil || event.SubjectID == "" {
		return core.ErrNotificationInvalid
	}
	if event.ID == "" {
		event.ID = notificationID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	var readAt any
	if event.ReadAt != nil {
		readAt = event.ReadAt.UnixNano()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO notifications
 (id,subject_id,tenant_id,type,title,body,severity,channel,created_at,read_at)
 VALUES(?,?,?,?,?,?,?,?,?,?)`, event.ID, event.SubjectID, event.TenantID, event.Type,
		event.Title, event.Body, event.Severity, event.Channel, event.CreatedAt.UnixNano(), readAt)
	if err != nil {
		return err
	}
	// Match the memory backend's retention semantics without a background
	// scheduler: writes opportunistically prune only this subject's old read
	// rows, keeping the indexed scan bounded and unread history untouched.
	_, _ = s.db.ExecContext(ctx, "DELETE FROM notifications WHERE subject_id=? AND read_at IS NOT NULL AND read_at<?",
		event.SubjectID, time.Now().Add(-notificationReadRetention).UnixNano())
	return nil
}

func (s *NotificationStore) ListBySubject(ctx context.Context, subjectID string, since time.Time, limit int) ([]*core.NotificationEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,subject_id,tenant_id,type,title,body,severity,channel,created_at,read_at
 FROM notifications WHERE subject_id=? AND created_at>=?
 ORDER BY created_at DESC,id DESC LIMIT ?`, subjectID, since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotifications(rows)
}

func (s *NotificationStore) ListPage(ctx context.Context, subjectID, beforeID string, unreadOnly bool, limit int) ([]*core.NotificationEvent, bool, error) {
	if limit <= 0 {
		limit = 20
	}
	beforeTime, err := s.cursorTime(ctx, subjectID, beforeID)
	if err != nil {
		return nil, false, err
	}
	query, args := notificationPageQuery(subjectID, beforeID, beforeTime, unreadOnly, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items, err := scanNotifications(rows)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

func notificationPageQuery(subjectID, beforeID string, beforeTime int64, unreadOnly bool, limit int) (string, []any) {
	query := `SELECT id,subject_id,tenant_id,type,title,body,severity,channel,created_at,read_at
 FROM notifications WHERE subject_id=?`
	args := []any{subjectID}
	if beforeID != "" {
		query += " AND (created_at<? OR (created_at=? AND id<?))"
		args = append(args, beforeTime, beforeTime, beforeID)
	}
	if unreadOnly {
		query += " AND read_at IS NULL"
	}
	query += " ORDER BY created_at DESC,id DESC LIMIT ?"
	return query, append(args, limit)
}

func (s *NotificationStore) cursorTime(ctx context.Context, subjectID, beforeID string) (int64, error) {
	if beforeID == "" {
		return 0, nil
	}
	var value int64
	err := s.db.QueryRowContext(ctx, "SELECT created_at FROM notifications WHERE subject_id=? AND id=?", subjectID, beforeID).Scan(&value)
	if err == sql.ErrNoRows {
		return 0, core.ErrNotificationNotFound
	}
	return value, err
}

func scanNotifications(rows *sql.Rows) ([]*core.NotificationEvent, error) {
	out := make([]*core.NotificationEvent, 0)
	for rows.Next() {
		event := &core.NotificationEvent{}
		var created int64
		var read sql.NullInt64
		err := rows.Scan(&event.ID, &event.SubjectID, &event.TenantID, &event.Type, &event.Title,
			&event.Body, &event.Severity, &event.Channel, &created, &read)
		if err != nil {
			return nil, err
		}
		event.CreatedAt = time.Unix(0, created).UTC()
		if read.Valid {
			value := time.Unix(0, read.Int64).UTC()
			event.ReadAt = &value
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *NotificationStore) MarkRead(ctx context.Context, id string) error {
	return s.markRead(ctx, "", id)
}

func (s *NotificationStore) MarkReadForSubject(ctx context.Context, subjectID, id string) error {
	return s.markRead(ctx, subjectID, id)
}

func (s *NotificationStore) markRead(ctx context.Context, subjectID, id string) error {
	query, args := "UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=?", []any{time.Now().UTC().UnixNano(), id}
	if subjectID != "" {
		query, args = "UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND subject_id=?", append(args, subjectID)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return core.ErrNotificationNotFound
	}
	return nil
}

func (s *NotificationStore) UnreadCount(ctx context.Context, subjectID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE subject_id=? AND read_at IS NULL", subjectID).Scan(&count)
	return count, err
}

func (s *NotificationStore) DeleteForSubject(ctx context.Context, subjectID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM notifications WHERE subject_id=?", subjectID)
	return err
}

func (s *NotificationStore) SendNotification(ctx context.Context, event *core.NotificationEvent) error {
	return s.Create(ctx, event)
}

func (s *NotificationStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *NotificationStore) DB() *sql.DB                    { return s.db }
func (s *NotificationStore) Close() error {
	if s == nil || s.db == nil || !s.owns {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// NotificationPreferenceStore persists per-type delivery settings.
type NotificationPreferenceStore struct {
	db   *sql.DB
	owns bool
}

func NewNotificationPreferenceStore(dsn string) (*NotificationPreferenceStore, error) {
	db, err := openNotificationDB(dsn)
	if err != nil {
		return nil, err
	}
	return &NotificationPreferenceStore{db: db, owns: true}, nil
}

func NewNotificationPreferenceStoreWithDB(db *sql.DB) (*NotificationPreferenceStore, error) {
	if err := ensureSchema(db, "notifications", notificationSchema); err != nil {
		return nil, err
	}
	return &NotificationPreferenceStore{db: db}, nil
}

func (s *NotificationPreferenceStore) ListBySubject(ctx context.Context, subjectID string) ([]core.NotificationPreference, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject_id,type,channel,enabled FROM notification_preferences
 WHERE subject_id=? ORDER BY type,channel`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]core.NotificationPreference, 0)
	for rows.Next() {
		var value core.NotificationPreference
		if err := rows.Scan(&value.SubjectID, &value.Type, &value.Channel, &value.Enabled); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *NotificationPreferenceStore) Put(ctx context.Context, value core.NotificationPreference) error {
	if value.SubjectID == "" || value.Type == "" || value.Channel == "" {
		return core.ErrNotificationInvalid
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO notification_preferences(subject_id,type,channel,enabled)
 VALUES(?,?,?,?) ON CONFLICT(subject_id,type,channel) DO UPDATE SET enabled=excluded.enabled`,
		value.SubjectID, value.Type, value.Channel, value.Enabled)
	return err
}

func (s *NotificationPreferenceStore) DeleteForSubject(ctx context.Context, subjectID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM notification_preferences WHERE subject_id=?", subjectID)
	return err
}

func (s *NotificationPreferenceStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *NotificationPreferenceStore) DB() *sql.DB                    { return s.db }
func (s *NotificationPreferenceStore) Close() error {
	if s == nil || s.db == nil || !s.owns {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func openNotificationDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite notifications: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := ensureSchema(db, "notifications", notificationSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite notifications: migrate: %w", err)
	}
	return db, nil
}

func notificationID() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	return base64.RawURLEncoding.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
}
