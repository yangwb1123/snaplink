// SQLite runtime busy_timeout. modernc.org/sqlite does NOT honor the
// mattn-style `_busy_timeout` DSN query param (only `_pragma=busy_timeout(N)`),
// and busy_timeout is a PER-CONNECTION setting: a PRAGMA run once at migration
// time does not carry to the pool connections that serve runtime traffic.
//
// Registering a connection hook applies the default to EVERY connection the
// driver opens, process-wide, across every store package, without threading a
// DSN change through ~17 store constructors.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/security"
	"golang.org/x/crypto/bcrypt"
	sqlited "modernc.org/sqlite"
)

const defaultBusyTimeoutMS = 5000

func init() {
	sqlited.RegisterConnectionHook(func(conn sqlited.ExecQuerierContext, dsn string) error {
		if strings.Contains(dsn, "busy_timeout(") {
			return nil
		}
		_, err := conn.ExecContext(context.Background(),
			fmt.Sprintf("PRAGMA busy_timeout=%d", defaultBusyTimeoutMS), nil)
		return err
	})
}

// beginImmediateRMW pins a connection and issues BEGIN IMMEDIATE, acquiring
// the write lock up front (plain DEFERRED has a lost-update race window).
func beginImmediateRMW(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// hashClientSecret hashes a plaintext client secret using bcrypt.
func hashClientSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), defaultimpl.BcryptCost())
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// isBcryptHash reports whether s is already a bcrypt hash.
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2")
}

// compareClientSecret returns true if plaintext matches the stored value.
func compareClientSecret(stored, plaintext string) bool {
	return security.CompareClientSecret(stored, plaintext)
}

const sqliteExpirySweepTimeout = 30 * time.Second

type sqliteExpiryReaper struct {
	worker *memreaper.Reaper
}

func startSQLiteExpiryReaper(db *sql.DB, interval time.Duration, statements ...string) *sqliteExpiryReaper {
	if db == nil || interval <= 0 {
		return nil
	}
	worker := memreaper.Start(interval, func(now time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), sqliteExpirySweepTimeout)
		defer cancel()
		for _, statement := range statements {
			_, _ = db.ExecContext(ctx, statement, now.UnixNano())
		}
	})
	return &sqliteExpiryReaper{worker: worker}
}

func (r *sqliteExpiryReaper) Close() error {
	if r == nil {
		return nil
	}
	return r.worker.Close()
}

func replaceSQLiteReaper(current **sqliteExpiryReaper, next *sqliteExpiryReaper) {
	if *current != nil {
		_ = (*current).Close()
	}
	*current = next
}

func (s *AuthCodeStore) StartReaper(interval time.Duration) {
	replaceSQLiteReaper(&s.reaper, startSQLiteExpiryReaper(s.db, interval,
		`DELETE FROM auth_codes WHERE expires_at < ?`))
}

func (s *RefreshTokenStore) StartReaper(interval time.Duration) {
	replaceSQLiteReaper(&s.reaper, startSQLiteExpiryReaper(s.db, interval,
		`DELETE FROM refresh_token_families WHERE expires_at < ?`,
		`DELETE FROM refresh_tokens WHERE expires_at < ?`,
		`DELETE FROM refresh_rotation_windows
           WHERE family_id NOT IN (SELECT family_id FROM refresh_token_families)
             AND ? > 0`))
}

func (s *DeviceCodeStore) StartReaper(interval time.Duration) {
	replaceSQLiteReaper(&s.reaper, startSQLiteExpiryReaper(s.db, interval,
		`DELETE FROM device_codes WHERE expires_at < ?`))
}

func (s *PARStore) StartReaper(interval time.Duration) {
	replaceSQLiteReaper(&s.reaper, startSQLiteExpiryReaper(s.db, interval,
		`DELETE FROM par_requests WHERE expires_at < ?`))
}

// mirrorRefreshFamily retains consumed-token reuse detection only through the
// token's validity window; after that, replay can no longer yield credentials
// and the ledger row may be reclaimed.
func (s *RefreshTokenStore) mirrorRefreshFamily(
	ctx context.Context, token, familyID string, expiresAt time.Time,
) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO refresh_token_families (token, family_id, expires_at)
        VALUES (?, ?, ?)`, token, familyID, expiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: insert refresh_token_families: %w", err)
	}
	return nil
}

var _ oauth.RefreshTokenStore = (*RefreshTokenStore)(nil)
