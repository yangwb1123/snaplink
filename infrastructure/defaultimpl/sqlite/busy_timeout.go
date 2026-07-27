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

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/security"
	sqlited "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
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
