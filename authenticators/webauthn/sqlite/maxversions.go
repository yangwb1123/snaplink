package sqlite

import "github.com/snaplink/sso/migrate"

// UsersMaxVersion returns the highest migration version declared for the
// webauthn_users store. cmd compares this against the live DB at boot via
// migrate.CheckSchema.
func UsersMaxVersion() int { return migrate.MaxVersion(userMigrations) }

// SessionsMaxVersion returns the highest migration version declared for
// the webauthn_sessions store. cmd compares this against the live DB at
// boot via migrate.CheckSchema.
func SessionsMaxVersion() int { return migrate.MaxVersion(sessionMigrations) }
