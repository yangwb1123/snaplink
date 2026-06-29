package sqlite

import "github.com/snaplink/sso/platform/migrate"

// ConnectionsMaxVersion returns the highest migration version declared for the
// connections store. cmd compares this against the live DB at boot via
// migrate.CheckSchema so that an older binary running against a
// forward-migrated database fails loud instead of silently serving on a
// schema it doesn't understand.
func ConnectionsMaxVersion() int { return migrate.MaxVersion(connectionMigrations) }
