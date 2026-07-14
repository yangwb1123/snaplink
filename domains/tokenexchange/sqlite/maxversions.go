package sqlite

import "github.com/snaplink/sso/platform/migrate"

// ChainStoreMaxVersion returns the highest migration version declared for
// the token-exchange chain store. cmd compares this against the live DB at
// boot via migrate.CheckSchema so that an older binary running against a
// forward-migrated database fails loud instead of silently serving on a
// schema it doesn't understand.
func ChainStoreMaxVersion() int { return migrate.MaxVersion(chainMigrations) }
