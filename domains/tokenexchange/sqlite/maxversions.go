package sqlite

import "github.com/yangwb1123/snaplink/platform/migrate"

// ChainStoreMaxVersion returns the highest migration version declared for
// the token-exchange chain store. cmd compares this against the live DB at
// boot via migrate.CheckSchema so that an older binary running against a
// forward-migrated database fails loud instead of silently serving on a
// schema it doesn't understand.
func ChainStoreMaxVersion() int { return migrate.MaxVersion(chainMigrations) }
