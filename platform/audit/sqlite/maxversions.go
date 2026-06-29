package sqlite

import "github.com/snaplink/sso/platform/migrate"

// AuditMaxVersion returns the highest migration version declared for the
// audit sink. cmd compares this against the live DB at boot via
// migrate.CheckSchema so that an older binary running against a
// forward-migrated database fails loud instead of silently serving on a
// schema it doesn't understand.
func AuditMaxVersion() int { return migrate.MaxVersion(migrations) }
