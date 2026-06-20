// Package bootstrap is the first-run initialization framework. Apps declare
// ordered Steps (seed admin user, create DB schema, mark default settings,
// ...); a Tracker persists which versions have run; a Runner runs the
// pending ones in order, exactly once, with audit events for every
// applied/skipped/failed step.
//
// Three primitives:
//
//	Step    — one ordered, named, version-tagged init action
//	Tracker — pluggable persistence: per-namespace "applied version" cursor
//	Runner  — applies pending steps, records audit events, idempotent
//
// Built-in trackers:
//
//   - bootstrap/file   — JSON state file (default; zero deps)
//   - bootstrap/memory — for tests
//
// Usage:
//
//	r := bootstrap.NewRunner("sso-server", file.New("/var/lib/sso/.bootstrap.json"),
//	    bootstrap.WithRecorder(rec),
//	    bootstrap.WithLogger(logger))
//	r.Register(seedAdminRole, seedAdminUser)
//	if err := r.Run(ctx); err != nil { return err }
//
// Each consumer app uses its own namespace ("billing-app", ...) so version
// numbers don't collide. Steps within a namespace MUST have monotonically
// increasing Version() values.
package bootstrap
