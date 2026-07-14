package core

import "context"

// BackupSource is a named SQLite database that can produce a backup
// file. Register with the server's backup registry so the admin
// backup endpoint can enumerate and trigger backups.
type BackupSource interface {
	// Name returns a human-readable label (e.g. "audit", "sessions").
	Name() string

	// BackupTo writes a VACUUM INTO snapshot to the given path.
	// The caller manages file lifecycle (creation, cleanup, streaming).
	BackupTo(ctx context.Context, destPath string) error
}

// PathAdminSessionsLinked is the cross-protocol session-hub admin query
// (Cross-protocol Session Hub backlog item): every session (every protocol
// a login fanned out into), grouped by global_sid, for one subject. GET,
// admin:read — mirrors PathAdminTokenSubject's per-subject-view scope.
// Relocated here (not consts_wire.go) because that file is at its per-file
// line budget.
const PathAdminSessionsLinked = "/admin/sessions/linked/:subject"
