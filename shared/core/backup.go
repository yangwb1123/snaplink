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
