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

// CredentialRevocationResult is one independently retryable leg of a
// tenant-lifecycle credential purge.
type CredentialRevocationResult struct {
	IdempotencyKey string `json:"idempotency_key"`
	Kind           string `json:"kind"`
	ResourceID     string `json:"resource_id"`
	Status         string `json:"status"`
	RevokedCount   int    `json:"revoked_count"`
	Error          string `json:"error,omitempty"`
}

// TenantCredentialRevocationReport makes suspension/deletion cleanup
// observable instead of hiding refresh-token or session failures.
type TenantCredentialRevocationReport struct {
	TenantID             string                       `json:"tenant_id"`
	RefreshTokensRevoked int                          `json:"refresh_tokens_revoked"`
	SessionsRevoked      int                          `json:"sessions_revoked"`
	Results              []CredentialRevocationResult `json:"results"`
}

// Complete reports whether every configured revocation leg succeeded.
func (r TenantCredentialRevocationReport) Complete() bool {
	for _, result := range r.Results {
		if result.Status == "failed" {
			return false
		}
	}
	return true
}
