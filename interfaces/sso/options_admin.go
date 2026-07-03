package sso

import (
	"time"

	"github.com/snaplink/sso/platform/rotation"
)

// WithAdminSessionTTL sets an idle timeout for admin bearer tokens. When
// a token has not been used for longer than the TTL, the admin middleware
// rejects the request and the caller must re-authenticate. 0 (default)
// disables idle timeout — tokens remain valid until their exp claim.
//
// The TTL is enforced by the admin middleware, which calls
// AdminTokenStore.Touch() on every successful request and checks
// LastUsedAt against the timeout. Requires WithAdminTokenStore.
//
// Typical value: 30 minutes — aligns with common SOC2/ISO 27001
// session idle-timeout requirements.
//
//	srv := sso.NewServer(
//	    sso.WithAdminTokenStore(store),
//	    sso.WithAdminSessionTTL(30 * time.Minute),
//	)
func WithAdminSessionTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl > 0 {
			s.adminSessionTTL = ttl
		}
	}
}

// WithBackupDir sets the destination directory for POST /api/v1/admin/backup
// (VACUUM INTO snapshots). Empty (default) falls back to the OS temp dir.
func WithBackupDir(dir string) Option {
	return func(s *Server) {
		if dir != "" {
			s.backupDir = dir
		}
	}
}

// WithBackupRetention keeps only the newest keep backup files per source
// after each successful backup. 0 (default) disables pruning.
func WithBackupRetention(keep int) Option {
	return func(s *Server) {
		if keep > 0 {
			s.backupKeep = keep
		}
	}
}

// WithCredentialRotation wires the platform/rotation Registry backing GET
// /api/v1/admin/credentials — a read-only governance inventory (type,
// version, status, created_at, next rotation due) of every credential class
// registered for automatic rotation. NEVER exposes secret material.
//
// The Registry is a passive snapshot source: build it (rotation.NewRegistry,
// then Register each corecredential.CredentialRotator), wrap it in a
// rotation.Scheduler, and Start/Stop the Scheduler from the composition root
// (cmd) — the same lifecycle discipline as the signing-key rotation loop.
// This option only wires the Server's READ access to reg; it does not start
// anything.
//
// Nil (the default) leaves the route unmounted — byte-identical to a build
// without this feature.
func WithCredentialRotation(reg *rotation.Registry) Option {
	return func(s *Server) { s.credentialRegistry = reg }
}
