package sso

import (
	"time"

	"github.com/snaplink/sso/domains/connections"
)

// WithDomainVerificationResolver injects the DNS-TXT resolver used by the admin
// connection email-domain verification endpoint (first-class DI so tests run
// network-free with a fake and operators can supply a DNS-over-HTTPS resolver).
// Nil/unset uses the stdlib-backed production resolver. This only affects the
// resolver; the enable flag + record prefix live on the connections.Store
// (WithDomainVerificationRequired / config connections.domain_verification).
func WithDomainVerificationResolver(r connections.DNSResolver) Option {
	return func(s *Server) {
		if r != nil {
			s.domainVerificationResolver = r
		}
	}
}

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
