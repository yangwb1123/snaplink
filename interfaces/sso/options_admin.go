package sso

import (
	"time"

	"github.com/snaplink/sso/platform/rotation"
	"github.com/snaplink/sso/platform/sse"
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

// WithSSEBroker mounts GET /api/v1/admin/events/stream — the realtime
// admin event source (Server-Sent Events). When an audit recorder is ALSO
// wired, NewServer taps its pipeline (the same AddSink/MultiSink seam
// WithCAEPTransmitter uses) so every recorded event is projected to a
// redacted Summary and published to b; without a recorder the route still
// mounts but never emits (the broker has no source).
//
// The caller owns b's lifecycle: construct it with sse.NewBroker and Close
// it during shutdown, BEFORE the HTTP graceful drain, so idle EventSource
// connections don't pin Shutdown to its full deadline (Server.SSEBroker
// exposes it back for exactly that). Default-off: a nil (unset) broker is
// byte-identical to a build without the feature.
func WithSSEBroker(b *sse.Broker) Option {
	return func(s *Server) { s.sseBroker = b }
}

// SSEBroker returns the wired broker (nil when unset), so cmd can Close it
// during shutdown without retaining its own reference.
func (s *Server) SSEBroker() *sse.Broker { return s.sseBroker }

// WithSSEHeartbeat overrides the admin event stream's keep-alive comment
// interval. <= 0 (the default) leaves the SDK default (sse.DefaultHeartbeat)
// in effect. Has no effect without WithSSEBroker.
func WithSSEHeartbeat(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.sseHeartbeat = d
		}
	}
}
