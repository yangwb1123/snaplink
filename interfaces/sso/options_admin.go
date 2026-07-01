package sso

import "time"

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
