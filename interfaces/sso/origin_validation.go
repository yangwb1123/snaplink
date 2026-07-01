package sso

// isOriginAllowed checks if the given origin is allowed by the CORS policy.
// Returns true if:
//   - No CORS policy is configured (allow all for backwards compatibility)
//   - The origin is in the AllowedOrigins list
//   - Wildcard "*" is configured
//
// Returns false if:
//   - CORS policy exists but origin is not in AllowedOrigins and no wildcard
//
// This is used for defense-in-depth CSRF protection on sensitive endpoints
// like /auth/login where we want to validate the Origin header even before
// the CORS middleware runs.
func (s *Server) isOriginAllowed(origin string) bool {
	// No CORS policy = no origin restrictions (backwards compatible)
	if s.corsPolicy == nil {
		return true
	}

	// Check each allowed origin
	for _, allowed := range s.corsPolicy.AllowedOrigins {
		// Wildcard allows any origin
		if allowed == "*" {
			return true
		}
		// Exact match
		if allowed == origin {
			return true
		}
	}

	return false
}
