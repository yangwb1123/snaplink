package ssoclient

import "context"

// AuthClient verifies bearer tokens and (optionally) revokes them. The Login
// flow is intentionally NOT in this interface — login is the SSO server's
// HTTP surface, called directly by browser / mobile clients via redirect or
// XHR; downstream Apps verify the resulting token.
type AuthClient interface {
	// ValidateToken decodes and verifies a bearer token. Returns the
	// authenticated subject or an error if the token is invalid, expired,
	// or revoked. `aud` is enforced when the implementation is configured
	// with an expected audience; the remote implementation also requires
	// the configured issuer (WithIssuer) and fails closed with
	// ErrIssuerRequired until it is set.
	ValidateToken(ctx context.Context, accessToken string) (*Subject, error)

	// Logout revokes the supplied session and/or token. Returns an error
	// if revocation could not be performed (not configured, bad request,
	// or transport failure); success means the server accepted the
	// revocation. A nil error no longer implies every downstream cache has
	// invalidated — it means the revocation requests were actually sent
	// and answered (gateway-side cached permissions might still take their
	// TTL to clear).
	Logout(ctx context.Context, req *LogoutRequest) error
}

// AuthzClient answers authorization questions. Each method takes a
// subjectID + clientID pair so the same user can see different surfaces in
// different Apps — matching the per-App policy already in the SDK.
type AuthzClient interface {
	Check(ctx context.Context, req *CheckRequest) (bool, error)
	ListPermissions(ctx context.Context, subjectID, clientID string) ([]Permission, error)
	ListRoles(ctx context.Context, subjectID, clientID string) ([]Role, error)
	GetMenus(ctx context.Context, subjectID, clientID string) (MenuTree, error)
}

// AuditClient ships security-relevant events to whatever sink is configured.
// Record is the unary path; for bursty workloads prefer batching them in
// caller code rather than opening a stream per event (remote impls keep a
// background goroutine if streaming is wired).
type AuditClient interface {
	Record(ctx context.Context, e *Event) error

	// Close releases any background resources (open streams, goroutines,
	// gRPC conns owned by the client). Safe to call multiple times.
	Close() error
}
