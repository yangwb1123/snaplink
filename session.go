package sso

import "context"

// SessionManager handles user session lifecycle. ListByUser + ListAll back
// the TokenAdminService.ListSessions RPC and are the only safe way to get a
// "list active sessions" view (JWT issuers are stateless and cannot answer).
type SessionManager interface {
	Create(ctx context.Context, userID string) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Destroy(ctx context.Context, sessionID string) error
	Refresh(ctx context.Context, sessionID string) (*Session, error)

	// ListByUser returns every active session for a user. Empty list if none.
	ListByUser(ctx context.Context, userID string) ([]*Session, error)

	// ListAll returns every active session. Backends with millions of sessions
	// MAY return ErrUnsupportedOperation rather than load the whole world.
	ListAll(ctx context.Context) ([]*Session, error)
}
