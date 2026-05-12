package sso

import "context"

// SessionManager handles user session lifecycle.
type SessionManager interface {
	Create(ctx context.Context, userID string) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Destroy(ctx context.Context, sessionID string) error
	Refresh(ctx context.Context, sessionID string) (*Session, error)
}
