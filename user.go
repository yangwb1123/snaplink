package sso

import "context"

// UserProvider manages user data storage and retrieval. List + Delete are
// the admin-only methods; reads + CreateOrUpdate are the runtime hot path.
type UserProvider interface {
	GetByID(ctx context.Context, id string) (*User, error)
	GetByExternalID(ctx context.Context, provider string, externalID string) (*User, error)
	CreateOrUpdate(ctx context.Context, user *User) error

	// List returns every known user. Order unspecified; pagination is the
	// caller's responsibility.
	List(ctx context.Context) ([]*User, error)

	// Delete removes a user by ID. Idempotent: missing IDs return nil.
	Delete(ctx context.Context, id string) error
}
