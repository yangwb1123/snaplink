package sso

import "context"

// ClientStore manages registered SSO client applications.
type ClientStore interface {
	Get(ctx context.Context, clientID string) (*Client, error)
	ValidateSecret(ctx context.Context, clientID, clientSecret string) error
}
