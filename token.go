package sso

import "context"

// TokenIssuer handles token lifecycle: issuance, validation, and revocation.
type TokenIssuer interface {
	Issue(ctx context.Context, subject *Subject, scopes []string) (*Token, error)
	Validate(ctx context.Context, token string) (*TokenClaims, error)
	Revoke(ctx context.Context, token string) error
}
