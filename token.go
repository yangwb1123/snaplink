package sso

import "context"

// TokenIssuer handles token lifecycle: issuance, validation, and revocation.
type TokenIssuer interface {
	Issue(ctx context.Context, subject *Subject, scopes []string) (*Token, error)
	Validate(ctx context.Context, token string) (*TokenClaims, error)
	Revoke(ctx context.Context, token string) error
}

// TokenLister is an OPTIONAL extension to TokenIssuer for backends that can
// enumerate issued tokens (session-backed, DB-backed). Stateless backends
// like JWT MUST NOT implement this — admin RPCs check the type assertion
// and respond Unimplemented (gRPC) / 501 (HTTP) when absent.
type TokenLister interface {
	ListActive(ctx context.Context) ([]TokenMeta, error)
}

// TokenMeta is the lightweight summary returned by TokenLister.ListActive —
// enough for admins to identify and revoke a token without exposing its bytes.
type TokenMeta struct {
	TokenID   string   `json:"token_id"`
	SubjectID string   `json:"subject_id"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  int64    `json:"issued_at_unix,omitempty"`
	ExpiresAt int64    `json:"expires_at_unix,omitempty"`
	Strategy  string   `json:"strategy,omitempty"` // "jwt" | "session" | ...
}
