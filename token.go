package sso

import "context"

// TokenIssuer handles token lifecycle: issuance, validation, and revocation.
type TokenIssuer interface {
	Issue(ctx context.Context, subject *Subject, scopes []string) (*Token, error)
	Validate(ctx context.Context, token string) (*TokenClaims, error)
	Revoke(ctx context.Context, token string) error
}

// TokenFormatHinter is an OPTIONAL extension that lets a TokenIssuer
// declare which inbound token shapes it can possibly validate. The
// multi-issuer dispatcher (`validateAnyToken`) uses this to skip
// issuers that obviously can't accept a token — avoiding the cost of
// e.g. attempting a base64 + signature parse on an opaque session
// token via the JWT issuer. Issuers that don't implement this
// interface are always tried (legacy behavior preserved).
//
// AcceptsTokenFormat MUST be pure (no I/O, no allocation in the hot
// path) — it's called once per Validate dispatch. False positives
// (returning true for a token this issuer can't actually validate)
// just cost a wasted Validate; false negatives (returning false for
// a token this issuer COULD validate) cause spurious validation
// failures. When in doubt, return true.
type TokenFormatHinter interface {
	AcceptsTokenFormat(token string) bool
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
