package core

import (
	"context"
	"time"
)

// AdminToken records an issued admin bearer token with its metadata.
// Used by the admin API to list and revoke active tokens.
type AdminToken struct {
	// ID is the opaque token identifier (not the full token value).
	ID string `json:"id"`

	// Label is an operator-supplied human name (e.g. "ci-cd pipeline").
	Label string `json:"label,omitempty"`

	// AdminID is the actor who requested the token.
	AdminID string `json:"admin_id,omitempty"`

	// Scopes granted to this token (e.g. ["admin:read", "admin:write"]).
	Scopes []string `json:"scopes,omitempty"`

	// CreatedAt is when the token was issued.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the token expires. Zero = never.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// LastUsedAt is the last time this token was used.
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// AdminTokenStore persists and manages admin bearer tokens. Without
// this store, admin tokens can only be revoked by clearing the
// underlying session or temp-token store — there's no visibility
// into which tokens exist or when they expire.
type AdminTokenStore interface {
	// Record persists a new admin token record.
	Record(ctx context.Context, token AdminToken) error

	// GetByID returns a single token record by ID. Returns
	// ErrTokenNotFound when the ID is unknown or the token was
	// revoked.
	GetByID(ctx context.Context, id string) (AdminToken, error)

	// List returns all non-expired admin tokens, newest first.
	// When adminID is non-empty, filters to tokens issued by
	// that admin.
	List(ctx context.Context, adminID string) ([]AdminToken, error)

	// Revoke marks a token as revoked (idempotent). Returns
	// nil even when the ID is unknown (anti-enumeration).
	Revoke(ctx context.Context, id string) error

	// Touch updates the LastUsedAt timestamp for a token.
	Touch(ctx context.Context, id string) error
}
