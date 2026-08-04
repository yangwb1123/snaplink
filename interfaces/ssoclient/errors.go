package ssoclient

import (
	"errors"
	"fmt"
)

var (
	ErrIssuerRequired           = errors.New("ssoclient: issuer required")
	ErrIssuerMismatch           = errors.New("ssoclient: issuer mismatch")
	ErrAudienceMismatch         = errors.New("ssoclient: audience mismatch")
	ErrLogoutNotConfigured      = errors.New("ssoclient: logout not configured")
	ErrInvalidGrant             = errors.New("invalid_grant")
	ErrInvalidClient            = errors.New("invalid_client")
	ErrInvalidScope             = errors.New("invalid_scope")
	ErrUnsupportedGrantType     = errors.New("unsupported_grant_type")
	ErrAuthorizationRejected    = errors.New("authorization_rejected")
	ErrInvalidAuthorizationFlow = errors.New("invalid_authorization_flow")
)

// AuthorizationError is returned when the authorization endpoint redirects
// back with an OAuth error instead of a code.
type AuthorizationError struct {
	Code        string
	Description string
}

func (e *AuthorizationError) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("ssoclient: authorization rejected: %s", e.Code)
	}
	return fmt.Sprintf("ssoclient: authorization rejected: %s: %s", e.Code, e.Description)
}

func (e *AuthorizationError) Unwrap() error { return ErrAuthorizationRejected }

// TokenError preserves the OAuth error code without inventing server detail.
type TokenError struct {
	Status      int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("ssoclient: token endpoint HTTP %d: %s", e.Status, e.Code)
	}
	return fmt.Sprintf("ssoclient: token endpoint HTTP %d: %s: %s", e.Status, e.Code, e.Description)
}

func (e *TokenError) Unwrap() error {
	switch e.Code {
	case "invalid_grant":
		return ErrInvalidGrant
	case "invalid_client":
		return ErrInvalidClient
	case "invalid_scope":
		return ErrInvalidScope
	case "unsupported_grant_type":
		return ErrUnsupportedGrantType
	default:
		return nil
	}
}
