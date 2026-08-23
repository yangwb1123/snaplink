// Package activation owns short-lived product activation credentials.
//
// Activation is deliberately separate from authentication and commerce. A
// code may point at a tenant entitlement, but it is never itself an OAuth
// credential and it never enters the commerce subscription aggregate.
package activation

import (
	"context"
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const DefaultTicketTTL = 5 * time.Minute

var (
	ErrInvalidActivation = errors.New("activation: invalid activation")
	ErrCodeConflict      = errors.New("activation: code conflict")
	ErrInvalidCode       = errors.New("activation: invalid code")
)

// Code is the operator-side provisioning record. Key and InvitationCode are
// accepted only when a code is added; MemoryStore stores their digests.
type Code struct {
	ID             string
	ProductID      string
	TenantID       string
	Key            string `json:"-"`
	InvitationCode string `json:"-"`
	Entitlement    *commerce.EntitlementSnapshot
	ExpiresAt      time.Time
	// MaxClaims defaults to one. A key is a one-time tenant claim; subsequent
	// logins use the stored binding rather than asking the user for the key.
	MaxClaims int
}

// PrepareInput is the unauthenticated activation request. Exactly one of
// LicenseKey and InvitationCode must be supplied.
type PrepareInput struct {
	ClientID       string
	ProductID      string
	LicenseKey     string
	InvitationCode string
	TenantHint     string
}

type ClaimInput struct {
	Ticket    string
	ClientID  string
	ProductID string
	Subject   string
}

type CurrentInput struct {
	ClientID  string
	ProductID string
	Subject   string
}

type Preparation struct {
	Ticket    string
	ProductID string
	ExpiresAt time.Time
}

// AccountContext is the safe, user-scoped projection returned after login.
// The service may omit Entitlement when the activation backend has no local
// entitlement projection; access enforcement remains server-side.
type AccountContext struct {
	ProductID   string                        `json:"product_id"`
	TenantID    string                        `json:"tenant_id"`
	Entitlement *commerce.EntitlementSnapshot `json:"entitlement,omitempty"`
}

type Store interface {
	Prepare(context.Context, PrepareInput) (*Preparation, error)
	Claim(context.Context, ClaimInput) (*AccountContext, error)
	Current(context.Context, CurrentInput) (*AccountContext, error)
}

func validatePrepareInput(input PrepareInput) error {
	if !validIdentifier(input.ClientID) || !validIdentifier(input.ProductID) {
		return ErrInvalidActivation
	}
	if (input.LicenseKey == "") == (input.InvitationCode == "") {
		return ErrInvalidActivation
	}
	if input.TenantHint != "" && !validIdentifier(input.TenantHint) {
		return ErrInvalidActivation
	}
	return nil
}

func validateClaimInput(input ClaimInput) error {
	if !validIdentifier(input.ClientID) || !validIdentifier(input.ProductID) ||
		!validIdentifier(input.Subject) || input.Ticket == "" {
		return ErrInvalidActivation
	}
	return nil
}

func validateCurrentInput(input CurrentInput) error {
	if !validIdentifier(input.ClientID) || !validIdentifier(input.ProductID) ||
		!validIdentifier(input.Subject) {
		return ErrInvalidActivation
	}
	return nil
}

func validIdentifier(value string) bool {
	return value != "" && value == trim(value) && len(value) <= 256 && !containsNUL(value)
}

func trim(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n' || value[0] == '\r') {
		value = value[1:]
	}
	for len(value) > 0 && (value[len(value)-1] == ' ' || value[len(value)-1] == '\t' || value[len(value)-1] == '\n' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	return value
}

func containsNUL(value string) bool {
	for _, char := range value {
		if char == 0 {
			return true
		}
	}
	return false
}
