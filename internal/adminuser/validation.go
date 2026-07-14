package adminuser

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// Validation errors returned by the admin user CRUD service.
// These map to HTTP 400 Bad Request in the handler layer.
var (
	ErrValidationUsernameFormat = errors.New("adminuser: username must start with a letter and contain only letters, digits, underscores, or hyphens")
	ErrValidationUsernameLength = errors.New("adminuser: username must be 3-50 characters")
	ErrValidationEmailFormat   = errors.New("adminuser: invalid email format")
	ErrValidationPassword      = errors.New("adminuser: password must be at least 8 characters with at least one letter and one digit")
)

// Username validation constraints.
const (
	UsernameMinLen = 3
	UsernameMaxLen = 50
	PasswordMinLen = 8
)

var (
	// usernameRe allows alphanumeric [a-zA-Z0-9], underscore, and hyphen.
	// Must start with a letter.
	usernameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

	// emailRe follows RFC 5322 loosely — checks for a basic email shape.
	emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// ValidateUsername validates a username string.
// Rules:
//   - 3-50 characters
//   - Must start with a letter
//   - Only letters, digits, underscore, hyphen
func ValidateUsername(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return ErrValidationUsernameLength
	}
	if len(s) < UsernameMinLen || len(s) > UsernameMaxLen {
		return ErrValidationUsernameLength
	}
	if !usernameRe.MatchString(s) {
		return ErrValidationUsernameFormat
	}
	return nil
}

// ValidateEmail validates an email address.
// Uses a loose RFC 5322 pattern — does NOT perform DNS resolution or
// SMTP verification.
func ValidateEmail(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return ErrValidationEmailFormat
	}
	if len(s) > 254 { // RFC 5321 limit
		return ErrValidationEmailFormat
	}
	if !emailRe.MatchString(s) {
		return ErrValidationEmailFormat
	}
	return nil
}

// ValidatePassword validates a plaintext password against the server's
// policy. Rules:
//   - ≥8 characters
//   - Contains at least one letter
//   - Contains at least one digit
//
// This is the minimum policy the server enforces; operators can layer
// additional policy upstream (e.g. via a PasswordPolicyValidator SPI).
// The password is NEVER returned in any API response.
func ValidatePassword(s string) error {
	if len(s) < PasswordMinLen {
		return ErrValidationPassword
	}
	hasLetter := false
	hasDigit := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return ErrValidationPassword
	}
	return nil
}
