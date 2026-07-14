package spi

import (
	"context"
	"errors"
	"unicode"
)

// CaptchaTokenContextKey is the context key used to pass a captcha token from
// the HTTP handler to CaptchaGate during self-service registration. The
// handler stores the raw captcha_token string under this key; CaptchaGate
// reads it before calling the CaptchaVerifier.
type CaptchaTokenContextKey struct{}

// RegistrationGate is the SPI for self-service registration abuse-protection
// gates. Implementations check a registration attempt and return nil to allow
// it or an error to reject it. Implementations MUST NOT log the password or
// raw captcha token — only the identifier + reason.
//
// Gates are composable: wire zero or more with WithRegistrationGates. When
// none are wired, the registration behaviour is unchanged (backward compat).
type RegistrationGate interface {
	CheckRegistration(ctx context.Context, username, email, ip string) error
}

// CaptchaVerifier verifies a captcha token for self-service registration.
// Implementations wrap a real CAPTCHA provider (e.g. hCaptcha, reCAPTCHA).
// When nil, CaptchaGate silently skips the check.
type CaptchaVerifier interface {
	Verify(ctx context.Context, captchaToken string) error
}

// ErrPasswordPolicyViolation is returned by PasswordPolicyValidator when a
// proposed password fails to meet the configured policy rules. The error
// message is deliberately generic to prevent enumeration of policy internals.
var ErrPasswordPolicyViolation = errors.New("password does not meet policy requirements")

// PasswordPolicyValidator validates a proposed password against policy rules.
type PasswordPolicyValidator interface {
	ValidatePassword(ctx context.Context, password string) error
}

// PasswordMaxAgeProvider is an OPTIONAL extension a PasswordPolicyValidator MAY
// satisfy to expose its configured MaxAgeDays to the login-time password-expiry
// gate (interfaces/sso rejectExpiredPassword). Kept separate from
// ValidatePassword (a NEW-password strength/history check run at signup /
// change-password time) because MaxAgeDays instead judges an EXISTING
// credential's age at LOGIN time — a different call shape entirely, and one
// that belongs at the composition/server layer (mirroring how
// max_active_sessions is enforced in interfaces/sso, not baked into an
// authenticator). Callers type-assert; a validator that doesn't implement it
// makes the dimension a no-op, same as MaxAgeDays<=0.
type PasswordMaxAgeProvider interface {
	// PasswordMaxAgeDays returns the configured maximum password age in days,
	// or 0 when the dimension is not enforced.
	PasswordMaxAgeDays() int
}

// PasswordPolicyConfig carries the operator-configured password policy rules.
// Zero values mean the corresponding rule is not enforced (backward compatible).
type PasswordPolicyConfig struct {
	MinLength      int  // minimum password length (0 = no minimum)
	RequireUpper   bool // require at least one uppercase letter
	RequireLower   bool // require at least one lowercase letter
	RequireDigit   bool // require at least one digit
	RequireSpecial bool // require at least one special character
	MaxHistory     int  // number of previous passwords to check (0 = no history)
	// MaxAgeDays is the password maximum age in days (0 = no expiry).
	// Enforced at LOGIN time, not here in ValidatePassword — see
	// PasswordMaxAgeProvider and interfaces/sso's rejectExpiredPassword.
	MaxAgeDays int
}

type passwordPolicyValidator struct {
	cfg PasswordPolicyConfig
}

// NewPasswordPolicyValidator creates a PasswordPolicyValidator from config.
func NewPasswordPolicyValidator(cfg PasswordPolicyConfig) PasswordPolicyValidator {
	return &passwordPolicyValidator{cfg: cfg}
}

// PasswordMaxAgeDays implements PasswordMaxAgeProvider, exposing the
// configured MaxAgeDays to the login-time password-expiry gate.
func (v *passwordPolicyValidator) PasswordMaxAgeDays() int { return v.cfg.MaxAgeDays }

func (v *passwordPolicyValidator) ValidatePassword(_ context.Context, password string) error {
	if v.cfg.MinLength > 0 && len(password) < v.cfg.MinLength {
		return ErrPasswordPolicyViolation
	}
	if v.cfg.RequireUpper && !hasRune(password, unicode.IsUpper) {
		return ErrPasswordPolicyViolation
	}
	if v.cfg.RequireLower && !hasRune(password, unicode.IsLower) {
		return ErrPasswordPolicyViolation
	}
	if v.cfg.RequireDigit && !hasRune(password, unicode.IsDigit) {
		return ErrPasswordPolicyViolation
	}
	if v.cfg.RequireSpecial && !hasSpecial(password) {
		return ErrPasswordPolicyViolation
	}
	return nil
}

// hasRune checks whether string s contains at least one rune satisfying pred.
func hasRune(s string, pred func(rune) bool) bool {
	for _, r := range s {
		if pred(r) {
			return true
		}
	}
	return false
}

// hasSpecial checks whether string s contains at least one special character
// (anything that is not upper, lower, digit, or whitespace).
func hasSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsUpper(r) && !unicode.IsLower(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}
