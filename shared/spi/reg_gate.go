package spi

import "context"

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
