package authenticators

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/spi"
)

// PasswordVerifier looks up a user record by username and checks the supplied
// password. Implementations should use a constant-time hash comparison
// (bcrypt, argon2, etc.).
type PasswordVerifier interface {
	Verify(ctx context.Context, username, password string) (*sso.AuthResult, error)
}

// PasswordVerifierFunc adapts a function to the PasswordVerifier interface.
type PasswordVerifierFunc func(ctx context.Context, username, password string) (*sso.AuthResult, error)

func (f PasswordVerifierFunc) Verify(ctx context.Context, u, p string) (*sso.AuthResult, error) {
	return f(ctx, u, p)
}

// PasswordAuthenticator authenticates users with a username + password pair.
type PasswordAuthenticator struct {
	verifier PasswordVerifier
	health   spi.PasswordHealthChecker // optional; nil = no signal, zero overhead
}

// PasswordOption configures a PasswordAuthenticator at construction.
type PasswordOption func(*PasswordAuthenticator)

// WithPasswordHealthChecker attaches an optional login-time
// credential-health signal. The checker runs ONLY after the password
// verifies, never blocks login, and surfaces purely as an advisory on the
// returned AuthResult (the login orchestrator audits it). A nil checker —
// or simply not passing this option — disables the check with zero
// overhead.
func WithPasswordHealthChecker(c spi.PasswordHealthChecker) PasswordOption {
	return func(p *PasswordAuthenticator) { p.health = c }
}

func NewPasswordAuthenticator(v PasswordVerifier, opts ...PasswordOption) *PasswordAuthenticator {
	p := &PasswordAuthenticator{verifier: v}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *PasswordAuthenticator) Name() string { return MethodPassword }

func (p *PasswordAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	username := req.Credential["username"]
	password := req.Credential["password"]
	if username == "" || password == "" {
		return nil, errors.New("password: username and password required")
	}
	result, err := p.verifier.Verify(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	if result.Provider == "" {
		result.Provider = p.Name()
	}
	if len(result.AuthMethods) == 0 {
		result.AuthMethods = []string{AuthMethodPwd}
	}
	// Credential-health signal: runs ONLY on a verified password (login
	// is the sole plaintext touchpoint in this server). Fail-open — a
	// checker error must never turn a valid login into a failure, and the
	// authenticator holds no logger, so the error is swallowed. A non-nil
	// signal rides back on the AuthResult for the orchestrator to audit;
	// it is never serialized into a token.
	if p.health != nil {
		if signal, hErr := p.health.Check(ctx, password); hErr == nil && signal != nil {
			result.CredentialHealth = signal
		}
	}
	return result, nil
}

func (p *PasswordAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("password: callback not supported")
}

func (p *PasswordAuthenticator) LoginURL(_ string) string { return "" }
