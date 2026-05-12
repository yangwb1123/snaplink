package authenticators

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso"
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
}

func NewPasswordAuthenticator(v PasswordVerifier) *PasswordAuthenticator {
	return &PasswordAuthenticator{verifier: v}
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
	return result, nil
}

func (p *PasswordAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("password: callback not supported")
}

func (p *PasswordAuthenticator) LoginURL(_ string) string { return "" }
