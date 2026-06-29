package authenticators

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"
)

// EmailSender delivers a verification code to an email address.
type EmailSender interface {
	Send(ctx context.Context, email, code string) error
}

// EmailSenderFunc adapts a function to the EmailSender interface.
type EmailSenderFunc func(ctx context.Context, email, code string) error

func (f EmailSenderFunc) Send(ctx context.Context, email, code string) error {
	return f(ctx, email, code)
}

// EmailAuthenticator authenticates a user via a one-time code sent to an email
// address. Uses the same two-step flow as PhoneAuthenticator.
type EmailAuthenticator struct {
	store      CodeStore
	sender     EmailSender
	codeLength int
	ttl        time.Duration
}

type EmailOption func(*EmailAuthenticator)

func WithEmailCodeLength(n int) EmailOption        { return func(e *EmailAuthenticator) { e.codeLength = n } }
func WithEmailCodeTTL(d time.Duration) EmailOption { return func(e *EmailAuthenticator) { e.ttl = d } }

func NewEmailAuthenticator(store CodeStore, sender EmailSender, opts ...EmailOption) *EmailAuthenticator {
	e := &EmailAuthenticator{
		store:      store,
		sender:     sender,
		codeLength: DefaultCodeLength,
		ttl:        DefaultEmailCodeTTL,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func (e *EmailAuthenticator) Name() string { return MethodEmail }

func (e *EmailAuthenticator) LockoutIdentity(credential map[string]string) string {
	return strings.ToLower(strings.TrimSpace(credential["email"]))
}

func (e *EmailAuthenticator) SendCode(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("email: valid email address required")
	}
	code, err := GenerateNumericCode(e.codeLength)
	if err != nil {
		return fmt.Errorf("email: generate code: %w", err)
	}
	if err := e.store.Save(ctx, e.key(email), code, e.ttl); err != nil {
		return fmt.Errorf("email: save code: %w", err)
	}
	if err := e.sender.Send(ctx, email, code); err != nil {
		return fmt.Errorf("email: send: %w", err)
	}
	return nil
}

func (e *EmailAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	email := strings.ToLower(strings.TrimSpace(req.Credential["email"]))
	code := req.Credential["code"]
	if email == "" || code == "" {
		return nil, errors.New("email: email and code required")
	}
	if err := e.store.Verify(ctx, e.key(email), code); err != nil {
		return nil, err
	}
	return &sso.AuthResult{
		UserID:      subjectPrefixEmail + email,
		ExternalID:  email,
		Provider:    e.Name(),
		Attributes:  map[string]string{"email": email},
		AuthMethods: []string{AuthMethodEmailOTP},
	}, nil
}

func (e *EmailAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("email: callback not supported")
}

func (e *EmailAuthenticator) LoginURL(_ string) string { return "" }

func (e *EmailAuthenticator) key(email string) string { return keyPrefixEmail + email }

// ============================================================================
// Registration abuse protection gates
// ============================================================================

// DomainAllowlistGate permits registration only from specified email domains.
// With an empty allowlist (the zero value), all domains are permitted — the
// gate is a no-op (backward compatible).
type DomainAllowlistGate struct {
	// AllowedDomains lists the email domains permitted to register.
	// Case-insensitive comparison. Empty = all domains permitted.
	AllowedDomains []string
}

// CheckRegistration implements spi.RegistrationGate.
func (g *DomainAllowlistGate) CheckRegistration(_ context.Context, _ string, email, _ string) error {
	if len(g.AllowedDomains) == 0 || email == "" {
		return nil
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("registration not permitted")
	}
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return errors.New("registration not permitted")
	}
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	for _, allowed := range g.AllowedDomains {
		if strings.ToLower(strings.TrimSpace(allowed)) == domain {
			return nil
		}
	}
	return errors.New("registration not permitted")
}

// CaptchaGateOption configures a CaptchaGate.
type CaptchaGateOption func(*CaptchaGate)

// WithCaptchaVerifier sets the captcha verification backend. Required for
// the gate to actually verify; without it the gate is a no-op.
func WithCaptchaVerifier(v spi.CaptchaVerifier) CaptchaGateOption {
	return func(g *CaptchaGate) { g.verifier = v }
}

// CaptchaGate checks a captcha token during registration. When no verifier
// is wired, the gate silently passes (no-op for backward compatibility).
type CaptchaGate struct {
	verifier spi.CaptchaVerifier
}

// NewCaptchaGate creates a captcha verification gate.
func NewCaptchaGate(opts ...CaptchaGateOption) *CaptchaGate {
	g := &CaptchaGate{}
	for _, o := range opts {
		o(g)
	}
	return g
}

// CheckRegistration implements spi.RegistrationGate.
func (g *CaptchaGate) CheckRegistration(ctx context.Context, _, _, _ string) error {
	if g.verifier == nil {
		return nil
	}
	token, _ := ctx.Value(spi.CaptchaTokenContextKey{}).(string)
	if token == "" {
		return errors.New("captcha verification required")
	}
	return g.verifier.Verify(ctx, token)
}
