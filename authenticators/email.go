package authenticators

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
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
