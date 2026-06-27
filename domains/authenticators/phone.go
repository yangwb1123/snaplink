package authenticators

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// SMSSender delivers a verification code to a phone number.
type SMSSender interface {
	Send(ctx context.Context, phone, code string) error
}

// SMSSenderFunc adapts a function to the SMSSender interface.
type SMSSenderFunc func(ctx context.Context, phone, code string) error

func (f SMSSenderFunc) Send(ctx context.Context, phone, code string) error {
	return f(ctx, phone, code)
}

// PhoneAuthenticator authenticates a user via a one-time code sent over SMS.
//
// Two-step flow:
//
//	SendCode(phone) -> code stored, code SMSed to user
//	Authenticate(phone, code) -> verified against store, code consumed
type PhoneAuthenticator struct {
	store      CodeStore
	sender     SMSSender
	codeLength int
	ttl        time.Duration
}

type PhoneOption func(*PhoneAuthenticator)

func WithPhoneCodeLength(n int) PhoneOption        { return func(p *PhoneAuthenticator) { p.codeLength = n } }
func WithPhoneCodeTTL(d time.Duration) PhoneOption { return func(p *PhoneAuthenticator) { p.ttl = d } }

func NewPhoneAuthenticator(store CodeStore, sender SMSSender, opts ...PhoneOption) *PhoneAuthenticator {
	p := &PhoneAuthenticator{
		store:      store,
		sender:     sender,
		codeLength: DefaultCodeLength,
		ttl:        DefaultPhoneCodeTTL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *PhoneAuthenticator) Name() string { return MethodPhone }

// LockoutIdentity keys per-account lockout on the phone number this
// authenticator actually verifies (core.LockoutKeyer) — NOT the generic field
// precedence, which an attacker could defeat by injecting a higher-precedence
// `username` this authenticator ignores. Matches Authenticate's raw read.
func (p *PhoneAuthenticator) LockoutIdentity(credential map[string]string) string {
	return credential["phone"]
}

// SendCode generates and dispatches a verification code for the given phone number.
func (p *PhoneAuthenticator) SendCode(ctx context.Context, phone string) error {
	if phone == "" {
		return errors.New("phone: phone number required")
	}
	code, err := GenerateNumericCode(p.codeLength)
	if err != nil {
		return fmt.Errorf("phone: generate code: %w", err)
	}
	if err := p.store.Save(ctx, p.key(phone), code, p.ttl); err != nil {
		return fmt.Errorf("phone: save code: %w", err)
	}
	if err := p.sender.Send(ctx, phone, code); err != nil {
		return fmt.Errorf("phone: send sms: %w", err)
	}
	return nil
}

func (p *PhoneAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	phone := req.Credential["phone"]
	code := req.Credential["code"]
	if phone == "" || code == "" {
		return nil, errors.New("phone: phone and code required")
	}
	if err := p.store.Verify(ctx, p.key(phone), code); err != nil {
		return nil, err
	}
	return &sso.AuthResult{
		UserID:      subjectPrefixPhone + phone,
		ExternalID:  phone,
		Provider:    p.Name(),
		Attributes:  map[string]string{"phone": phone},
		AuthMethods: []string{AuthMethodSMS},
	}, nil
}

func (p *PhoneAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("phone: callback not supported")
}

func (p *PhoneAuthenticator) LoginURL(_ string) string { return "" }

func (p *PhoneAuthenticator) key(phone string) string { return keyPrefixPhone + phone }
