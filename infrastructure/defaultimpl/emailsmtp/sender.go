package emailsmtp

import (
	"context"
	"fmt"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

// tmplData is the template execution context. Not every field is populated
// for every message type (SendResetToken sets Target+Token, Send sets
// Email+Code, ...) — each embedded template references only the fields
// relevant to its own message type.
type tmplData struct {
	Token, Code, Target, Email, NewEmail, TenantID, Role, LinkBaseURL, From string
}

// Sender is the built-in net/smtp implementation of the four shared/spi
// token-delivery senders plus the OTP email transport. It structurally
// satisfies domains/authenticators.EmailSender (Send(ctx, email, code) error)
// without importing that package — domains/authenticators sits ABOVE
// infrastructure/ in the layer order (architecture_layer_test.go), so the
// interface guard lives at the cmd wiring site instead (see
// cmd/sso-server/serverbuildauthn), not here.
type Sender struct {
	cfg  Config
	tmpl *templateSet
	send sendFunc
	now  func() time.Time
	log  spi.Logger
}

// Option configures a Sender at construction.
type Option func(*Sender)

// WithSendFunc overrides the transport (default net/smtp.SendMail via
// defaultSendFunc) — the legitimate seam tests use to capture outbound mail
// without a live SMTP server. Nil is ignored so a zero-value Option is inert.
func WithSendFunc(fn sendFunc) Option {
	return func(s *Sender) {
		if fn != nil {
			s.send = fn
		}
	}
}

// New builds a Sender from cfg, parsing the embedded default templates and
// overlaying cfg.TemplatesDir when set.
func New(cfg Config, log spi.Logger, opts ...Option) (*Sender, error) {
	ts, err := newTemplateSet(cfg.TemplatesDir)
	if err != nil {
		return nil, fmt.Errorf("emailsmtp: load templates: %w", err)
	}
	if log == nil {
		log = spi.NopLogger{}
	}
	s := &Sender{cfg: cfg, tmpl: ts, send: defaultSendFunc, now: time.Now, log: log}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

var (
	_ spi.PasswordResetSender     = (*Sender)(nil)
	_ spi.EmailVerificationSender = (*Sender)(nil)
	_ spi.EmailChangeSender       = (*Sender)(nil)
	_ spi.InvitationSender        = (*Sender)(nil)
)

// SendResetToken implements spi.PasswordResetSender.
func (s *Sender) SendResetToken(_ context.Context, target, token string) error {
	return s.deliver(tmplPasswordReset, target, tmplData{
		Target: target, Token: token, LinkBaseURL: s.cfg.LinkBaseURL, From: s.cfg.From,
	})
}

// SendEmailVerificationToken implements spi.EmailVerificationSender.
func (s *Sender) SendEmailVerificationToken(_ context.Context, email, token string) error {
	return s.deliver(tmplEmailVerification, email, tmplData{
		Email: email, Token: token, LinkBaseURL: s.cfg.LinkBaseURL, From: s.cfg.From,
	})
}

// SendEmailChangeToken implements spi.EmailChangeSender. Delivery target is
// the NEW address (proves control of it) — matches the interface doc comment.
func (s *Sender) SendEmailChangeToken(_ context.Context, newEmail, token string) error {
	return s.deliver(tmplEmailChange, newEmail, tmplData{
		NewEmail: newEmail, Token: token, LinkBaseURL: s.cfg.LinkBaseURL, From: s.cfg.From,
	})
}

// SendInvitation implements spi.InvitationSender.
func (s *Sender) SendInvitation(_ context.Context, email, tenantID, role, token string) error {
	return s.deliver(tmplInvitation, email, tmplData{
		Email: email, TenantID: tenantID, Role: role, Token: token,
		LinkBaseURL: s.cfg.LinkBaseURL, From: s.cfg.From,
	})
}

// Send is the email-OTP transport domains/authenticators.EmailSender dials
// (structural satisfaction — see the Sender doc comment for why the
// interface guard is not declared in this package).
func (s *Sender) Send(_ context.Context, email, code string) error {
	return s.deliver(tmplOTP, email, tmplData{Email: email, Code: code, From: s.cfg.From})
}

// deliver renders the template then dispatches the actual SMTP send on a
// background goroutine and returns nil immediately. REQUIRED for
// anti-enumeration: /auth/forgot-password only calls the sender for a KNOWN
// account (protocols/selfservice/password_reset.go), so a blocking send
// would make known-account responses measurably slower than unknown-account
// ones — a timing oracle (AGENTS.md Anti-Enumeration). Render failures are
// logged (never the token/target) and swallowed (fail-open, matching the
// existing sender contract).
func (s *Sender) deliver(name, to string, data tmplData) error {
	subject, body, err := s.tmpl.render(name, data)
	if err != nil {
		s.log.Error("emailsmtp: render failed", "template", name, "error", err)
		return nil
	}
	msg := buildMessage(s.cfg.From, to, subject, body, s.now())
	go s.dispatch(to, msg)
	return nil
}
