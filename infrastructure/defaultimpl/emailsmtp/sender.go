package emailsmtp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// tmplData is the template execution context. Not every field is populated
// for every message type (SendResetToken sets Target+Token, Send sets
// Email+Code, ...) — each embedded template references only the fields
// relevant to its own message type.
type tmplData struct {
	Token, Code, Target, Email, NewEmail, TenantID, Role, ActionURL, From, Title, Body string
}

const (
	actionResetPassword = "reset_password"
	actionVerifyEmail   = "verify_email"
	actionChangeEmail   = "change_email"
	actionInvitation    = "invitation"
)

// NotificationEmailResolver maps a stable subject to its current verified
// delivery address. Returning an error fails only the email channel.
type NotificationEmailResolver func(context.Context, string) (string, error)

// NotificationSender adapts Sender to the generic notification channel.
type NotificationSender struct {
	sender  *Sender
	resolve NotificationEmailResolver
}

func NewNotificationSender(sender *Sender, resolve NotificationEmailResolver) *NotificationSender {
	return &NotificationSender{sender: sender, resolve: resolve}
}

func (s *NotificationSender) SendNotification(ctx context.Context, event *core.NotificationEvent) error {
	if s == nil || s.sender == nil || s.resolve == nil || event == nil || event.SubjectID == "" {
		return errors.New("emailsmtp: notification sender is not configured")
	}
	email, err := s.resolve(ctx, event.SubjectID)
	if err != nil {
		return err
	}
	if email == "" {
		return errors.New("emailsmtp: notification recipient has no email")
	}
	subject, body, err := s.sender.tmpl.render(tmplNotification, tmplData{Title: event.Title, Body: event.Body, Email: email, From: s.sender.cfg.From})
	if err != nil {
		return err
	}
	message := buildMessage(s.sender.cfg.From, email, subject, body, s.sender.now())
	return s.sender.sendMessage(ctx, email, message)
}

var _ core.NotificationSender = (*NotificationSender)(nil)

// Sender is the built-in net/smtp implementation of the four shared/spi
// token-delivery senders plus the OTP email transport. It structurally
// satisfies domains/authenticators.EmailSender (Send(ctx, email, code) error)
// without importing that package — domains/authenticators sits ABOVE
// infrastructure/ in the layer order (architecture_layer_test.go), so the
// interface guard lives at the cmd wiring site instead (see
// cmd/sso-server/serverbuildauthn), not here.
type Sender struct {
	cfg     Config
	tmpl    *templateSet
	send    sendFunc
	dialTLS tlsDialFunc
	now     func() time.Time
	log     spi.Logger
}

// Option configures a Sender at construction.
type Option func(*Sender)

// WithSendFunc overrides the transport (default net/smtp.SendMail via
// defaultSendFunc) — the legitimate seam tests use to capture outbound mail
// without a live SMTP server. Nil is ignored so a zero-value Option is inert.
// It only affects the non-implicit-TLS path: an implicit-TLS send (port 465
// or tls_mode=implicit) always uses the TLS transport, which is overridden
// with WithTLSDial instead.
func WithSendFunc(fn sendFunc) Option {
	return func(s *Sender) {
		if fn != nil {
			s.send = fn
		}
	}
}

// WithTLSDial overrides the TLS dial used by the implicit-TLS transport
// (default crypto/tls.Dial). Nil is ignored. Tests inject a dial that trusts
// a throwaway CA so the real tls.Dial + handshake still runs against an
// in-process TLS SMTP listener while everything else about the sender's TLS
// config (ServerName, MinVersion, no InsecureSkipVerify) is exercised as-is.
func WithTLSDial(fn tlsDialFunc) Option {
	return func(s *Sender) {
		if fn != nil {
			s.dialTLS = fn
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
	s := &Sender{cfg: cfg, tmpl: ts, send: defaultSendFunc, dialTLS: defaultTLSDial, now: time.Now, log: log}
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
		Target: target, Token: token, ActionURL: actionLink(s.cfg.LinkBaseURL, actionResetPassword, token), From: s.cfg.From,
	})
}

// SendEmailVerificationToken implements spi.EmailVerificationSender.
func (s *Sender) SendEmailVerificationToken(_ context.Context, email, token string) error {
	return s.deliver(tmplEmailVerification, email, tmplData{
		Email: email, Token: token, ActionURL: actionLink(s.cfg.LinkBaseURL, actionVerifyEmail, token), From: s.cfg.From,
	})
}

// SendEmailChangeToken implements spi.EmailChangeSender. Delivery target is
// the NEW address (proves control of it) — matches the interface doc comment.
func (s *Sender) SendEmailChangeToken(_ context.Context, newEmail, token string) error {
	return s.deliver(tmplEmailChange, newEmail, tmplData{
		NewEmail: newEmail, Token: token, ActionURL: actionLink(s.cfg.LinkBaseURL, actionChangeEmail, token), From: s.cfg.From,
	})
}

// SendInvitation implements spi.InvitationSender.
func (s *Sender) SendInvitation(_ context.Context, email, tenantID, role, token string) error {
	return s.deliver(tmplInvitation, email, tmplData{
		Email: email, TenantID: tenantID, Role: role, Token: token,
		ActionURL: actionLink(s.cfg.LinkBaseURL, actionInvitation, token), From: s.cfg.From,
	})
}

func actionLink(base, action, token string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	query := u.Query()
	query.Set("flow", action)
	query.Set("token", token)
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return u.String()
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
