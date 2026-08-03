package authenticators

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
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
	if err := dispatchCodeDelivery(ctx, e.sender, email, code, func(failureCtx context.Context) {
		invalidateUndeliveredCode(failureCtx, e.store, e.key(email), code)
	}); err != nil {
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

func (e *EmailAuthenticator) CloseCodeDelivery(ctx context.Context) error {
	if closer, ok := e.sender.(interface{ Close(context.Context) error }); ok {
		return closer.Close(ctx)
	}
	return nil
}

// ============================================================================
// MagicLinkAuthenticator
// ============================================================================

// MagicLinkAuthenticator authenticates a user via a clickable link emailed to
// them, embedding a high-entropy opaque token. Functionally this IS
// EmailAuthenticator with two differences: (1) SendCode generates a long
// GenerateOpaqueToken value instead of a short human-typed GenerateNumericCode
// digit string, and (2) the value handed to EmailSender.Send is a full
// clickable URL rather than a bare code. Authenticate is otherwise UNCHANGED
// from EmailAuthenticator — it reads the SAME req.Credential["email"] /
// ["code"] keys and calls the SAME CodeStore.Verify, so the login-UI landing
// page for the clicked link only needs to parse the link's token/email and
// POST them to the EXISTING /auth/login as provider=magiclink,
// credential={email, code:<token>}. No interface or request-binding change
// anywhere in interfaces/sso was needed for this authenticator to work.
//
// Folded into email.go rather than a dedicated magic_link.go: domains/
// authenticators is pinned at its frozen 18-non-test-file fan-out ceiling
// (directory_fanout_test.go dirFileCountExemptions) and this type is
// EmailAuthenticator's closest sibling — see AGENTS.md §0.1 directory-depth /
// fan-out gate.
type MagicLinkAuthenticator struct {
	store       CodeStore
	sender      EmailSender
	baseURL     string
	tokenLength int
	ttl         time.Duration
}

type MagicLinkOption func(*MagicLinkAuthenticator)

// WithMagicLinkTokenLength overrides the opaque token's crypto/rand BYTE
// length (before base64url encoding); default DefaultMagicLinkTokenBytes.
func WithMagicLinkTokenLength(n int) MagicLinkOption {
	return func(m *MagicLinkAuthenticator) { m.tokenLength = n }
}

// WithMagicLinkTTL overrides how long the emailed link remains valid;
// default DefaultMagicLinkTTL.
func WithMagicLinkTTL(d time.Duration) MagicLinkOption {
	return func(m *MagicLinkAuthenticator) { m.ttl = d }
}

// NewMagicLinkAuthenticator builds a MagicLinkAuthenticator. baseURL is the
// login-UI landing page the emailed link points at (e.g.
// "https://sso.example.com/login/") — SendCode appends the token/email as
// query/fragment values, it never appends a path segment, so baseURL MUST
// resolve to an actual served page on its own (a bare static file server, as
// this SDK's hosted login SPA is, has no path-based SPA fallback). An empty
// baseURL is accepted here (every sibling NewX constructor is panic/error
// free) but produces an unusable link; callers wiring this in MUST validate
// it non-empty before enabling the authenticator — see cmd/sso-server's
// appendMagicLinkAuthenticator, which fails the boot loudly instead.
func NewMagicLinkAuthenticator(store CodeStore, sender EmailSender, baseURL string, opts ...MagicLinkOption) *MagicLinkAuthenticator {
	m := &MagicLinkAuthenticator{
		store:       store,
		sender:      sender,
		baseURL:     baseURL,
		tokenLength: DefaultMagicLinkTokenBytes,
		ttl:         DefaultMagicLinkTTL,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *MagicLinkAuthenticator) Name() string { return MethodMagicLink }

// LockoutIdentity mirrors EmailAuthenticator: lockout is keyed on the actual
// email this authenticator verifies (core.LockoutKeyer), not generic
// credential-field precedence, which an attacker could defeat by injecting a
// higher-precedence field this authenticator ignores.
func (m *MagicLinkAuthenticator) LockoutIdentity(credential map[string]string) string {
	return strings.ToLower(strings.TrimSpace(credential["email"]))
}

// SendCode generates an opaque token, stores it, and emails a clickable
// magic link.
//
// Anti-enumeration (AGENTS.md §3): behaves identically regardless of whether
// email corresponds to a real account — it mirrors EmailAuthenticator.
// SendCode exactly, which never consults a UserProvider or checks account
// existence at all; it unconditionally saves + sends for any syntactically
// valid address. The only rejection path is a 400 for a malformed address
// (shared by every caller, real account or not) — never an existence oracle.
//
// URL shape: baseURL + "?token=" + token + "#email=" + escaped-email —
// deliberately NOT "?email=...&token=..." (see the doc comment on
// buildMessage-adjacent otp.tmpl rendering in infrastructure/defaultimpl/
// emailsmtp): that template renders the OTP body through html/template for
// XSS-hardening (defense-in-depth against control/markup injection in an
// interpolated field — see emailsmtp/templates.go's templateEntry comment),
// which HTML-entity-escapes a literal "&" in the value to "&amp;". A
// bare-code OTP or a single-query-param link (e.g. password_reset.tmpl's
// "?token={{.Token}}") never contains "&" so this never surfaced before;
// splitting email into a "#" fragment instead of a second "&"-joined query
// param keeps the ENTIRE link free of "&", "<", ">", '"', "'" (url.
// QueryEscape percent-encodes all of them in the email value; the base64url
// token alphabet never contains any), so it survives that escaping
// unchanged with ZERO changes to emailsmtp. The query/fragment split also
// costs nothing server-side: both are client-only and never reach the
// static file server baseURL resolves to.
func (m *MagicLinkAuthenticator) SendCode(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("magiclink: valid email address required")
	}
	token, err := GenerateOpaqueToken(m.tokenLength)
	if err != nil {
		return fmt.Errorf("magiclink: generate token: %w", err)
	}
	if err := m.store.Save(ctx, m.key(email), token, m.ttl); err != nil {
		return fmt.Errorf("magiclink: save token: %w", err)
	}
	link := m.baseURL + "?token=" + token + "#email=" + url.QueryEscape(email)
	// Reuses EmailSender.Send(ctx, email, code) verbatim, passing the full
	// link in the "code" slot: EmailSender is just "deliver this string to
	// this address" — the built-in SMTP Sender's Send (infrastructure/
	// defaultimpl/emailsmtp/sender.go) embeds whatever it's given into
	// otp.tmpl's {{.Code}} with no assumption that it's short or numeric.
	// Extending the interface with a second, link-specific method would only
	// widen the surface every EmailSender implementation must satisfy, for
	// no behavioral gain.
	if err := dispatchCodeDelivery(ctx, m.sender, email, link, func(failureCtx context.Context) {
		invalidateUndeliveredCode(failureCtx, m.store, m.key(email), token)
	}); err != nil {
		return fmt.Errorf("magiclink: send: %w", err)
	}
	return nil
}

func (m *MagicLinkAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	email := strings.ToLower(strings.TrimSpace(req.Credential["email"]))
	token := req.Credential["code"]
	if email == "" || token == "" {
		return nil, errors.New("magiclink: email and code required")
	}
	if err := m.store.Verify(ctx, m.key(email), token); err != nil {
		return nil, err
	}
	return &sso.AuthResult{
		// Same subjectPrefixEmail scheme as EmailAuthenticator (not a
		// magiclink-specific prefix): account resolution in this SDK keys on
		// the literal UserID string (interfaces/sso upserts on User.ID, no
		// (Provider,ExternalID) lookup gates it), so a user who verifies the
		// SAME email via a magic link lands on the SAME account as one who
		// verifies it via the numeric email-OTP code — the two are just
		// different delivery mechanisms for one underlying "this email is
		// verified" identity. Provider below stays MethodMagicLink for
		// audit/display; it plays no role in that resolution.
		UserID:     subjectPrefixEmail + email,
		ExternalID: email,
		Provider:   m.Name(),
		Attributes: map[string]string{"email": email},
		// Reuses the existing AuthMethodOTPLink ("otp_link") RFC 8176-style
		// AMR tag rather than minting a new constant: it already exists
		// (domains/authenticators/consts.go) for exactly this class of
		// authentication ("a one-time link delivered out-of-band") and
		// TempTokenAuthenticator already stamps it for the generic magic-
		// link/password-reset/device-transfer case. A distinct
		// "magiclink"-only AMR value isn't warranted — relying parties doing
		// step-up/ACR logic care that this was link-based OTP, not which of
		// the two link-issuing authenticators produced it.
		AuthMethods: []string{AuthMethodOTPLink},
	}, nil
}

func (m *MagicLinkAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("magiclink: callback not supported")
}

func (m *MagicLinkAuthenticator) LoginURL(_ string) string { return "" }

func (m *MagicLinkAuthenticator) key(email string) string { return keyPrefixMagicLink + email }

func (m *MagicLinkAuthenticator) CloseCodeDelivery(ctx context.Context) error {
	if closer, ok := m.sender.(interface{ Close(context.Context) error }); ok {
		return closer.Close(ctx)
	}
	return nil
}

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
