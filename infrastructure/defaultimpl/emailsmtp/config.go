// Package emailsmtp is the built-in net/smtp implementation of the four
// shared/spi token-delivery senders (password reset, email verification,
// email change, org invitation) plus the email-OTP transport
// domains/authenticators.EmailSender dials. It is the default, zero-external-
// dependency way the runnable sso-server binary actually delivers mail; an
// operator with a transactional-email provider can still supply their own
// spi.*Sender implementation via the SDK options instead.
package emailsmtp

import "time"

// Config configures the built-in SMTP sender. Field-for-field mirror of
// config.SMTPConfig (cmd/sso-server/serverbuildplatform translates one into
// the other at the wiring site). Kept as an independent type rather than
// importing the config package directly: config/ is a composition-layer
// package (layer rank 6 in architecture_layer_test.go) while
// infrastructure/ is rank 4, and the layer gate only allows a package to
// import its own layer or a strictly lower (more-shared) one — an
// infrastructure package importing config would be an upward edge the gate
// rejects, and the exemption list is frozen (shrink-only, no new entries).
// domains/authenticators.OIDCFederationConfig / config.OIDCFederationAuthConfig
// is the same split for the same reason.
type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	// Password is typically injected via config/secrets.go secret:// resolution
	// or the SSO_SMTP__PASSWORD env override, never a plaintext YAML default.
	Password string
	From     string
	// StartTLS is documentation-only: net/smtp.SendMail negotiates STARTTLS
	// automatically whenever the server advertises it and falls back to
	// plaintext otherwise — the pre-existing 587/25 behavior, unchanged — so
	// there is no separate code path to gate. Implicit TLS (port 465, which
	// SendMail cannot do) is selected by port or TLSMode; see TLSMode.
	StartTLS bool
	// TLSMode selects the transport's TLS behavior. "" or "auto": implicit
	// TLS (a crypto/tls.Dial before the first SMTP verb) on port 465 only;
	// every other port keeps net/smtp.SendMail's STARTTLS-when-advertised
	// negotiation (may fall back to plaintext — require TLS at the
	// relay/edge if that is unacceptable). "implicit": TLS handshake before
	// the first SMTP verb regardless of port (non-465 implicit-TLS relays).
	// Any other value is treated as "auto". Verification is always
	// fail-closed: ServerName is the relay host, the TLS floor is 1.2, and
	// InsecureSkipVerify is never set.
	TLSMode string
	// Timeout bounds each background send goroutine dispatch fires off; 0
	// (the SDK default) uses defaultTimeout.
	Timeout time.Duration
	// TemplatesDir overlays the five go:embed default templates from disk
	// when set; empty = embedded defaults only.
	TemplatesDir string
	// LinkBaseURL is prefixed to reset/verify/invite links. Required: the
	// sender only ever sees the token/target the calling spi.*Sender method
	// hands it, never server.issuer, so it cannot construct a link otherwise.
	LinkBaseURL string
}
