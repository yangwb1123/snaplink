package emailsmtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// sendFunc matches net/smtp.SendMail's signature — the transport seam New
// defaults to defaultSendFunc and WithSendFunc overrides for tests, so tests
// never need a live SMTP server for sender/template coverage.
type sendFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

// tlsDialFunc establishes a TLS connection to addr using cfg — the seam the
// implicit-TLS transport dials through. New defaults it to crypto/tls.Dial;
// WithTLSDial overrides it for tests, mirroring WithSendFunc.
type tlsDialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)

// Config.TLSMode values. tlsModeAuto (the zero value, and the fallback for any
// unrecognized string) keeps the pre-implicit-TLS behavior byte-for-byte:
// port 465 selects implicit TLS, every other port goes through
// net/smtp.SendMail's opportunistic STARTTLS negotiation.
const (
	tlsModeAuto     = "auto"
	tlsModeImplicit = "implicit"
)

// defaultTimeout bounds a background send when cfg.Timeout is unset (<= 0).
const defaultTimeout = 10 * time.Second

// RFC5322 header names + values, centralized so buildMessage has no literal
// leaks (AGENTS.md "no literal leaks").
const (
	hdrFrom          = "From"
	hdrTo            = "To"
	hdrSubject       = "Subject"
	hdrDate          = "Date"
	hdrMessageID     = "Message-ID"
	hdrMIMEVersion   = "MIME-Version"
	hdrContentType   = "Content-Type"
	mimeVersion10    = "1.0"
	contentTypePlain = `text/plain; charset="utf-8"`
)

// defaultSendFunc is net/smtp.SendMail: it negotiates STARTTLS automatically
// whenever the server advertises it and falls back to plaintext otherwise, so
// smtp.starttls needs no separate code branch here (587/25 behavior is
// unchanged). Implicit TLS (port 465, which SendMail cannot do — it always
// starts with a plaintext dial) is served by implicitTLSSendFunc instead,
// selected in sendMessage when useImplicitTLS reports it.
func defaultSendFunc(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

// defaultTLSDial is crypto/tls.Dial adapted to tlsDialFunc's net.Conn return:
// tls.Dial's concrete *tls.Conn result is not assignable to a
// net.Conn-returning func type, so New wires this adapter as the default
// dialTLS instead of tls.Dial directly.
func defaultTLSDial(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.Dial(network, addr, cfg)
}

// implicitTLSConfig builds the TLS client config for an implicit-TLS session:
// ServerName pinned to the relay host (SNI + certificate verification name)
// and a TLS 1.2 floor. InsecureSkipVerify is NEVER set — a relay with an
// untrusted certificate must be terminated at the edge/relay, not silently
// trusted in software, so a verification failure is fail-closed.
func implicitTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}

// implicitTLSSendFunc is the port-465 transport: it establishes the TLS
// connection FIRST (crypto/tls.Dial) and only then speaks SMTP over it — the
// one thing net/smtp.SendMail cannot express, since SendMail always starts
// with a plaintext dial and only upgrades via STARTTLS. It mirrors
// SendMail's session steps (greet/hello via NewClient, optional AUTH, MAIL,
// RCPT, DATA write, QUIT) and wraps errors without echoing credentials or
// message contents.
func implicitTLSSendFunc(dial tlsDialFunc, tlsCfg *tls.Config, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls dial: %w", err)
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls address %q: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls session: %w", err)
	}
	if a != nil {
		if err := client.Auth(a); err != nil {
			return fmt.Errorf("emailsmtp: implicit-tls auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls mail: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("emailsmtp: implicit-tls rcpt: %w", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls data close: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("emailsmtp: implicit-tls quit: %w", err)
	}
	return nil
}

// dispatch performs the actual send on a background goroutine, decoupled
// from the request context (cancelled once the handler returns) so SMTP
// latency never blocks or lengthens the calling request — see deliver's doc
// comment for why this is required, not optional. s.send runs on ITS OWN
// inner goroutine because net/smtp.SendMail takes no context and can block
// past cfg.Timeout (e.g. a stalled TCP connect); the select below is what
// actually enforces the bound. Errors are logged WITHOUT the token/target —
// only host + error, never the message contents.
func (s *Sender) dispatch(to string, msg []byte) {
	if err := s.sendMessage(context.Background(), to, msg); err != nil {
		s.log.Error("emailsmtp: send failed", "host", s.cfg.Host, "error", err)
	}
}

func (s *Sender) sendMessage(parent context.Context, to string, msg []byte) error {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	done := make(chan error, 1)
	go func() {
		if s.useImplicitTLS() {
			done <- implicitTLSSendFunc(s.dialTLS, implicitTLSConfig(s.cfg.Host), addr, auth, s.cfg.From, []string{to}, msg)
			return
		}
		done <- s.send(addr, auth, s.cfg.From, []string{to}, msg)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// useImplicitTLS reports whether this send must open the connection with a
// TLS handshake before the first SMTP verb: the conventional 465 implicit-TLS
// port, or Config.TLSMode explicitly requesting it (see tlsModeImplicit). Any
// other port keeps net/smtp.SendMail's opportunistic STARTTLS negotiation
// (587) or plaintext relay (25) — byte-identical to the pre-implicit-TLS
// behavior. Unrecognized TLSMode values fall back to auto.
func (s *Sender) useImplicitTLS() bool {
	return s.cfg.Port == 465 || s.cfg.TLSMode == tlsModeImplicit
}

// buildMessage assembles an RFC5322 message. Each Send targets exactly one
// recipient (no Bcc-style batch that could desync the To header from the
// actual envelope recipient). from/to are sanitized here (not just subject
// upstream in templates.go) because they can carry attacker-influenced input
// too — e.g. a self-service signup email or an OTP target — that never passed
// through the template renderer.
func buildMessage(from, to, subject, body string, now time.Time) []byte {
	from, to, subject = sanitizeHeaderValue(from), sanitizeHeaderValue(to), sanitizeHeaderValue(subject)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\r\n", hdrFrom, from)
	fmt.Fprintf(&b, "%s: %s\r\n", hdrTo, to)
	fmt.Fprintf(&b, "%s: %s\r\n", hdrSubject, subject)
	fmt.Fprintf(&b, "%s: %s\r\n", hdrDate, now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "%s: <%d@%s>\r\n", hdrMessageID, now.UnixNano(), messageIDHost(from))
	fmt.Fprintf(&b, "%s: %s\r\n", hdrMIMEVersion, mimeVersion10)
	fmt.Fprintf(&b, "%s: %s\r\n\r\n", hdrContentType, contentTypePlain)
	b.WriteString(body)
	return []byte(b.String())
}

// sanitizeHeaderValue strips CR/LF from an RFC5322 header value so an
// attacker-influenced field (a signup email, an OTP target, ...) can never
// inject an extra header or split the message (SMTP header-injection
// hardening) — the same defense render() applies to Subject, applied here to
// every header value buildMessage writes, including ones that bypass the
// template renderer entirely (From/To).
func sanitizeHeaderValue(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

// messageIDHost extracts the domain half of an address for the Message-ID
// right-hand side, falling back to "localhost" for a malformed/empty From.
func messageIDHost(from string) string {
	if i := strings.IndexByte(from, '@'); i >= 0 && i+1 < len(from) {
		return from[i+1:]
	}
	return "localhost"
}
