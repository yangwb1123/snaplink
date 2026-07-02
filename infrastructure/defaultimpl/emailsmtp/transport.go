package emailsmtp

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

// sendFunc matches net/smtp.SendMail's signature — the transport seam New
// defaults to defaultSendFunc and WithSendFunc overrides for tests, so tests
// never need a live SMTP server for sender/template coverage.
type sendFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

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
// smtp.starttls needs no separate code branch here. Implicit TLS (port 465,
// which SendMail cannot do — it always starts with a plaintext dial) is a
// deferred follow-up: a crypto/tls.Dial branch keyed on cfg.Port==465, kept
// out of v1 per the adjudicated scope (STARTTLS 587 + plaintext 25 now).
func defaultSendFunc(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
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
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	done := make(chan error, 1)
	go func() { done <- s.send(addr, auth, s.cfg.From, []string{to}, msg) }()
	select {
	case err := <-done:
		if err != nil {
			s.log.Error("emailsmtp: send failed", "host", s.cfg.Host, "error", err)
		}
	case <-ctx.Done():
		s.log.Error("emailsmtp: send timed out", "host", s.cfg.Host, "timeout", timeout)
	}
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
