package emailsmtp

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBuildMessage_SanitizesHeaderInjection proves a CRLF embedded in an
// attacker-influenced field (a signup email, an OTP target — neither passes
// through the template renderer's own Subject sanitization) cannot inject an
// extra RFC5322 header into the constructed message. net/smtp.SendMail
// itself rejects a CRLF in its from/to ENVELOPE parameters (validateLine),
// but that offers no protection for header lines inside the msg body this
// function builds — that's what sanitizeHeaderValue is for.
func TestBuildMessage_SanitizesHeaderInjection(t *testing.T) {
	malicious := "victim@ex.com\r\nBcc: attacker@evil.example"
	msg := string(buildMessage("s@ex.com", malicious, "Subject line", "body", time.Now()))
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Fatalf("injected Bcc header line survived buildMessage: %q", msg)
		}
	}
	if !strings.Contains(msg, "To: victim@ex.com") {
		t.Fatalf("expected a To header carrying the (merged, CRLF-stripped) value, got: %q", msg)
	}
}

// serveFakeSMTP speaks just enough of RFC 5321 for net/smtp.SendMail's
// non-TLS, non-auth path to succeed against it: greet, accept EHLO/MAIL/RCPT,
// switch to DATA mode on "DATA", read the message until the terminating
// "\r\n.\r\n", ack it, then accept QUIT. It publishes the collected DATA
// payload to got and stops after one session.
func serveFakeSMTP(t *testing.T, ln net.Listener, got chan<- string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return // listener closed by the test — not a failure
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	reply := func(line string) { w.WriteString(line + "\r\n"); w.Flush() }

	reply("220 fake.local ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.Fields(line)[0])
		switch cmd {
		case "EHLO", "HELO":
			reply("250 fake.local")
		case "MAIL", "RCPT":
			reply("250 OK")
		case "DATA":
			reply("354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				dl, derr := r.ReadString('\n')
				if derr != nil || dl == ".\r\n" {
					break
				}
				b.WriteString(dl)
			}
			got <- b.String()
			reply("250 OK: queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("500 unrecognized")
		}
	}
}

// TestTransport_RealSMTP proves the real net/smtp.SendMail path (defaultSendFunc)
// against an in-process listener — no TLS, no auth, no live server — so the
// wiring between Sender.dispatch and the stdlib transport is exercised for
// real, not just through the WithSendFunc capture seam the other tests use.
func TestTransport_RealSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go serveFakeSMTP(t, ln, got)

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	s, err := New(Config{Enabled: true, Host: host, Port: port, From: "s@ex.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendResetToken(context.Background(), "r@ex.com", "abc-real-smtp"); err != nil {
		t.Fatalf("SendResetToken returned %v, want nil", err)
	}
	select {
	case data := <-got:
		if !strings.Contains(data, "abc-real-smtp") {
			t.Fatal("token not delivered over the wire")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake SMTP received nothing")
	}
}
