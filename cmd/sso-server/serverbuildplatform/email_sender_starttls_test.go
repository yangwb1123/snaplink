package serverbuildplatform

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
)

// stockCaptureLogger records dispatch errors so the async sender can be
// observed without reaching into emailsmtp internals. It never records the
// message body; only the logger call itself is captured.
type stockCaptureLogger struct {
	lines chan string
	mu    sync.Mutex
	all   []string
}

func newStockCaptureLogger() *stockCaptureLogger {
	return &stockCaptureLogger{lines: make(chan string, 1)}
}

func (l *stockCaptureLogger) Info(string, ...any)  {}
func (l *stockCaptureLogger) Debug(string, ...any) {}

func (l *stockCaptureLogger) Error(msg string, keysAndValues ...any) {
	line := msg
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		line += fmt.Sprintf(" %v=%v", keysAndValues[i], keysAndValues[i+1])
	}
	l.mu.Lock()
	l.all = append(l.all, line)
	l.mu.Unlock()
	select {
	case l.lines <- line:
	default:
	}
}

func (l *stockCaptureLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.all...)
}

// stockSMTPFixture is a one-connection, no-STARTTLS loopback relay. It exists
// only to prove the stock config -> BuildEmailSender -> emailsmtp mapping: a
// require_starttls config must fail before MAIL, while an auto/dropped mode
// would deliver over plaintext.
type stockSMTPFixture struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	conn     net.Conn
	commands []string
	done     chan struct{}
}

func newStockSMTPFixture(t *testing.T) *stockSMTPFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &stockSMTPFixture{t: t, ln: ln, done: make(chan struct{})}
	go f.serve()
	t.Cleanup(f.stop)
	return f
}

func (f *stockSMTPFixture) serve() {
	defer close(f.done)
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	f.mu.Lock()
	f.conn = conn
	f.mu.Unlock()
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}
	write("220 stock.local ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		command := strings.ToUpper(fields[0])
		f.mu.Lock()
		f.commands = append(f.commands, command)
		f.mu.Unlock()
		switch command {
		case "EHLO", "HELO":
			write("250 stock.local") // deliberately no STARTTLS/AUTH extension
		case "MAIL", "RCPT":
			write("250 OK")
		case "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			for {
				dl, derr := r.ReadString('\n')
				if derr != nil {
					return
				}
				if dl == ".\r\n" {
					break
				}
			}
			write("250 OK: queued")
		case "QUIT":
			write("221 bye")
			return
		default:
			write("500 unrecognized")
		}
	}
}

func (f *stockSMTPFixture) address(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.ln.Addr().String())
	if err != nil {
		t.Fatalf("split fixture addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse fixture port: %v", err)
	}
	return host, port
}

func (f *stockSMTPFixture) stop() {
	_ = f.ln.Close()
	f.mu.Lock()
	conn := f.conn
	f.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		f.t.Error("stock SMTP fixture did not stop")
	}
}

func (f *stockSMTPFixture) saw(command string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.commands {
		if got == command {
			return true
		}
	}
	return false
}

func (f *stockSMTPFixture) observedCommands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// TestBuildEmailSender_RequireSTARTTLSReachesTransport proves the stock wiring
// passes config.SMTPConfig.TLSMode through unchanged. Against a relay without
// STARTTLS the async dispatch must log a fail-closed strict-mode error and the
// relay must see no MAIL; the legacy auto path would have delivered. The log
// must not contain the configured password or message token.
func TestBuildEmailSender_RequireSTARTTLSReachesTransport(t *testing.T) {
	fixture := newStockSMTPFixture(t)
	host, port := fixture.address(t)
	logger := newStockCaptureLogger()
	const (
		password  = "stock-password-9d2"
		token     = "stock-token-4a1"
		recipient = "recipient@example.com"
	)

	sender, err := BuildEmailSender(config.SMTPConfig{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "stock-user",
		Password: password,
		From:     "no-reply@example.com",
		TLSMode:  "require_starttls",
	}, logger)
	if err != nil {
		t.Fatalf("BuildEmailSender: %v", err)
	}
	if sender == nil {
		t.Fatal("BuildEmailSender returned nil with smtp.enabled and a host")
	}
	if err := sender.SendResetToken(context.Background(), recipient, token); err != nil {
		t.Fatalf("SendResetToken returned %v, want nil (fire-and-forget)", err)
	}

	var line string
	select {
	case line = <-logger.lines:
	case <-time.After(3 * time.Second):
		t.Fatalf("require_starttls did not reach the transport; commands=%v logs=%v",
			fixture.observedCommands(), logger.snapshot())
	}
	if !strings.Contains(line, "STARTTLS") && !strings.Contains(line, "require_starttls") {
		t.Fatalf("logged error does not identify strict STARTTLS failure: %q", line)
	}
	for _, secret := range []string{password, token, recipient} {
		if strings.Contains(line, secret) {
			t.Errorf("strict STARTTLS log leaked %q: %q", secret, line)
		}
	}

	select {
	case <-fixture.done:
	case <-time.After(3 * time.Second):
		t.Fatalf("stock SMTP fixture did not finish; commands=%v", fixture.observedCommands())
	}
	if fixture.saw("MAIL") || fixture.saw("RCPT") || fixture.saw("DATA") {
		t.Fatalf("require_starttls mapping delivered over plaintext; commands=%v", fixture.observedCommands())
	}
	if fixture.saw("AUTH") {
		t.Fatalf("require_starttls mapping attempted AUTH without TLS; commands=%v", fixture.observedCommands())
	}
}
