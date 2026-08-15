package emailsmtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

// serveFakeSMTP accepts one connection from ln and runs serveSMTP over it.
func serveFakeSMTP(t *testing.T, ln net.Listener, got chan<- string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return // listener closed by the test — not a failure
	}
	defer conn.Close()
	serveSMTP(t, conn, got)
}

// serveSMTP speaks just enough of RFC 5321 for the transport paths under test
// (net/smtp.SendMail's non-TLS, non-auth path and the implicit-TLS session
// built on smtp.NewClient) to succeed against it: greet, accept
// EHLO/MAIL/RCPT, switch to DATA mode on "DATA", read the message until the
// terminating "\r\n.\r\n", ack it, then accept QUIT. It publishes the
// collected DATA payload to got and stops after one session. conn is the
// already-established transport (plain or TLS-wrapped).
func serveSMTP(t *testing.T, conn net.Conn, got chan<- string) {
	t.Helper()
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

// testTLSListener starts a TLS-wrapped TCP listener for the in-process
// implicit-TLS tests. The throwaway certificate is self-signed for the
// 127.0.0.1 IP SAN, so the sender's real tls.Dial (ServerName pinned to the
// relay host, TLS 1.2 floor, no InsecureSkipVerify) succeeds only when the
// test injects a WithTLSDial that clones the sender's config and adds pool as
// a trusted root. The cert is generated at test time — no fixtures to rot.
func testTLSListener(t *testing.T) (net.Listener, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test cert to pool")
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, pool
}

// serveTLSFakeSMTP accepts one connection, forces the TLS handshake (a
// tls.Listener hands out un-handshaken conns — handshaking eagerly makes a
// non-TLS client fail this goroutine fast instead of hanging on reads), then
// runs the same RFC 5321 conversation as serveFakeSMTP over the encrypted
// channel.
func serveTLSFakeSMTP(t *testing.T, ln net.Listener, got chan<- string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return // listener closed by the test — not a failure
	}
	defer conn.Close()
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		return
	}
	serveSMTP(t, conn, got)
}

// trustTestCA returns a WithTLSDial option whose dial runs the real
// crypto/tls.Dial after cloning the sender's config and trusting pool — so
// the real handshake executes against the in-process TLS listener while
// ServerName/MinVersion/InsecureSkipVerify still come from the sender's own
// config, which the tests assert on.
func trustTestCA(pool *x509.CertPool) func(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		testCfg := cfg.Clone()
		testCfg.RootCAs = pool
		return tls.Dial(network, addr, testCfg)
	}
}

// TestSender_UseImplicitTLS_Selection pins the transport-selection predicate:
// port 465 auto-selects implicit TLS, TLSMode "implicit" forces it on any
// port, and every other port/mode keeps the plaintext STARTTLS path — an
// unknown TLSMode is treated as auto, never as implicit (fail-closed toward
// the historical behavior).
func TestSender_UseImplicitTLS_Selection(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		mode    string
		wantTLS bool
	}{
		{"port 465 auto-enables", 465, "", true},
		{"port 465 explicit auto", 465, "auto", true},
		{"port 465 explicit implicit", 465, "implicit", true},
		{"587 starttls unchanged", 587, "", false},
		{"25 plaintext unchanged", 25, "", false},
		{"587 explicit implicit wins", 587, "implicit", true},
		{"unknown mode treated as auto", 587, "bogus", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Sender{cfg: Config{Port: tc.port, TLSMode: tc.mode}}
			if got := s.useImplicitTLS(); got != tc.wantTLS {
				t.Fatalf("useImplicitTLS(port=%d, mode=%q) = %v, want %v", tc.port, tc.mode, got, tc.wantTLS)
			}
		})
	}
}

// TestTransport_ImplicitTLS_Port465 proves port 465 auto-selects the
// implicit-TLS transport end to end. A real 465 listener is privileged, so
// the sender is configured with Host 127.0.0.1 / Port 465 (the exact config
// the selection predicate test pins) and the WithTLSDial seam — the
// documented test hook for this transport — verifies the transport derived
// the host:465 address from cfg before routing the real tls.Dial to the
// ephemeral TLS listener. The TLS config handed to the dial must pin
// ServerName to the relay host, floor the protocol at TLS 1.2, and never set
// InsecureSkipVerify.
func TestTransport_ImplicitTLS_Port465(t *testing.T) {
	ln, pool := testTLSListener(t)
	got := make(chan string, 1)
	go serveTLSFakeSMTP(t, ln, got)

	realAddr := ln.Addr().String()
	var seenCfg *tls.Config
	var seenAddr string
	s, err := New(Config{Enabled: true, Host: "127.0.0.1", Port: 465, From: "s@ex.com"}, nil,
		WithTLSDial(func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			seenCfg = cfg
			seenAddr = addr
			return trustTestCA(pool)(network, realAddr, cfg)
		}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendResetToken(context.Background(), "r@ex.com", "abc-465"); err != nil {
		t.Fatalf("SendResetToken over implicit TLS returned %v, want nil", err)
	}
	select {
	case data := <-got:
		if !strings.Contains(data, "abc-465") {
			t.Fatal("token not delivered over the TLS channel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS SMTP server received nothing")
	}
	if seenCfg == nil {
		t.Fatal("implicit-TLS dial was never invoked for port 465")
	}
	if seenAddr != "127.0.0.1:465" {
		t.Errorf("implicit-TLS dial addr = %q, want the configured 127.0.0.1:465 relay", seenAddr)
	}
	if seenCfg.ServerName != "127.0.0.1" {
		t.Errorf("ServerName = %q, want relay host 127.0.0.1", seenCfg.ServerName)
	}
	if seenCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", seenCfg.MinVersion)
	}
	if seenCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must never be set by the implicit-TLS config")
	}
}

// TestTransport_ImplicitTLS_ExplicitMode proves tls_mode=implicit selects the
// TLS transport on a NON-465 port (a non-standard implicit-TLS relay): same
// real handshake + session as the port-465 path.
func TestTransport_ImplicitTLS_ExplicitMode(t *testing.T) {
	ln, pool := testTLSListener(t)
	got := make(chan string, 1)
	go serveTLSFakeSMTP(t, ln, got)

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	dialed := make(chan struct{}, 1)
	s, err := New(Config{Enabled: true, Host: host, Port: port, TLSMode: "implicit", From: "s@ex.com"}, nil,
		WithTLSDial(func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialed <- struct{}{}
			return trustTestCA(pool)(network, addr, cfg)
		}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendResetToken(context.Background(), "r@ex.com", "abc-explicit"); err != nil {
		t.Fatalf("SendResetToken with tls_mode=implicit returned %v, want nil", err)
	}
	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("implicit-TLS dial not invoked for tls_mode=implicit on a non-465 port")
	}
	select {
	case data := <-got:
		if !strings.Contains(data, "abc-explicit") {
			t.Fatal("token not delivered over the TLS channel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS SMTP server received nothing")
	}
}

// TestTransport_Non465_PlaintextUnchanged is the no-regression assertion for
// the pre-existing 587/25 behavior: without port 465 or tls_mode=implicit the
// sender keeps net/smtp.SendMail's plaintext (opportunistic-STARTTLS) path
// and never dials TLS at all.
func TestTransport_Non465_PlaintextUnchanged(t *testing.T) {
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

	dialed := make(chan struct{}, 1)
	s, err := New(Config{Enabled: true, Host: host, Port: port, From: "s@ex.com"}, nil,
		WithTLSDial(func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialed <- struct{}{}
			return nil, tls.RecordHeaderError{}
		}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendResetToken(context.Background(), "r@ex.com", "abc-plain"); err != nil {
		t.Fatalf("SendResetToken returned %v, want nil", err)
	}
	select {
	case data := <-got:
		if !strings.Contains(data, "abc-plain") {
			t.Fatal("token not delivered over the plaintext channel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake SMTP received nothing")
	}
	select {
	case <-dialed:
		t.Fatal("TLS dial invoked for a non-465, auto-mode send")
	default:
	}
}

// TestTransport_ImplicitTLS_HandshakeFailure_FailClosed proves the implicit-TLS
// path never degrades to plaintext: against a plaintext (non-TLS) listener the
// real crypto/tls.Dial handshake fails, the error surfaces to the caller, and
// the plaintext session never reaches DATA (nothing lands in got).
func TestTransport_ImplicitTLS_HandshakeFailure_FailClosed(t *testing.T) {
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

	// Default tls.Dial — no injected trust, so the self-signed case is
	// covered elsewhere; here the endpoint is not even TLS, so the handshake
	// must fail before any SMTP verb.
	s, err := New(Config{Enabled: true, Host: host, Port: port, TLSMode: "implicit", From: "s@ex.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "body", time.Now())
	err = s.sendMessage(context.Background(), "r@ex.com", msg)
	if err == nil {
		t.Fatal("implicit-TLS send against a plaintext listener succeeded, want a handshake error")
	}
	if !strings.Contains(err.Error(), "tls:") {
		t.Fatalf("error = %v, want a TLS handshake error (no plaintext fallback)", err)
	}
	select {
	case data := <-got:
		t.Fatalf("plaintext SMTP session received data %q — implicit TLS degraded to plaintext", data)
	default:
	}
}
