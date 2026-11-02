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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// strictSMTPEvent records one command the fixture observed. secure means the
// command arrived after the fixture completed its STARTTLS upgrade.
type strictSMTPEvent struct {
	command string
	secure  bool
}

type strictSMTPServerOptions struct {
	advertiseSTARTTLS bool
	advertiseAuth     bool
	authReply         string
	startTLSReply     string
	failHandshake     bool
	stallGreeting     bool
	stallData         bool
	cert              *tls.Certificate
}

// strictSMTPServer is a one-connection loopback SMTP/TLS fixture. Every
// listener, accepted connection, and handler goroutine is bounded by stop,
// which the test cleanup joins; tests that assert late-IO closure wait for
// done before cleanup so the observation is not confused with teardown.
type strictSMTPServer struct {
	t    *testing.T
	ln   net.Listener
	opts strictSMTPServerOptions

	mu         sync.Mutex
	raw        net.Conn
	events     []strictSMTPEvent
	data       string
	peerClosed bool

	done chan struct{}
}

func newStrictSMTPServer(t *testing.T, opts strictSMTPServerOptions) *strictSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &strictSMTPServer{t: t, ln: ln, opts: opts, done: make(chan struct{})}
	go s.serve()
	t.Cleanup(s.stop)
	return s
}

func (s *strictSMTPServer) serve() {
	defer close(s.done)
	conn, err := s.ln.Accept()
	if err != nil {
		return // listener closed by teardown
	}
	s.mu.Lock()
	s.raw = conn
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.raw = nil
		s.mu.Unlock()
		_ = conn.Close()
	}()
	s.handle(conn)
}

func (s *strictSMTPServer) handle(conn net.Conn) {
	defer conn.Close() // the original plaintext conn; TCP closes the TLS wrapper too
	if s.opts.stallGreeting {
		s.drainUntilClosed(conn)
		return
	}
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	s.writeLine(w, "220 strict.local ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			s.noteReadEnd()
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		command := strings.ToUpper(fields[0])
		s.record(command, secure)
		switch command {
		case "EHLO", "HELO":
			s.writeEHLO(w, secure)
		case "STARTTLS":
			if !s.opts.advertiseSTARTTLS {
				s.writeLine(w, "502 STARTTLS not supported")
				continue
			}
			if s.opts.startTLSReply != "" {
				s.writeLine(w, s.opts.startTLSReply)
				continue
			}
			if s.opts.failHandshake {
				s.writeLine(w, "220 Ready to start TLS")
				_, _ = w.WriteString("not-a-tls-record\r\n")
				_ = w.Flush()
				return
			}
			if s.opts.cert == nil {
				s.writeLine(w, "454 TLS not configured")
				return
			}
			s.writeLine(w, "220 Ready to start TLS")
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{*s.opts.cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsConn.Handshake(); err != nil {
				s.noteReadEnd()
				return
			}
			conn = tlsConn
			r = bufio.NewReader(conn)
			w = bufio.NewWriter(conn)
			secure = true
			s.record("TLS", true)
		case "AUTH":
			if !secure {
				s.writeLine(w, "530 Must issue STARTTLS first")
				continue
			}
			if s.opts.authReply != "" {
				s.writeLine(w, s.opts.authReply+" "+strings.TrimSpace(line))
				continue
			}
			s.writeLine(w, "235 2.7.0 Authentication successful")
		case "MAIL", "RCPT":
			s.writeLine(w, "250 OK")
		case "DATA":
			s.writeLine(w, "354 End data with <CR><LF>.<CR><LF>")
			if s.opts.stallData {
				s.drainUntilClosed(conn)
				return
			}
			var b strings.Builder
			for {
				dl, derr := r.ReadString('\n')
				if derr != nil {
					s.noteReadEnd()
					return
				}
				if dl == ".\r\n" {
					break
				}
				b.WriteString(dl)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			s.writeLine(w, "250 OK: queued")
		case "QUIT":
			s.writeLine(w, "221 bye")
			return
		default:
			s.writeLine(w, "500 unrecognized")
		}
	}
}

func (s *strictSMTPServer) writeEHLO(w *bufio.Writer, secure bool) {
	lines := []string{"strict.local"}
	if !secure && s.opts.advertiseSTARTTLS {
		lines = append(lines, "STARTTLS")
	}
	if s.opts.advertiseAuth {
		lines = append(lines, "AUTH PLAIN")
	}
	for i, line := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		fmt.Fprintf(w, "250%s%s\r\n", sep, line)
	}
	_ = w.Flush()
}

func (s *strictSMTPServer) writeLine(w *bufio.Writer, line string) {
	_, _ = w.WriteString(line + "\r\n")
	_ = w.Flush()
}

func (s *strictSMTPServer) drainUntilClosed(conn net.Conn) {
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			s.noteReadEnd()
			return
		}
	}
}

func (s *strictSMTPServer) noteReadEnd() {
	s.mu.Lock()
	s.peerClosed = true
	s.mu.Unlock()
}

func (s *strictSMTPServer) record(command string, secure bool) {
	s.mu.Lock()
	s.events = append(s.events, strictSMTPEvent{command: command, secure: secure})
	s.mu.Unlock()
}

func (s *strictSMTPServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("split fixture addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse fixture port: %v", err)
	}
	return host, port
}

func (s *strictSMTPServer) hasCommand(command string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.command == command {
			return true
		}
	}
	return false
}

func (s *strictSMTPServer) eventNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.events))
	for _, event := range s.events {
		suffix := ""
		if event.secure {
			suffix = "(tls)"
		}
		names = append(names, event.command+suffix)
	}
	return names
}

func (s *strictSMTPServer) waitForCommand(t *testing.T, command string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.hasCommand(command) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("SMTP fixture never saw %s; events=%v", command, s.eventNames())
}

func (s *strictSMTPServer) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("SMTP fixture did not finish; events=%v", s.eventNames())
	}
}

func (s *strictSMTPServer) stop() {
	_ = s.ln.Close()
	s.mu.Lock()
	raw := s.raw
	s.mu.Unlock()
	if raw != nil {
		_ = raw.Close()
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.t.Error("SMTP fixture did not stop")
	}
}

// TestStrictSTARTTLS_MissingExtensionNeverMAILs is the causal red/green
// regression: with tls_mode=require_starttls and a relay that never advertises
// STARTTLS, the sender must fail closed before MAIL. The pre-change behavior
// treated the unknown mode as auto and sent the envelope over plaintext.
func TestStrictSTARTTLS_MissingExtensionNeverMAILs(t *testing.T) {
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled: true,
		Host:    host,
		Port:    port,
		TLSMode: "require_starttls",
		From:    "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Error("strict STARTTLS send without server STARTTLS succeeded; want a fail-closed error")
	}
	if srv.hasCommand("MAIL") {
		t.Errorf("strict STARTTLS send issued MAIL without TLS; events=%v", srv.eventNames())
	}
	if srv.hasCommand("AUTH") {
		t.Errorf("strict STARTTLS send issued AUTH without TLS; events=%v", srv.eventNames())
	}
}

func (s *strictSMTPServer) eventsSnapshot() []strictSMTPEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]strictSMTPEvent(nil), s.events...)
}

func (s *strictSMTPServer) dataString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *strictSMTPServer) peerClosedConn() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerClosed
}

// strictTestCA generates a throwaway local CA and server leaves at test time;
// no global root pool or test-environment state is mutated. Trusted leaves are
// installed only on the per-send strict config built by the test seam.
type strictTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newStrictTestCA(t *testing.T) *strictTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "emailsmtp strict test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &strictTestCA{cert: cert, key: key, pool: pool}
}

func (ca *strictTestCA) leaf(t *testing.T, ips []net.IP, dns []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "emailsmtp strict test relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf keypair: %v", err)
	}
	return pair
}

func trustStrictCA(s *Sender, pool *x509.CertPool) {
	s.strictTLS = func(host string) *tls.Config {
		cfg := strictTLSConfig(host)
		cfg.RootCAs = pool
		return cfg
	}
}

// TestStrictSTARTTLS_SuccessAuthOnlyAfterTLS proves the real STARTTLS upgrade
// succeeds against a generated local CA, that AUTH/MAIL/RCPT/DATA all happen
// only after the handshake, and that the sender's TLS config pins the relay
// hostname with a TLS 1.2 floor and certificate verification.
func TestStrictSTARTTLS_SuccessAuthOnlyAfterTLS(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var seen *tls.Config
	s.strictTLS = func(relayHost string) *tls.Config {
		cfg := strictTLSConfig(relayHost)
		cfg.RootCAs = ca.pool
		seen = cfg
		return cfg
	}

	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "strict-body-token", time.Now())
	if err := s.sendMessage(context.Background(), "r@ex.com", msg); err != nil {
		t.Fatalf("strict STARTTLS send: %v", err)
	}
	srv.waitDone(t)

	if seen == nil {
		t.Fatal("strict TLS config was never built")
	}
	if seen.ServerName != host {
		t.Errorf("ServerName = %q, want relay host %q", seen.ServerName, host)
	}
	if seen.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", seen.MinVersion)
	}
	if seen.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must never be set by strict STARTTLS")
	}

	authAfterTLS := false
	for _, event := range srv.eventsSnapshot() {
		switch event.command {
		case "AUTH", "MAIL", "RCPT", "DATA":
			if !event.secure {
				t.Errorf("%s arrived before TLS; events=%v", event.command, srv.eventNames())
			}
		}
		if event.command == "AUTH" && event.secure {
			authAfterTLS = true
		}
	}
	if !authAfterTLS {
		t.Fatalf("AUTH was not issued over TLS; events=%v", srv.eventNames())
	}
	if !srv.hasCommand("TLS") {
		t.Fatalf("fixture never completed a TLS handshake; events=%v", srv.eventNames())
	}
	if got := srv.dataString(); !strings.Contains(got, "strict-body-token") {
		t.Fatalf("delivered message missing body token: %q", got)
	}
}

// TestStrictSTARTTLS_Port465StrictWins proves explicit require_starttls wins
// over the port-465 implicit-TLS auto-selection: the connection still starts
// plaintext, negotiates STARTTLS, and upgrades before AUTH even though the
// configured port is 465. The dial seam only redirects the ephemeral listener.
func TestStrictSTARTTLS_Port465StrictWins(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		cert:              &cert,
	})
	realAddr := srv.ln.Addr().String()

	s, err := New(Config{
		Enabled:  true,
		Host:     "127.0.0.1",
		Port:     465,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustStrictCA(s, ca.pool)
	var requested string
	s.strictDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		requested = addr
		var d net.Dialer
		return d.DialContext(ctx, network, realAddr)
	}

	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "port-465-strict-body", time.Now())
	if err := s.sendMessage(context.Background(), "r@ex.com", msg); err != nil {
		t.Fatalf("strict STARTTLS send on port 465: %v", err)
	}
	srv.waitDone(t)
	if requested != "127.0.0.1:465" {
		t.Errorf("dial addr = %q, want configured 127.0.0.1:465", requested)
	}
	if !srv.hasCommand("TLS") || !srv.hasCommand("AUTH") {
		t.Fatalf("strict STARTTLS was bypassed on port 465; events=%v", srv.eventNames())
	}
}

func TestSender_StrictModePriority(t *testing.T) {
	cases := []struct {
		name         string
		port         int
		mode         string
		wantStrict   bool
		wantImplicit bool
	}{
		{"port 465 strict wins", 465, "require_starttls", true, false},
		{"port 587 strict", 587, "require_starttls", true, false},
		{"port 465 auto implicit unchanged", 465, "", false, true},
		{"port 587 implicit unchanged", 587, "implicit", false, true},
		{"port 587 unknown auto unchanged", 587, "bogus", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Sender{cfg: Config{Port: tc.port, TLSMode: tc.mode}}
			if got := s.useStrictSTARTTLS(); got != tc.wantStrict {
				t.Errorf("useStrictSTARTTLS(port=%d, mode=%q) = %v, want %v", tc.port, tc.mode, got, tc.wantStrict)
			}
			if got := s.useImplicitTLS(); got != tc.wantImplicit {
				t.Errorf("useImplicitTLS(port=%d, mode=%q) = %v, want %v", tc.port, tc.mode, got, tc.wantImplicit)
			}
		})
	}
}

func TestStrictSTARTTLS_UntrustedCertFailClosed(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "untrusted-body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS accepted an untrusted relay certificate")
	}
	if !strings.Contains(sendErr.Error(), "certificate") {
		t.Errorf("error = %v, want a certificate verification failure", sendErr)
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands before verifying the certificate; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_WrongHostFailClosed(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.2")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustStrictCA(s, ca.pool)
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "wrong-host-body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS accepted a certificate for a different host")
	}
	if !strings.Contains(sendErr.Error(), "127.0.0.2") || !strings.Contains(sendErr.Error(), "127.0.0.1") {
		t.Errorf("error = %v, want a hostname mismatch for 127.0.0.1 vs 127.0.0.2", sendErr)
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands after hostname mismatch; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_FailedHandshakeFailClosed(t *testing.T) {
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		failHandshake:     true,
	})
	host, port := srv.hostPort(t)
	s, err := New(Config{
		Enabled: true,
		Host:    host,
		Port:    port,
		TLSMode: "require_starttls",
		From:    "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "bad-handshake-body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS succeeded despite a broken TLS handshake")
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands after a failed handshake; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_STARTTLSCommandRejected(t *testing.T) {
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		startTLSReply:     "454 TLS temporarily unavailable",
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "starttls-command-rejected", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS succeeded after the relay rejected STARTTLS")
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands after STARTTLS was rejected; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_MissingExtensionNoLegacyFallback(t *testing.T) {
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{advertiseAuth: true})
	host, port := srv.hostPort(t)

	legacyCalled := false
	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "strict-user",
		Password: "strict-pass",
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil, WithSendFunc(func(string, smtp.Auth, string, []string, []byte) error {
		legacyCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "fallback-body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS without server STARTTLS succeeded")
	}
	if legacyCalled {
		t.Fatal("strict STARTTLS fell back to the configured legacy send function")
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands without STARTTLS; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_InjectedInsecureConfigStillVerifies(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled: true,
		Host:    host,
		Port:    port,
		TLSMode: "require_starttls",
		From:    "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Even a same-package test injection cannot weaken the strict transport:
	// the helper re-pins ServerName, clears InsecureSkipVerify, and floors TLS
	// 1.2, so this untrusted CA must still fail the handshake.
	s.strictTLS = func(string) *tls.Config {
		return &tls.Config{ServerName: "wrong.example", MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "insecure-injection-body", time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS honored an injected InsecureSkipVerify config")
	}
	if srv.hasCommand("TLS") || srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS advanced after an untrusted handshake; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_AuthFailureDoesNotLeakCredentials(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		authReply:         "535 denied",
		cert:              &cert,
	})
	host, port := srv.hostPort(t)
	const (
		password  = "leak-password-9f3"
		bodyToken = "auth-failure-body-secret"
	)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "leak-user",
		Password: password,
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustStrictCA(s, ca.pool)
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", bodyToken, time.Now())
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS succeeded despite a relay AUTH rejection")
	}
	encodedAuth := base64.StdEncoding.EncodeToString([]byte("\x00leak-user\x00" + password))
	for _, secret := range []string{"leak-user", password, encodedAuth, bodyToken} {
		if strings.Contains(sendErr.Error(), secret) {
			t.Errorf("strict STARTTLS error leaked %q: %v", secret, sendErr)
		}
	}
	if srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent MAIL after AUTH was rejected; events=%v", srv.eventNames())
	}
}

// strictQuiescenceConn wraps the real fixture connection so the cancellation
// window is controlled: Read/Write count live client I/O, and Close announces
// entry before blocking on releaseClose. A send that returns while the
// cancellation callback (or the client read it must close) is still active is
// therefore observable as closeFinished/activeOps state at return, not as an
// eventual server-side side effect.
type strictQuiescenceConn struct {
	net.Conn
	closeStarted  chan struct{}
	closeFinished chan struct{}
	releaseClose  <-chan struct{}
	closeOnce     sync.Once
	finishOnce    sync.Once
	active        atomic.Int32
}

func (c *strictQuiescenceConn) Read(p []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.Conn.Read(p)
}

func (c *strictQuiescenceConn) Write(p []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.Conn.Write(p)
}

func (c *strictQuiescenceConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeStarted) })
	<-c.releaseClose
	err := c.Conn.Close()
	c.finishOnce.Do(func() { close(c.closeFinished) })
	return err
}

func strictChannelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// TestStrictSTARTTLS_CancelJoinsClientAndCallbackBeforeReturn is the causal
// red/green join regression. It holds the admitted cancellation close callback
// in Close while the client is blocked reading the stalled DATA reply. The
// pre-repair sendMessage returned on ctx.Done with the callback still blocked
// and the client read still live; the repaired strict path must not return
// until both the callback and local SMTP I/O have terminated.
func TestStrictSTARTTLS_CancelJoinsClientAndCallbackBeforeReturn(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		stallData:         true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled: true,
		Host:    host,
		Port:    port,
		TLSMode: "require_starttls",
		From:    "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustStrictCA(s, ca.pool)

	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(release)
	closeStarted := make(chan struct{})
	closeFinished := make(chan struct{})
	connCh := make(chan *strictQuiescenceConn, 1)
	s.strictDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := &strictQuiescenceConn{
			Conn:          raw,
			closeStarted:  closeStarted,
			closeFinished: closeFinished,
			releaseClose:  releaseClose,
		}
		connCh <- conn
		return conn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "join-body", time.Now())
	go func() { errCh <- s.sendMessage(ctx, "r@ex.com", msg) }()
	srv.waitForCommand(t, "DATA", 5*time.Second)
	conn := <-connCh
	cancel()

	select {
	case <-closeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation close callback was never admitted")
	}

	var sendErr error
	returnedEarly := false
	select {
	case sendErr = <-errCh:
		returnedEarly = true
	case <-time.After(500 * time.Millisecond):
		// The repaired path is still joining the deliberately blocked callback.
		// This window only exposes a pre-repair early return; correctness below
		// is asserted from the state observed at that return, not from a later
		// server-side event.
	}
	var activeAtReturn int32
	if returnedEarly {
		activeAtReturn = conn.active.Load()
	}

	release()
	select {
	case <-closeFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("released cancellation callback did not finish")
	}
	if !returnedEarly {
		select {
		case sendErr = <-errCh:
		case <-time.After(5 * time.Second):
			t.Fatal("strict send did not return after the callback was released")
		}
	}

	if returnedEarly {
		t.Error("sendMessage returned while the admitted cancellation callback was still blocked")
	}
	if activeAtReturn != 0 {
		t.Errorf("sendMessage returned with %d active SMTP I/O operation(s)", activeAtReturn)
	}
	if got := conn.active.Load(); got != 0 {
		t.Errorf("strict send left %d active SMTP I/O operation(s) after return", got)
	}
	if !strictChannelClosed(closeFinished) {
		t.Error("sendMessage returned before the cancellation callback finished")
	}
	if sendErr == nil {
		t.Fatal("strict send returned nil after cancellation")
	}
	srv.waitDone(t)
}

func TestStrictSTARTTLS_CancelClosesAdmittedConn(t *testing.T) {
	ca := newStrictTestCA(t)
	cert := ca.leaf(t, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{
		advertiseSTARTTLS: true,
		advertiseAuth:     true,
		stallData:         true,
		cert:              &cert,
	})
	host, port := srv.hostPort(t)
	const (
		password  = "cancel-password-7c1"
		bodyToken = "cancel-body-secret"
	)

	s, err := New(Config{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "cancel-user",
		Password: password,
		TLSMode:  "require_starttls",
		From:     "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trustStrictCA(s, ca.pool)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", bodyToken, time.Now())
	go func() { errCh <- s.sendMessage(ctx, "r@ex.com", msg) }()
	srv.waitForCommand(t, "DATA", 5*time.Second)
	cancel()

	var sendErr error
	select {
	case sendErr = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("strict STARTTLS send did not return after cancellation")
	}
	if sendErr == nil {
		t.Fatal("strict STARTTLS send returned nil after cancellation")
	}
	for _, secret := range []string{password, bodyToken, "cancel-user"} {
		if strings.Contains(sendErr.Error(), secret) {
			t.Errorf("cancellation error leaked %q: %v", secret, sendErr)
		}
	}
	srv.waitDone(t)
	if !srv.peerClosedConn() {
		t.Fatal("cancelled strict STARTTLS left the admitted connection open")
	}
	if srv.hasCommand("MAIL") == false || srv.hasCommand("DATA") == false {
		t.Fatalf("expected the session to reach DATA before cancellation; events=%v", srv.eventNames())
	}
}

func TestStrictSTARTTLS_ConfiguredTimeoutClosesGreeting(t *testing.T) {
	srv := newStrictSMTPServer(t, strictSMTPServerOptions{stallGreeting: true})
	host, port := srv.hostPort(t)

	s, err := New(Config{
		Enabled: true,
		Host:    host,
		Port:    port,
		TLSMode: "require_starttls",
		Timeout: 200 * time.Millisecond,
		From:    "s@ex.com",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := buildMessage("s@ex.com", "r@ex.com", "subject", "timeout-body", time.Now())
	start := time.Now()
	sendErr := s.sendMessage(context.Background(), "r@ex.com", msg)
	elapsed := time.Since(start)
	srv.waitDone(t)

	if sendErr == nil {
		t.Fatal("strict STARTTLS send returned nil despite a stalled greeting")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("configured timeout did not bound the send: elapsed %s", elapsed)
	}
	if !srv.peerClosedConn() {
		t.Fatal("timed-out strict STARTTLS left the admitted connection open")
	}
	if srv.hasCommand("AUTH") || srv.hasCommand("MAIL") {
		t.Fatalf("strict STARTTLS sent commands on a timed-out connection; events=%v", srv.eventNames())
	}
}
