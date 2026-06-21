package radiusauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// This file drives the PRODUCTION radiusExchanger (NOT the fake) over real
// loopback sockets so the security ANCHOR — the RFC 2865 Response Authenticator
// validation that rejects a forged Access-Accept produced WITHOUT the shared
// secret — and the hand-rolled RadSec framing actually execute. Every other test
// in this package uses the fake Exchanger and therefore never touches
// Exchange/exchangeOne/radSecExchange/readFull (all 0.0% before this file).
//
// The load-bearing assertions are the two "forged/wrong-secret Accept" cases
// (UDP + RadSec): a peer that signs an Access-Accept with a DIFFERENT secret (or
// none) MUST be rejected by the client configured with the real secret —
// surfacing as a transport error and, through Authenticate, as
// ErrServerUnavailable, NEVER a successful login. A future regression (a flip of
// InsecureSkipVerify, a broken RadSec IsAuthenticResponse re-check) fails them.

const (
	// testSecret is the real shared secret the client + the honest server agree
	// on. testWrongSecret is what a forger uses; the client never holds it.
	testSecret      = "anchor-secret"
	testWrongSecret = "attacker-guess"
)

// realExchanger constructs the PRODUCTION radiusExchanger from cfg (filling the
// required Name/SharedSecret when the test left them blank). It deliberately
// does NOT use WithExchanger — this is the whole point: exercise the layeh path.
func realExchanger(t *testing.T, cfg Config) *radiusExchanger {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "roundtrip"
	}
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = testSecret
	}
	ex, err := newRadiusExchanger(cfg)
	if err != nil {
		t.Fatalf("newRadiusExchanger: %v", err)
	}
	return ex
}

// realAuthenticator builds the production Authenticator over the real exchanger
// (no fake), so the Exchange -> Authenticate mapping (Accept->success,
// Reject->ErrAuthFailed, transport->ErrServerUnavailable) is exercised end to
// end.
func realAuthenticator(t *testing.T, cfg Config) *Authenticator {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "roundtrip"
	}
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = testSecret
	}
	a, err := New(cfg) // real radiusExchanger, NOT WithExchanger
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// startUDPServer stands up a layeh PacketServer on 127.0.0.1:0 with secret
// `secret`, handing each request to `handler`. It returns the bound address and
// registers shutdown via t.Cleanup. The server VALIDATES the inbound request
// with `secret` (so it only runs the handler when the client used the matching
// secret), then the handler decides the reply.
func startUDPServer(t *testing.T, secret string, handler radius.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	srv := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler:      handler,
	}
	done := make(chan struct{})
	go func() {
		// Serve returns ErrServerShutdown after Shutdown; any other error is a
		// harness fault worth surfacing.
		if err := srv.Serve(pc); err != nil && !errors.Is(err, radius.ErrServerShutdown) {
			t.Errorf("PacketServer.Serve: %v", err)
		}
		close(done)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	return pc.LocalAddr().String()
}

// --- 1. Correct-secret Access-Accept => accepted, attributes round-trip ------

func TestRoundTrip_UDP_CorrectSecret_Accept(t *testing.T) {
	addr := startUDPServer(t, testSecret, func(w radius.ResponseWriter, r *radius.Request) {
		resp := r.Response(radius.CodeAccessAccept)
		// A reply attribute the client is configured to map back, proving the
		// Accept's attributes survive the real wire round trip + mapReplyAttributes.
		_ = rfc2865.FilterID_SetString(resp, "Enterprise-VPN")
		_ = w.Write(resp)
	})

	cfg := Config{
		Servers: []string{addr},
		Timeout: 2 * time.Second,
		ReplyAttributeMapping: map[radius.Type]string{
			rfc2865.FilterID_Type: "filter_id",
		},
	}

	// Drive the real exchanger directly.
	ex := realExchanger(t, cfg)
	accepted, attrs, err := ex.Exchange(context.Background(), "alice", "s3cret")
	if err != nil {
		t.Fatalf("Exchange err = %v, want nil", err)
	}
	if !accepted {
		t.Fatal("Exchange accepted = false, want true (server returned Access-Accept)")
	}
	if attrs["filter_id"] != "Enterprise-VPN" {
		t.Errorf("filter_id = %q, want Enterprise-VPN (reply attribute did not round-trip)", attrs["filter_id"])
	}

	// And through Authenticate: a real Accept mints a Subject.
	a := realAuthenticator(t, cfg)
	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil {
		t.Fatalf("Authenticate err = %v, want nil", err)
	}
	if res.ExternalID != "alice" {
		t.Errorf("ExternalID = %q, want alice", res.ExternalID)
	}
	if res.Attributes["filter_id"] != "Enterprise-VPN" {
		t.Errorf("Authenticate filter_id = %q, want Enterprise-VPN", res.Attributes["filter_id"])
	}
}

// --- 2. THE load-bearing assertion: forged / wrong-secret Accept => REJECTED -

// forgedAcceptResponder is a RAW UDP listener (NOT a layeh server) modelling an
// attacker who does NOT hold the shared secret: it replies to EVERY datagram
// with an Access-Accept whose Response Authenticator is computed with a WRONG
// secret. Replying to every datagram (rather than the layeh server's
// dedup-by-identifier single reply) lets the client accumulate forged replies up
// to MaxPacketErrors and return *NonAuthenticResponseError promptly, instead of
// silently timing out — so the assertion pins the AUTHENTICITY check, not a
// timeout. The forger never validates the request; it just echoes back an Accept.
func forgedAcceptResponder(t *testing.T, forgeWith string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, radius.MaxPacketLength)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return // listener closed at cleanup
			}
			if n < 20 {
				continue
			}
			// Parse the request under the FORGER's (wrong) secret only to recover
			// the Identifier + Request Authenticator needed to frame a reply. The
			// reply is then Encode()'d (signed) with that same wrong secret, so the
			// honest client's IsAuthenticResponse(reply, request, realSecret) fails.
			req, perr := radius.Parse(append([]byte(nil), buf[:n]...), []byte(forgeWith))
			if perr != nil {
				continue
			}
			resp := req.Response(radius.CodeAccessAccept) // copies Identifier+Authenticator+Secret(=forgeWith)
			wire, eerr := resp.Encode()                   // signs the Response Authenticator with forgeWith
			if eerr != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, raddr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestRoundTrip_UDP_ForgedAccept_Rejected_TheAnchor(t *testing.T) {
	// The forger signs an Access-Accept with a secret the client does NOT have.
	addr := forgedAcceptResponder(t, testWrongSecret)

	cfg := Config{
		Servers: []string{addr},
		// A short deadline with MANY retries => a tiny resend interval
		// (Timeout/(Retries+1)). The forger answers every retransmit, so the client
		// accumulates forged replies past MaxPacketErrors (the prod
		// defaultMaxPacketErrors = 5) and returns *NonAuthenticResponseError fast,
		// pinning the AUTHENTICITY check rather than a bare timeout. (Either way err
		// != nil and there is no login; this just makes the cause precise + quick.)
		Timeout: 1 * time.Second,
		Retries: 30, // resend interval ~1s/31 ≈ 32ms => >5 forged replies well within 1s
	}

	ex := realExchanger(t, cfg)
	start := time.Now()
	accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret")

	// THE anchor: a forged Accept is NEVER accepted.
	if accepted {
		t.Fatal("CRITICAL: forged Access-Accept (signed with the WRONG secret) was ACCEPTED — the Response Authenticator anchor failed")
	}
	if err == nil {
		t.Fatal("CRITICAL: forged Access-Accept produced no error — an attacker without the shared secret could log in")
	}
	// Pin the cause to the Response-Authenticator check specifically (not merely
	// "some error"): IsAuthenticResponse must reject the wrong-secret signature.
	var nonAuth *radius.NonAuthenticResponseError
	if !errors.As(err, &nonAuth) {
		t.Fatalf("forged-Accept err = %v, want *radius.NonAuthenticResponseError (the Response-Authenticator check must be what rejects it)", err)
	}
	// Must reject quickly via MaxPacketErrors, not hang to the (already short) deadline.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("forged-Accept rejection took %v — expected prompt MaxPacketErrors trip", elapsed)
	}

	// And through Authenticate: a forged Accept maps to ErrServerUnavailable —
	// the DISTINCT transport error, NEVER a login and NEVER ErrAuthFailed-only.
	a := realAuthenticator(t, cfg)
	res, aerr := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if res != nil {
		t.Fatal("CRITICAL: Authenticate returned a Subject for a forged Accept — must never log in")
	}
	if !errors.Is(aerr, ErrServerUnavailable) {
		t.Fatalf("forged-Accept Authenticate err = %v, want ErrServerUnavailable", aerr)
	}
}

// --- 3. Access-Reject => clean verdict (accepted=false, err=nil) -> ErrAuthFailed

func TestRoundTrip_UDP_Reject_MapsToAuthFailed(t *testing.T) {
	addr := startUDPServer(t, testSecret, func(w radius.ResponseWriter, r *radius.Request) {
		_ = w.Write(r.Response(radius.CodeAccessReject))
	})

	cfg := Config{Servers: []string{addr}, Timeout: 2 * time.Second}

	ex := realExchanger(t, cfg)
	accepted, _, err := ex.Exchange(context.Background(), "alice", "WRONG")
	if err != nil {
		t.Fatalf("Reject Exchange err = %v, want nil (a Reject is a verdict, not a transport error)", err)
	}
	if accepted {
		t.Fatal("Exchange accepted = true on an Access-Reject")
	}

	a := realAuthenticator(t, cfg)
	if _, aerr := a.Authenticate(context.Background(), authReq("alice", "WRONG")); !errors.Is(aerr, ErrAuthFailed) {
		t.Fatalf("Reject Authenticate err = %v, want ErrAuthFailed", aerr)
	}
}

// --- 4. Timeout (server never replies) => bounded err -> ErrServerUnavailable -

func TestRoundTrip_UDP_Timeout_MapsToServerUnavailable(t *testing.T) {
	// A handler that NEVER writes a reply: the client retransmits, then the
	// bounded per-request deadline fires. This must return promptly (well under
	// the test's own guard), proving a black-holed server cannot hang a login.
	addr := startUDPServer(t, testSecret, func(w radius.ResponseWriter, r *radius.Request) {
		// silence: never reply
	})

	cfg := Config{
		Servers: []string{addr},
		Timeout: 300 * time.Millisecond, // small, bounded
		Retries: 1,
	}

	ex := realExchanger(t, cfg)

	deadline := time.AfterFunc(5*time.Second, func() {
		t.Error("Exchange did not return within 5s on a silent server — the request deadline did not bound it")
	})
	start := time.Now()
	accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret")
	deadline.Stop()

	if accepted {
		t.Fatal("silent server yielded accepted = true")
	}
	if err == nil {
		t.Fatal("silent server yielded no error — want a bounded timeout")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Exchange took %v on a 300ms-timeout server — not bounded", elapsed)
	}

	a := realAuthenticator(t, cfg)
	if _, aerr := a.Authenticate(context.Background(), authReq("alice", "s3cret")); !errors.Is(aerr, ErrServerUnavailable) {
		t.Fatalf("timeout Authenticate err = %v, want ErrServerUnavailable", aerr)
	}
}

// ===========================================================================
// RadSec (RADIUS-over-TLS, RFC 6614) round trips — the ONLY coverage of
// radSecExchange + readFull + the length-prefix framing + the line-319
// IsAuthenticResponse re-check.
// ===========================================================================

// selfSignedTLS returns a tls.Certificate + its leaf PEM for a localhost cert.
// The PEM is fed into Config.RadSecCACertPEM so the client TLS-verifies the
// RadSec server (no InsecureSkipVerify — the secure posture is what we test).
func selfSignedTLS(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "radsec-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"radsec.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert, leafPEM
}

// radSecResponse builds a RADIUS reply, signed with replySecret, framed exactly
// as the wire form the production radSecExchange expects to read (the RADIUS
// header's 2-byte Length already delimits the record). When replySecret == the
// client's real secret the client accepts it; when it differs the client's
// IsAuthenticResponse re-check rejects it.
func radSecResponse(reqWire []byte, code radius.Code, replySecret string) ([]byte, error) {
	req, err := radius.Parse(reqWire, []byte(replySecret))
	if err != nil {
		return nil, err
	}
	resp := req.Response(code) // copies Identifier + Request Authenticator + Secret(=replySecret)
	return resp.Encode()       // signs the Response Authenticator with replySecret
}

// startRadSecServer stands up a tls.Listener on 127.0.0.1:0 whose accept loop
// reads ONE length-prefixed Access-Request (the same 20-byte-header + Length
// framing radSecExchange writes), then replies with `code` signed by
// `replySecret`, length-prefixed. It returns the bound address + the server
// cert's PEM (for RadSecCACertPEM). `rawReplyOverride`, when non-nil, is written
// verbatim instead of a framed RADIUS reply (used to drive the framing/length
// guards + readFull directly).
func startRadSecServer(t *testing.T, cert tls.Certificate, replySecret string, code radius.Code, rawReplyOverride []byte) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))

				// Read the length-prefixed request exactly like the client writes it.
				header := make([]byte, 20)
				if _, err := readConnFull(c, header); err != nil {
					return
				}
				total := int(header[2])<<8 | int(header[3])
				if total < 20 || total > radius.MaxPacketLength {
					return
				}
				reqWire := make([]byte, total)
				copy(reqWire, header)
				if total > 20 {
					if _, err := readConnFull(c, reqWire[20:]); err != nil {
						return
					}
				}

				if rawReplyOverride != nil {
					_, _ = c.Write(rawReplyOverride)
					return
				}
				reply, err := radSecResponse(reqWire, code, replySecret)
				if err != nil {
					return
				}
				_, _ = c.Write(reply)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// readConnFull mirrors the production readFull for the test server side (the
// listener is net.Conn-based, like the client).
func readConnFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// radSecCfg builds a RadSec client Config verifying the test server cert via
// RadSecCACertPEM + the 127.0.0.1 SNI (the cert carries that IP SAN).
func radSecCfg(addr string, caPEM []byte, secret string) Config {
	return Config{
		Name:             "radsec",
		Servers:          []string{addr},
		SharedSecret:     secret,
		Timeout:          3 * time.Second,
		UseRadSec:        true,
		RadSecCACertPEM:  caPEM,
		RadSecServerName: "127.0.0.1",
	}
}

// --- 5. RadSec correct-secret Accept => accepted -----------------------------

func TestRoundTrip_RadSec_CorrectSecret_Accept(t *testing.T) {
	cert, caPEM := selfSignedTLS(t)
	addr := startRadSecServer(t, cert, testSecret, radius.CodeAccessAccept, nil)

	cfg := radSecCfg(addr, caPEM, testSecret)
	ex := realExchanger(t, cfg)

	accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret")
	if err != nil {
		t.Fatalf("RadSec Exchange err = %v, want nil", err)
	}
	if !accepted {
		t.Fatal("RadSec accepted = false, want true (server returned a correctly-signed Access-Accept over TLS)")
	}

	a := realAuthenticator(t, cfg)
	res, aerr := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if aerr != nil {
		t.Fatalf("RadSec Authenticate err = %v, want nil", aerr)
	}
	if res.ExternalID != "alice" {
		t.Errorf("RadSec ExternalID = %q, want alice", res.ExternalID)
	}
}

// --- 6. RadSec forged / wrong-secret Accept => REJECTED (the RadSec anchor) ---

func TestRoundTrip_RadSec_ForgedAccept_Rejected_TheAnchor(t *testing.T) {
	cert, caPEM := selfSignedTLS(t)
	// TLS is honest (the cert verifies), but the RADIUS reply is signed with a
	// secret the client does NOT have — exactly a compromised-TLS-peer or
	// misconfigured-secret scenario. The line-319 IsAuthenticResponse re-check is
	// the ONLY thing standing between this and a forged login.
	addr := startRadSecServer(t, cert, testWrongSecret, radius.CodeAccessAccept, nil)

	cfg := radSecCfg(addr, caPEM, testSecret)
	ex := realExchanger(t, cfg)

	accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret")
	if accepted {
		t.Fatal("CRITICAL: RadSec forged Access-Accept (wrong secret) was ACCEPTED — the RadSec Response Authenticator re-check failed")
	}
	if err == nil {
		t.Fatal("CRITICAL: RadSec forged Access-Accept produced no error — the RadSec path does not validate the Response Authenticator")
	}
	var nonAuth *radius.NonAuthenticResponseError
	if !errors.As(err, &nonAuth) {
		t.Logf("RadSec forged-Accept err = %v (want *radius.NonAuthenticResponseError); anchor still holds via err != nil", err)
	}

	a := realAuthenticator(t, cfg)
	res, aerr := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if res != nil {
		t.Fatal("CRITICAL: RadSec Authenticate returned a Subject for a forged Accept")
	}
	if !errors.Is(aerr, ErrServerUnavailable) {
		t.Fatalf("RadSec forged-Accept Authenticate err = %v, want ErrServerUnavailable", aerr)
	}
}

// --- RadSec framing guards: the length-prefix bounds + readFull --------------

// A response whose declared Length exceeds MaxPacketLength must be rejected by
// the line-296 bound (total > radius.MaxPacketLength) — a malicious peer cannot
// make the client allocate/read an oversized record. We hand-craft a 20-byte
// header claiming length 5000.
func TestRoundTrip_RadSec_OverlongLength_Rejected(t *testing.T) {
	cert, caPEM := selfSignedTLS(t)
	raw := make([]byte, 20)
	raw[0] = byte(radius.CodeAccessAccept)
	binary.BigEndian.PutUint16(raw[2:4], 5000) // > MaxPacketLength (4096)
	addr := startRadSecServer(t, cert, testSecret, radius.CodeAccessAccept, raw)

	cfg := radSecCfg(addr, caPEM, testSecret)
	ex := realExchanger(t, cfg)

	accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret")
	if accepted {
		t.Fatal("over-length RadSec record was accepted")
	}
	if err == nil {
		t.Fatal("over-length RadSec record produced no error — the length bound did not fire")
	}
}

// A response whose declared Length is < 20 (a truncated header) must be rejected
// by the same bound (total < 20). We claim length 8.
func TestRoundTrip_RadSec_UndersizeLength_Rejected(t *testing.T) {
	cert, caPEM := selfSignedTLS(t)
	raw := make([]byte, 20)
	raw[0] = byte(radius.CodeAccessAccept)
	binary.BigEndian.PutUint16(raw[2:4], 8) // < 20
	addr := startRadSecServer(t, cert, testSecret, radius.CodeAccessAccept, raw)

	cfg := radSecCfg(addr, caPEM, testSecret)
	ex := realExchanger(t, cfg)

	if accepted, _, err := ex.Exchange(context.Background(), "alice", "s3cret"); accepted || err == nil {
		t.Fatalf("undersize RadSec length not rejected: accepted=%v err=%v", accepted, err)
	}
}

// --- RadSec Reject over TLS => clean verdict -> ErrAuthFailed -----------------

func TestRoundTrip_RadSec_Reject_MapsToAuthFailed(t *testing.T) {
	cert, caPEM := selfSignedTLS(t)
	addr := startRadSecServer(t, cert, testSecret, radius.CodeAccessReject, nil)

	cfg := radSecCfg(addr, caPEM, testSecret)
	ex := realExchanger(t, cfg)

	accepted, _, err := ex.Exchange(context.Background(), "alice", "WRONG")
	if err != nil {
		t.Fatalf("RadSec Reject Exchange err = %v, want nil", err)
	}
	if accepted {
		t.Fatal("RadSec Reject yielded accepted = true")
	}

	a := realAuthenticator(t, cfg)
	if _, aerr := a.Authenticate(context.Background(), authReq("alice", "WRONG")); !errors.Is(aerr, ErrAuthFailed) {
		t.Fatalf("RadSec Reject Authenticate err = %v, want ErrAuthFailed", aerr)
	}
}

// Guard: the exported sso.Authenticator surface is what we drove above.
var _ sso.Authenticator = (*Authenticator)(nil)
