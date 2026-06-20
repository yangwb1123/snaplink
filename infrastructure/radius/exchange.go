package radiusauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// Exchanger is the MINIMAL seam the Authenticator depends on to send one RADIUS
// Access-Request and learn the verdict. Declaring our OWN narrow interface
// (rather than coupling the authenticator to layeh.com/radius directly) keeps
// the seam test-injectable: the tests in this package drive a FAKE Exchanger
// with NO real RADIUS server and NO mocking framework — the §2 "real impl, no
// mocks" discipline applied to the RADIUS boundary, mirroring ldap's
// conn/dialer and kerberos's SPNEGOValidator seams. The prod radiusExchanger
// is the only thing that touches layeh.com/radius.
//
// Contract:
//   - accepted == true  IFF the server returned Access-Accept. attrs then carries
//     the mapped reply attributes (Filter-Id / Class / configured VSAs).
//   - accepted == false WITH err == nil  is a clean Access-Reject (the
//     credential verdict: unknown user OR wrong password — the server returns
//     Reject for BOTH, which is the anti-enumeration property the authenticator
//     relies on; see authenticator.go).
//   - err != nil  is a TRANSPORT/operational failure (timeout, server
//     unreachable, a forged/non-authentic response, a TLS/RadSec handshake
//     failure) — DISTINCT from a clean Reject so the authenticator can map it to
//     ErrServerUnavailable without leaking whether the user exists.
type Exchanger interface {
	Exchange(ctx context.Context, username, password string) (accepted bool, attrs map[string]string, err error)
}

// radiusExchanger is the production Exchanger over layeh.com/radius. It builds
// an RFC 2865 Access-Request (User-Name + User-Password [PAP] + the configured
// NAS-Identifier), sends it to the first server that answers (failover), and
// maps the reply.
//
// SECURITY: the shared secret is the trust anchor. layeh encrypts the
// User-Password with it (RFC 2865 §5.2 PAP) and — critically — VALIDATES the
// Response Authenticator with it on every reply (radius.IsAuthenticResponse,
// which radius.Client.Exchange runs internally unless InsecureSkipVerify is
// set). A forged Access-Accept produced WITHOUT the shared secret therefore
// fails that check and is rejected as a non-authentic response (a transport
// error here, NEVER a false-positive accept). The secret is held only in the
// per-request packet + the client and is NEVER logged.
type radiusExchanger struct {
	cfg Config
	// client is the reusable layeh client for the plain UDP/TCP path. It carries
	// the resend interval (Retry) and the verification posture. For the RadSec
	// (RADIUS-over-TLS) path we do NOT use it — layeh's stock client has no TLS
	// transport — and instead dial the TLS connection ourselves (radSecExchange),
	// re-running the SAME IsAuthenticResponse check so the security property is
	// identical.
	client *radius.Client
	// tlsConfig is the resolved RadSec *tls.Config, built once at construction
	// when RadSec is enabled (nil otherwise). Reused across requests.
	tlsConfig *tls.Config
}

// newRadiusExchanger builds the production exchanger from an already-validated
// Config. It performs NO network I/O (the server is contacted lazily, per
// Authenticate), so a RADIUS server that is down at boot does not block startup;
// only the optional RadSec client certificate / CA (local material) is read.
func newRadiusExchanger(cfg Config) (*radiusExchanger, error) {
	netProto := "udp"
	if cfg.useTCP() {
		// RadSec runs over TLS-on-TCP; a plain-TCP RADIUS transport is also
		// selectable. Either way the layeh client's Net must be "tcp".
		netProto = "tcp"
	}
	ex := &radiusExchanger{
		cfg: cfg,
		client: &radius.Client{
			Net: netProto,
			// Retry is the resend interval (RADIUS-over-UDP is best-effort, so a
			// dropped request must be retransmitted within the request deadline).
			// A non-positive value disables retransmit; we derive it from the
			// configured Retries + Timeout so a slow link still gets a resend
			// before the bounded context deadline fires.
			Retry: cfg.retryInterval(),
			// MaxPacketErrors caps how many malformed/non-authentic packets the
			// client will skip before surfacing the error. We keep a small bound
			// so a noisy port returns promptly rather than spinning.
			MaxPacketErrors: defaultMaxPacketErrors,
			// InsecureSkipVerify here governs layeh's RESPONSE-AUTHENTICATOR check
			// (NOT TLS). It MUST stay false: skipping it would accept a forged
			// Accept produced without the shared secret. There is no operator knob
			// to disable it — the secret-based response validation is mandatory.
			InsecureSkipVerify: false,
		},
	}
	if cfg.useRadSec() {
		tc, err := cfg.radSecTLSConfig()
		if err != nil {
			return nil, err
		}
		ex.tlsConfig = tc
	}
	return ex, nil
}

// defaultMaxPacketErrors bounds how many malformed/non-authentic datagrams the
// UDP client tolerates before returning, so a host blasting junk at the RADIUS
// port cannot keep a login spinning.
const defaultMaxPacketErrors = 5

// Exchange builds the Access-Request and sends it to each configured server in
// order, returning on the first that produces a definitive answer (Accept or
// Reject). A per-request bounded context deadline caps the whole round trip so a
// black-holed server cannot hang the login goroutine; failover moves on to the
// next server only on a TRANSPORT error, never on a clean Reject (a Reject is a
// verdict, not an outage).
func (e *radiusExchanger) Exchange(ctx context.Context, username, password string) (bool, map[string]string, error) {
	var lastErr error
	for _, addr := range e.cfg.Servers {
		// Honor a cancelled/expired caller context between failover attempts so a
		// client that gave up doesn't drive a long walk through every server.
		if err := ctx.Err(); err != nil {
			return false, nil, fmt.Errorf("radius: %w", err)
		}

		// A fresh packet per attempt: radius.New seeds a new random Request
		// Authenticator, and User-Password encryption (PAP) is keyed off it + the
		// shared secret, so each datagram is independently encrypted.
		packet, err := e.buildAccessRequest(username, password)
		if err != nil {
			// A build error (e.g. an over-length attribute) is operator-side, not a
			// credential verdict; it is independent of the username so it leaks no
			// existence signal. Surface it as a transport-class error.
			return false, nil, err
		}

		// Bound THIS server's round trip. The deadline also caps layeh's internal
		// retransmit loop (Retry), so total wait <= Timeout regardless of resends.
		attemptCtx, cancel := context.WithTimeout(ctx, e.cfg.requestTimeout())
		resp, err := e.exchangeOne(attemptCtx, packet, addr)
		cancel()
		if err != nil {
			// Timeout / unreachable / non-authentic response: try the next server.
			lastErr = err
			continue
		}

		switch resp.Code {
		case radius.CodeAccessAccept:
			return true, e.mapReplyAttributes(resp), nil
		case radius.CodeAccessReject:
			// Clean verdict. accepted=false, err=nil — the authenticator collapses
			// this to ErrAuthFailed (the unknown-user == wrong-password property).
			return false, nil, nil
		default:
			// Access-Challenge (PAP has no challenge leg) or any other code is not a
			// usable verdict for this PAP gate. Treat it as a transport-class
			// anomaly (distinct from a Reject) and fail over; it reveals nothing
			// about the user.
			lastErr = fmt.Errorf("radius: unexpected response code %v from %s", resp.Code, addr)
			continue
		}
	}
	if lastErr == nil {
		// No servers configured would have been caught at Validate; defensively
		// surface a generic transport error.
		lastErr = errors.New("radius: no server produced a response")
	}
	return false, nil, lastErr
}

// exchangeOne sends one packet to one server, choosing the RadSec (TLS) path or
// the stock UDP/TCP client path.
func (e *radiusExchanger) exchangeOne(ctx context.Context, packet *radius.Packet, addr string) (*radius.Packet, error) {
	if e.tlsConfig != nil {
		return e.radSecExchange(ctx, packet, addr)
	}
	// Stock layeh path: builds the datagram, sends, retransmits within ctx, and
	// VALIDATES the Response Authenticator with the shared secret. A
	// *radius.NonAuthenticResponseError (forged reply) surfaces here as an error.
	return e.client.Exchange(ctx, packet, addr)
}

// buildAccessRequest assembles the RFC 2865 Access-Request: User-Name +
// User-Password (PAP — layeh encrypts it with the shared secret + Request
// Authenticator) + the configured NAS-Identifier. The shared secret is baked
// into the packet by radius.New; layeh uses it for both the password encryption
// and the later Response-Authenticator validation.
func (e *radiusExchanger) buildAccessRequest(username, password string) (*radius.Packet, error) {
	packet := radius.New(radius.CodeAccessRequest, []byte(e.cfg.SharedSecret))
	if err := rfc2865.UserName_SetString(packet, username); err != nil {
		return nil, fmt.Errorf("radius: set User-Name: %w", err)
	}
	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		return nil, fmt.Errorf("radius: set User-Password: %w", err)
	}
	if nasID := e.cfg.nasIdentifier(); nasID != "" {
		if err := rfc2865.NASIdentifier_SetString(packet, nasID); err != nil {
			return nil, fmt.Errorf("radius: set NAS-Identifier: %w", err)
		}
	}
	return packet, nil
}

// mapReplyAttributes projects ONLY the operator-configured reply attributes off
// an Access-Accept onto the local attribute map. Nothing is copied implicitly:
// a RADIUS server cannot smuggle an unexpected attribute (a stray VSA, a
// Reply-Message) onto the Subject — and thus into a token — unless the operator
// asked for it via ReplyAttributeMapping. This mirrors how the ldap
// authenticator maps only the configured directory attributes. An absent
// attribute is simply skipped (no empty key written).
func (e *radiusExchanger) mapReplyAttributes(resp *radius.Packet) map[string]string {
	if len(e.cfg.ReplyAttributeMapping) == 0 {
		return nil
	}
	out := make(map[string]string, len(e.cfg.ReplyAttributeMapping))
	for radiusType, localKey := range e.cfg.ReplyAttributeMapping {
		var val string
		switch radiusType {
		case rfc2865.FilterID_Type:
			val = rfc2865.FilterID_GetString(resp)
		case rfc2865.Class_Type:
			// Class is conventionally an opaque token the NAS echoes in accounting;
			// rendered as a string for the local attribute. Empty when absent.
			val = rfc2865.Class_GetString(resp)
		default:
			// Any other configured attribute Type (e.g. a vendor-specific attribute
			// the operator maps by its numeric Type) is read generically and
			// rendered as a string. radius.String yields "" for a missing attribute.
			val = radius.String(resp.Get(radiusType))
		}
		if val != "" {
			out[localKey] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Interface guard: *radiusExchanger is an Exchanger.
var _ Exchanger = (*radiusExchanger)(nil)

// radSecExchange sends one Access-Request over a RadSec (RADIUS-over-TLS, RFC
// 6614) connection. layeh's stock client has no TLS transport, so we dial the
// TLS connection ourselves, frame the packet with Packet.Encode (which fills the
// Request Authenticator), write it, read the reply, parse it with the shared
// secret, and — preserving the SAME security property the UDP path gets for
// free — VALIDATE the Response Authenticator with radius.IsAuthenticResponse
// (the exact check radius.Client.Exchange runs internally). A reply that fails
// that check is rejected as non-authentic, NEVER accepted.
//
// RadSec is the RECOMMENDED posture: plain RADIUS/UDP PAP is only as secure as
// the shared secret and the network path, whereas RadSec wraps the whole
// exchange in TLS (mutual-auth capable). The transport here is TCP-framed
// length-prefixed RADIUS as RFC 6614 specifies (the 2-byte Length field in the
// RADIUS header delimits the record on the stream).
func (e *radiusExchanger) radSecExchange(ctx context.Context, packet *radius.Packet, addr string) (*radius.Packet, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: e.cfg.requestTimeout()},
		Config:    e.tlsConfig,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("radius: radsec dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	// Propagate the caller's deadline to the socket so a stalled peer cannot hang
	// past the bounded request timeout.
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	// Encode fills the Request Authenticator + serializes the packet (the same
	// wire form the UDP client sends). The shared secret keys the PAP password
	// encryption already applied by buildAccessRequest.
	wire, err := packet.Encode()
	if err != nil {
		return nil, fmt.Errorf("radius: encode: %w", err)
	}
	if _, err := rawConn.Write(wire); err != nil {
		return nil, fmt.Errorf("radius: radsec write: %w", err)
	}

	// Read one RADIUS record. The RADIUS header is 20 bytes; bytes 2-3 are the
	// total Length (RFC 2865 §3). We read the header, learn the length, then read
	// the remainder — RFC 6614 frames records on the TLS stream by this Length.
	header := make([]byte, 20)
	if _, err := readFull(rawConn, header); err != nil {
		return nil, fmt.Errorf("radius: radsec read header: %w", err)
	}
	total := int(header[2])<<8 | int(header[3])
	if total < 20 || total > radius.MaxPacketLength {
		return nil, fmt.Errorf("radius: radsec invalid response length %d", total)
	}
	buf := make([]byte, total)
	copy(buf, header)
	if total > 20 {
		if _, err := readFull(rawConn, buf[20:]); err != nil {
			return nil, fmt.Errorf("radius: radsec read body: %w", err)
		}
	}

	resp, err := radius.Parse(buf, []byte(e.cfg.SharedSecret))
	if err != nil {
		return nil, fmt.Errorf("radius: radsec parse response: %w", err)
	}
	// THE security gate on the RadSec path: a forged response that was not
	// produced with the shared secret fails this check and is rejected. This is
	// the exact validation radius.Client.Exchange performs for the UDP path; we
	// reproduce it so RadSec is no weaker.
	reqWire, err := packet.Encode()
	if err != nil {
		return nil, fmt.Errorf("radius: re-encode request for validation: %w", err)
	}
	if !radius.IsAuthenticResponse(buf, reqWire, []byte(e.cfg.SharedSecret)) {
		return nil, &radius.NonAuthenticResponseError{}
	}
	return resp, nil
}

// readFull reads exactly len(buf) bytes or returns an error. (net.Conn has no
// io.ReadFull convenience; this keeps the RadSec framing self-contained without
// pulling io into the hot signature.)
func readFull(c net.Conn, buf []byte) (int, error) {
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
