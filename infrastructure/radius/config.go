package radiusauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"layeh.com/radius"
)

// Default* fill the corresponding zero-valued Config fields. The timeout +
// retries bound the per-server round trip so a slow or dead RADIUS server
// cannot hang a login indefinitely (RADIUS-over-UDP is best-effort: a dropped
// request is invisible without a bounded retransmit + deadline).
const (
	// DefaultTimeout caps ONE Access-Request round trip to ONE server (including
	// layeh's internal retransmits). With failover (multiple Servers) the
	// WORST-CASE total wait is len(Servers) * Timeout, so keep it modest.
	DefaultTimeout = 5 * time.Second

	// DefaultRetries is how many times a single Access-Request is retransmitted
	// to a server within the request deadline before that server is treated as
	// unreachable. RADIUS/UDP packets can be silently dropped, so at least one
	// retransmit materially improves reliability on a lossy path. The resend
	// interval is derived as Timeout/(Retries+1) so all retransmits fit inside
	// the bounded Timeout.
	DefaultRetries = 2

	// DefaultNASIdentifier is the NAS-Identifier (RFC 2865 §5.32) sent when the
	// operator does not configure one. It identifies THIS SSO server to the
	// RADIUS server in its logs / policy (a stable, non-secret label).
	DefaultNASIdentifier = "snaplink-sso"
)

// AuthProtocol selects how the user's password is carried in the
// Access-Request. PAP (the default) is the only protocol layeh's helper
// encrypts end-to-end with the shared secret; CHAP is accepted as a config
// value for forward-compatibility but is NOT implemented by the stock exchanger
// (see Validate) — an operator needing CHAP supplies a custom Exchanger.
type AuthProtocol string

const (
	// AuthPAP carries the User-Password attribute, encrypted by the shared
	// secret + Request Authenticator (RFC 2865 §5.2). This is the implemented
	// default. PAP is only as confidential as the shared secret and the network
	// path — RadSec (TLS) is strongly recommended over plain UDP (see doc.go).
	AuthPAP AuthProtocol = "pap"

	// AuthCHAP names CHAP (RFC 2865 §5.3). Reserved for an operator-supplied
	// Exchanger; the stock radiusExchanger does NOT implement it (Validate
	// rejects it to fail loud rather than silently send PAP).
	AuthCHAP AuthProtocol = "chap"
)

// Config describes one upstream RADIUS server (or failover set) this SSO server
// authenticates users against, acting as a RADIUS CLIENT. One Config yields one
// Authenticator; an operator may wire several (one per RADIUS realm), selected
// at /auth/login by provider=<Name>.
//
// SECURITY: SharedSecret is the trust anchor of the entire exchange. It
// encrypts the PAP User-Password AND authenticates the server's reply (the
// Response Authenticator) — without it a man-in-the-middle can neither read the
// password nor forge an Access-Accept. It is REQUIRED, is NEVER logged, and is
// NEVER placed on the returned AuthResult or in an error.
type Config struct {
	// Name is the authenticator name + the value clients pass in provider=<name>
	// to choose this RADIUS server at /auth/login. It is also the
	// AuthResult.Provider value. REQUIRED.
	Name string

	// Servers are the RADIUS server endpoints in "host:port" form (the RADIUS
	// auth port is conventionally 1812; RadSec is conventionally 2083), tried in
	// order for FAILOVER: the first that returns a definitive Accept/Reject wins;
	// a TRANSPORT failure (timeout/unreachable/non-authentic reply) falls through
	// to the next. A clean Access-Reject is a verdict, NOT an outage, so it does
	// NOT trigger failover. At least one is REQUIRED.
	Servers []string

	// SharedSecret is the RADIUS shared secret configured on BOTH this client and
	// the RADIUS server. It is the security anchor (PAP password encryption +
	// Response-Authenticator validation). REQUIRED and must be non-empty — an
	// empty secret would leave the password effectively in the clear and the
	// reply unauthenticated. Never logged.
	SharedSecret string

	// NASIdentifier is the NAS-Identifier (RFC 2865 §5.32) attribute identifying
	// this SSO server to the RADIUS server. Empty => DefaultNASIdentifier. It is
	// a non-secret label used in the RADIUS server's logs / policy matching.
	NASIdentifier string

	// AuthProtocol selects the password-carrying protocol. Empty => AuthPAP (the
	// only protocol the stock exchanger implements). AuthCHAP is reserved for an
	// operator-supplied Exchanger and is rejected by Validate for the stock path.
	AuthProtocol AuthProtocol

	// ReplyAttributeMapping projects RADIUS reply attributes off an
	// Access-Accept onto AuthResult.Attributes keys this server uses. Key = the
	// RADIUS attribute Type (e.g. rfc2865.FilterID_Type, rfc2865.Class_Type, or a
	// numeric vendor-specific Type); value = the local attribute key (e.g.
	// "filter_id", "radius_class"). ONLY the listed attributes are read and
	// mapped — nothing is passed through implicitly, so a RADIUS server cannot
	// smuggle an unexpected attribute (a stray VSA, a Reply-Message) onto the
	// AuthResult and thus into a token. Empty => no attributes mapped (only
	// ExternalID is populated).
	ReplyAttributeMapping map[radius.Type]string

	// Timeout caps ONE Access-Request round trip to ONE server (incl.
	// retransmits). Zero => DefaultTimeout.
	Timeout time.Duration

	// Retries is the number of retransmits to a single server within the request
	// deadline before it is considered unreachable. Zero => DefaultRetries. A
	// negative value disables retransmit (a single shot).
	Retries int

	// --- RadSec (RADIUS-over-TLS, RFC 6614) ---------------------------------
	//
	// Plain RADIUS/UDP PAP is dated: its confidentiality rests entirely on the
	// shared secret and a trusted network path. RadSec wraps the whole exchange
	// in TLS (optionally mutually authenticated). It is STRONGLY RECOMMENDED over
	// plain UDP for any traffic crossing an untrusted segment.

	// UseRadSec switches the transport to RADIUS-over-TLS (TCP + TLS, RFC 6614).
	// When true the server certificate is verified (against RadSecCACertPEM or
	// the system roots) and the Servers addresses are dialed over TLS (the RadSec
	// port is conventionally 2083). The shared-secret-based Response-Authenticator
	// validation STILL applies on top of TLS (defense in depth). Default false
	// (plain UDP).
	UseRadSec bool

	// UseTCP selects a plain (non-TLS) TCP transport (RFC 6613) WITHOUT RadSec.
	// Rarely needed; UseRadSec is the secure choice. Ignored when UseRadSec is
	// set (RadSec is already TCP+TLS). Default false (UDP).
	UseTCP bool

	// RadSecTLSConfig is an OPTIONAL fully-formed *tls.Config for the RadSec
	// connection. When nil a config is built from RadSecCACertPEM +
	// RadSecClientCertPEM/KeyPEM + RadSecServerName + RadSecInsecureSkipVerify
	// below. When non-nil it is used verbatim (the operator owns it). Only
	// consulted when UseRadSec is true.
	RadSecTLSConfig *tls.Config

	// RadSecCACertPEM is an OPTIONAL PEM bundle of CA certificate(s) that signed
	// the RADIUS server's RadSec certificate, for servers using a private CA not
	// in the system trust store. Empty => the system roots. Ignored when
	// RadSecTLSConfig is supplied.
	RadSecCACertPEM []byte

	// RadSecClientCertPEM + RadSecClientKeyPEM are an OPTIONAL client certificate
	// + key for MUTUALLY-AUTHENTICATED RadSec (the RADIUS server verifies this
	// client). Both must be set together or both empty. The key is sensitive and
	// is never logged. Ignored when RadSecTLSConfig is supplied.
	RadSecClientCertPEM []byte
	RadSecClientKeyPEM  []byte

	// RadSecServerName overrides the TLS SNI / certificate-name verification
	// host. Empty => the host parsed from the dialed Servers address. Ignored when
	// RadSecTLSConfig is supplied.
	RadSecServerName string

	// RadSecInsecureSkipVerify disables TLS certificate verification on the
	// RadSec connection. DANGEROUS — a man-in-the-middle can then impersonate the
	// RADIUS server. Permitted ONLY for development, and ONLY together with
	// RadSecAllowInsecure (so it cannot be tripped without also acknowledging the
	// insecure posture). Ignored when RadSecTLSConfig is supplied.
	RadSecInsecureSkipVerify bool

	// RadSecAllowInsecure opts OUT of the RadSec-certificate-verification gate,
	// permitting RadSecInsecureSkipVerify. It exists only for local development /
	// a trusted-network test server and MUST NEVER be set in production.
	RadSecAllowInsecure bool
}

// Validate checks the required fields and the security-anchor invariant
// (non-empty shared secret), failing the operator's boot CLOSED on a
// misconfiguration — a credential-validation gate with no server or no shared
// secret is not a runtime warning but a security/wiring regression. It performs
// NO network I/O (the server is contacted lazily, per Authenticate), so a
// down server does not block startup.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("radius: Name required")
	}
	if len(c.Servers) == 0 {
		return errors.New("radius: at least one server (host:port) required")
	}
	for _, s := range c.Servers {
		if strings.TrimSpace(s) == "" {
			return errors.New("radius: server address must not be empty")
		}
		// A bare host with no port is the most common RADIUS misconfiguration
		// (1812 is NOT a default the wire assumes); reject it loud at boot rather
		// than fail every login with an opaque dial error.
		if !strings.Contains(s, ":") {
			return fmt.Errorf("radius: server %q must be in host:port form (e.g. radius.example.com:1812)", s)
		}
	}

	// THE security anchor: the shared secret encrypts the PAP password AND
	// authenticates the server's reply. An empty secret leaves the password
	// effectively in the clear and the Response Authenticator unverifiable — a
	// catastrophic posture this gate refuses to start with.
	if c.SharedSecret == "" {
		return errors.New("radius: SharedSecret required (it is the security anchor — it encrypts the PAP password and authenticates the server's Response Authenticator)")
	}

	switch c.authProtocol() {
	case AuthPAP:
		// implemented
	case AuthCHAP:
		// CHAP is not implemented by the stock exchanger. Fail loud rather than
		// silently downgrade to PAP (which would be a surprising on-wire change of
		// the password protocol).
		return errors.New("radius: AuthProtocol \"chap\" is not implemented by the stock exchanger (use \"pap\", or supply a custom Exchanger for CHAP)")
	default:
		return fmt.Errorf("radius: unknown AuthProtocol %q (use \"pap\")", c.AuthProtocol)
	}

	if c.Retries < -1 {
		return errors.New("radius: Retries must be >= -1 (0 = default, -1 = no retransmit)")
	}

	// RadSec TLS gate: when verification is skipped it must be explicitly
	// acknowledged via RadSecAllowInsecure (mirrors the ldap InsecureSkipVerify /
	// AllowInsecure pairing) — a credential gate must not silently trust any
	// server certificate. The operator-supplied RadSecTLSConfig owns its own
	// verification, so this only governs the built-from-fields path.
	if c.UseRadSec && c.RadSecTLSConfig == nil {
		if c.RadSecInsecureSkipVerify && !c.RadSecAllowInsecure {
			return errors.New("radius: RadSecInsecureSkipVerify requires RadSecAllowInsecure (it disables RadSec certificate verification — development only)")
		}
		// A client cert for mutual RadSec needs BOTH halves; one without the other
		// cannot form a key pair.
		hasCert := len(c.RadSecClientCertPEM) > 0
		hasKey := len(c.RadSecClientKeyPEM) > 0
		if hasCert != hasKey {
			return errors.New("radius: RadSecClientCertPEM and RadSecClientKeyPEM must both be set (mutual RadSec) or both empty")
		}
	}
	return nil
}

// authProtocol resolves the configured protocol, defaulting to PAP.
func (c *Config) authProtocol() AuthProtocol {
	if c.AuthProtocol == "" {
		return AuthPAP
	}
	// Normalize case so "PAP"/"Pap" are accepted like the documented lowercase.
	return AuthProtocol(strings.ToLower(string(c.AuthProtocol)))
}

func (c *Config) nasIdentifier() string {
	if strings.TrimSpace(c.NASIdentifier) != "" {
		return c.NASIdentifier
	}
	return DefaultNASIdentifier
}

func (c *Config) requestTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// retries resolves the retransmit count (DefaultRetries when zero; a negative
// value means no retransmit).
func (c *Config) retries() int {
	if c.Retries == 0 {
		return DefaultRetries
	}
	if c.Retries < 0 {
		return 0
	}
	return c.Retries
}

// retryInterval derives the layeh client's resend interval so that all
// retransmits fit inside the bounded request Timeout: with N retries the request
// is sent up to N+1 times, spaced Timeout/(N+1) apart. A zero/negative result
// disables retransmit in layeh.
func (c *Config) retryInterval() time.Duration {
	n := c.retries()
	if n <= 0 {
		return 0
	}
	return c.requestTimeout() / time.Duration(n+1)
}

// useRadSec reports whether the RadSec (TLS) transport is selected.
func (c *Config) useRadSec() bool { return c.UseRadSec }

// useTCP reports whether a TCP transport (RadSec implies TCP, or an explicit
// plain-TCP selection) is needed for the layeh client's Net.
func (c *Config) useTCP() bool { return c.UseRadSec || c.UseTCP }

// radSecTLSConfig returns the *tls.Config for the RadSec connection: the
// operator-supplied one verbatim when set, else one built from the
// RadSec*PEM / RadSecServerName / RadSecInsecureSkipVerify fields. Called once
// at construction.
func (c *Config) radSecTLSConfig() (*tls.Config, error) {
	if c.RadSecTLSConfig != nil {
		return c.RadSecTLSConfig, nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.RadSecInsecureSkipVerify, // gated behind RadSecAllowInsecure in Validate
		ServerName:         c.RadSecServerName,
	}
	if len(c.RadSecCACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.RadSecCACertPEM) {
			return nil, errors.New("radius: RadSecCACertPEM contained no valid PEM certificate")
		}
		cfg.RootCAs = pool
	}
	if len(c.RadSecClientCertPEM) > 0 && len(c.RadSecClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(c.RadSecClientCertPEM, c.RadSecClientKeyPEM)
		if err != nil {
			// Do NOT echo the key bytes — only a generic reason.
			return nil, errors.New("radius: RadSecClientCertPEM/KeyPEM is not a valid certificate/key pair")
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
