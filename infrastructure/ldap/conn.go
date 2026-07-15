package ldapauth

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// conn is the MINIMAL slice of *ldap.Conn the Authenticator uses. Declaring our
// own interface (rather than depending on *ldap.Conn directly) keeps the seam
// test-injectable: the real *ldap.Conn from go-ldap satisfies it structurally,
// and conn_test.go injects an in-process fake directory with NO real LDAP
// server. Mirrors kms/awskms's KMSAPI minimal-interface discipline (§4: "a
// small interface the prod impl satisfies, a fake for tests").
//
// Only the four operations the auth flow needs appear here:
//   - Bind  — service-account bind (search leg) AND user bind (verify leg).
//   - Search — locate the user entry + (optionally) the user's groups.
//   - StartTLS — upgrade a plaintext ldap:// connection before any bind.
//   - Close — release the connection.
type conn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(config *tls.Config) error
	Close() error
}

// dialer opens a conn to one directory URL with a dial timeout. The prod impl
// (ldapDialer) wraps ldap.DialURL; tests supply a fake that returns an
// in-process directory. The dial is the ONLY place a network connection is
// created, so injecting the dialer fully isolates the tests from any real
// server.
type dialer interface {
	Dial(rawURL string, timeout time.Duration, tlsCfg *tls.Config) (conn, error)
}

// ldapConn adapts *ldap.Conn to the conn interface. The method set already
// matches; this named wrapper exists so the package compiles against the
// interface and so SetTimeout (the per-operation bound) is applied uniformly.
type ldapConn struct {
	*ldap.Conn
}

// Close satisfies conn.Close (ldap.Conn.Close returns an error in recent
// go-ldap; the wrapper pins the signature the interface declares).
func (c *ldapConn) Close() error { return c.Conn.Close() }

// ldapDialer is the production dialer: it opens a real connection via
// ldap.DialURL. For an ldaps:// URL the TLS handshake happens during the dial
// (DialWithTLSConfig); for an ldap:// URL the connection is plaintext until the
// caller invokes StartTLS. The per-operation request timeout is applied via
// Conn.SetTimeout so a hung bind/search cannot stall a login past its bound.
type ldapDialer struct {
	requestTimeout time.Duration
}

func (d *ldapDialer) Dial(rawURL string, timeout time.Duration, tlsCfg *tls.Config) (conn, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("ldap: parse URL %q: %w", rawURL, err)
	}
	opts := []ldap.DialOpt{
		// Bound the TCP/TLS connect so a black-holed directory host returns
		// promptly instead of hanging the login goroutine.
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
	}
	// For ldaps:// the TLS config is consumed during the dial. For ldap:// it is
	// unused here (StartTLS, called by the authenticator after the dial, carries
	// its own config) — passing it is harmless.
	if strings.EqualFold(u.Scheme, "ldaps") && tlsCfg != nil {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	c, err := ldap.DialURL(rawURL, opts...)
	if err != nil {
		return nil, err
	}
	// Per-request deadline for every subsequent bind/search on this conn. NOTE:
	// this does NOT bound a later StartTLS's raw TLS handshake — see
	// startTLSWithTimeout, which the authenticator wraps StartTLS in for
	// exactly that reason.
	if d.requestTimeout > 0 {
		c.SetTimeout(d.requestTimeout)
	}
	return &ldapConn{Conn: c}, nil
}

// startTLSWithTimeout bounds c.StartTLS to timeout. go-ldap's Conn.SetTimeout
// (applied above in ldapDialer.Dial) only arms a timer around the StartTLS
// extended-request/response wait: the raw tls.Conn.Handshake() call StartTLS
// makes immediately AFTER that response arrives has NO timeout of its own —
// go-ldap never calls SetDeadline on the underlying net.Conn, and that field
// (Conn.conn) is unexported, so a caller outside the ldap package cannot set
// one either. Left unbounded, a directory that accepts the StartTLS extended
// op but then stalls the handshake bytes (a black hole, or a deliberately
// slow peer) would hang this dial attempt — and the login request driving it
// — forever, silently breaking the "worst-case total connect time is
// len(URLs) * DialTimeout" invariant DefaultDialTimeout documents. We race
// StartTLS against timeout and close c on expiry: closing the shared
// net.Conn unblocks whatever Read the abandoned Handshake() goroutine is
// stuck in, so it cannot outlive this call by more than an instant.
func startTLSWithTimeout(c conn, tlsCfg *tls.Config, timeout time.Duration) error {
	if timeout <= 0 {
		return c.StartTLS(tlsCfg)
	}
	done := make(chan error, 1) // buffered: a late result from the abandoned goroutine must not leak it
	go func() { done <- c.StartTLS(tlsCfg) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = c.Close()
		return fmt.Errorf("StartTLS timed out after %s", timeout)
	}
}
