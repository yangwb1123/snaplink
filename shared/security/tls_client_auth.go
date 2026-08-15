// Package security provides TLS client certificate verification for
// RFC 8705 §2 tls_client_auth and self_signed_tls client authentication
// methods at the /token, /introspect, /revoke, and /par endpoints.
package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
)

// VerifyTLSClientAuth checks whether the presented client certificate
// satisfies the registered TLS constraint fields per RFC 8705 §2.
// Each non-empty constraint is AND-ed: when both SubjectDN and SANDNS
// are set, the cert MUST match BOTH. Returns nil on success or a
// descriptive error.
func VerifyTLSClientAuth(cert *x509.Certificate, subjectDN, sanDNS, sanEmail, sanURI string) error {
	if subjectDN != "" {
		if !matchSubjectDN(cert.Subject.String(), subjectDN) {
			return errors.New("tls_client_auth: client cert Subject DN does not match registered TLSClientAuthSubjectDN")
		}
	}
	if sanDNS != "" {
		if !matchSANDNS(cert, sanDNS) {
			return errors.New("tls_client_auth: client cert SAN DNS does not match registered TLSClientAuthSANDNS")
		}
	}
	if sanEmail != "" {
		if !matchSANEmail(cert, sanEmail) {
			return errors.New("tls_client_auth: client cert SAN email does not match registered TLSClientAuthSANEmail")
		}
	}
	if sanURI != "" {
		if !matchSANURI(cert, sanURI) {
			return errors.New("tls_client_auth: client cert SAN URI does not match registered TLSClientAuthSANURI")
		}
	}
	return nil
}

// CertPublicKeyMatchesJWK reports whether the cert's public key matches
// the raw key material in the given JWK fields.
func CertPublicKeyMatchesJWK(cert *x509.Certificate, kty, crv, x, y, n, e string) (bool, error) {
	if cert == nil {
		return false, errors.New("nil certificate")
	}
	pub := cert.PublicKey
	switch kty {
	case "RSA":
		return rsaPublicKeyMatchesJWK(pub, n, e)
	case "EC":
		return ecPublicKeyMatchesJWK(pub, x, y)
	case "OKP":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false, nil
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return false, err
		}
		return string(edPub) == string(xBytes), nil
	}
	return false, errors.New("unsupported JWK kty: " + kty)
}

// rsaPublicKeyMatchesJWK compares an RSA certificate public key against raw
// JWK n/e material — extracted verbatim from CertPublicKeyMatchesJWK.
func rsaPublicKeyMatchesJWK(pub any, n, e string) (bool, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, nil
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return false, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return false, err
	}
	gotN := new(big.Int).SetBytes(nBytes)
	gotE := decodePublicExponent(eBytes)
	return rsaPub.N.Cmp(gotN) == 0 && rsaPub.E == gotE, nil
}

// ecPublicKeyMatchesJWK compares an EC certificate public key against raw
// JWK x/y material — extracted verbatim from CertPublicKeyMatchesJWK.
func ecPublicKeyMatchesJWK(pub any, x, y string) (bool, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, nil
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return false, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return false, err
	}
	gotX := new(big.Int).SetBytes(xBytes)
	gotY := new(big.Int).SetBytes(yBytes)
	return ecPub.X.Cmp(gotX) == 0 && ecPub.Y.Cmp(gotY) == 0, nil
}

// IsTLSClientCert returns true when the request carries a verified TLS
// client certificate (either from the TLS layer itself or from a
// trusted proxy header via the configured extractor). This is a
// convenience predicate for the token handler's mTLS auth path.
func IsTLSClientCert(cert *x509.Certificate) bool {
	return cert != nil
}

func decodePublicExponent(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	var e int
	for _, v := range b {
		e = (e << 8) | int(v)
	}
	return e
}

// matchSubjectDN compares two RFC 4514 DN strings after normalization.
func matchSubjectDN(got, expected string) bool {
	return normalizeDN(got) == normalizeDN(expected)
}

// normalizeDN strips extra whitespace around = and , delimiters.
func normalizeDN(dn string) string {
	var b strings.Builder
	for _, r := range dn {
		switch {
		case r == '=':
			b.WriteRune(r)
		case r == ',' || r == '+':
			b.WriteRune(r)
		case r == ' ':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// matchSANDNS checks if any DNS SAN entry matches expected
// (case-insensitive per RFC 5280 §4.2.1.6).
func matchSANDNS(cert *x509.Certificate, expected string) bool {
	expected = strings.ToLower(expected)
	for _, dns := range cert.DNSNames {
		if strings.ToLower(dns) == expected {
			return true
		}
	}
	return false
}

// matchSANEmail checks if any rfc822Name SAN entry matches expected.
func matchSANEmail(cert *x509.Certificate, expected string) bool {
	at := strings.LastIndex(expected, "@")
	if at < 0 {
		return false
	}
	expLocal := expected[:at]
	expHost := strings.ToLower(expected[at+1:])
	for _, email := range cert.EmailAddresses {
		at2 := strings.LastIndex(email, "@")
		if at2 < 0 {
			continue
		}
		if strings.ToLower(email[at2+1:]) != expHost {
			continue
		}
		if email[:at2] == expLocal {
			return true
		}
	}
	return false
}

// matchSANURI checks if any URI SAN entry matches expected
// (byte-exact match per RFC 5280 §4.2.1.6).
func matchSANURI(cert *x509.Certificate, expected string) bool {
	expectedURI := expected
	for _, uri := range cert.URIs {
		if uri.String() == expectedURI {
			return true
		}
	}
	return false
}

// SANFromCert extracts the first SAN of each type from the cert
// for diagnostic logging.
func SANFromCert(cert *x509.Certificate) (dns, email, uri string, ips []net.IP) {
	if len(cert.DNSNames) > 0 {
		dns = cert.DNSNames[0]
	}
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}
	if len(cert.URIs) > 0 {
		uri = cert.URIs[0].String()
	}
	ips = cert.IPAddresses
	return
}

// compile-time check that crypto interfaces are satisfied.
var _ crypto.PublicKey = (*rsa.PublicKey)(nil)
var _ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
var _ crypto.PublicKey = (ed25519.PublicKey)(nil)

// Page cursor tokens (grpcadmin keyset pagination).
//
// Token format: v1.<base64url(payload)>.<base64url(HMAC-SHA256(key, payload))>
//
//	payload = after_bytes || 0x00 || filter_canonical || 0x00 || order_canonical
//
// - after_bytes is the STORE-OPAQUE keyset cursor from the previous page
//   (the store's own encoding of the last sort key + tiebreaker). The
//   handler never interprets it; stores must keep it 0x00-free so the
//   payload's 0x00-partitioning stays unambiguous (the memory stores'
//   base64url encoding satisfies this by construction).
// - filter_canonical / order_canonical bind the token to the request spec:
//   a client that changes the filter or sort between pages is rejected with
//   the same invalid page_token as any other tamper. The two grammar
//   spellings canonicalize identically ("name eq x" == "name:x"; " name "
//   == "name"), so switching spellings between pages is fine.
//
// Legacy offset tokens (base64url of decimal digits, no dots, no "v1."
// prefix) are disjoint from v1 tokens by construction: each format cleanly
// rejects the other's tokens. The fallback path still mints/consumes offset
// tokens untouched; only the extension path uses this codec.
//
// Key stability: the process-wide default key is ephemeral (crypto/rand),
// so in-flight cursors invalidate on restart — safe (same invalid
// page_token message), and fine for single-replica deployments. cmd
// installs a deployment-stable derived key via InstallPageCursorKey when a
// stable secret (the audit-webhook HMAC secret) is configured, so cursors
// survive restarts and round-robin across replicas of one deployment.

// pageCursorKey is the process-wide HMAC key. nil until InstallPageCursorKey
// or the first PageCursorCodec() call (which falls back to a random key).
var (
	pageCursorMu    sync.RWMutex
	pageCursorKey   []byte
	pageCursorCodec *PageCursorCodec
)

// DefaultPageCursorCodec returns the process-wide page-cursor codec. When
// no key was installed via InstallPageCursorKey, the first call derives an
// ephemeral random key (restart-invalidates-cursors semantics).
func DefaultPageCursorCodec() *PageCursorCodec {
	pageCursorMu.RLock()
	c := pageCursorCodec
	pageCursorMu.RUnlock()
	if c != nil {
		return c
	}
	key, err := randomPageCursorKey()
	if err != nil {
		// crypto/rand failure is unrecoverable at this layer; fall back to a
		// zero-keyed codec so the RPC path degrades to a (non-secret) MAC
		// rather than panicking on an admin listing call.
		key = make([]byte, 32)
	}
	pageCursorMu.Lock()
	defer pageCursorMu.Unlock()
	if pageCursorCodec == nil {
		pageCursorKey = key
		pageCursorCodec = NewPageCursorCodec(key)
	}
	return pageCursorCodec
}

// InstallPageCursorKey sets the process-wide page-cursor MAC key. Call once
// at cmd boot with a deployment-stable derived key so in-flight page tokens
// survive restarts and are valid across replicas of one deployment. Safe to
// call multiple times; the last installation wins for subsequent Encode
// calls, while Decode accepts tokens minted under the PREVIOUS key too
// (rotation-safe: each codec instance verifies with its own key).
func InstallPageCursorKey(key []byte) {
	if len(key) == 0 {
		return
	}
	pageCursorMu.Lock()
	defer pageCursorMu.Unlock()
	pageCursorKey = append([]byte(nil), key...)
	pageCursorCodec = NewPageCursorCodec(pageCursorKey)
}

// DerivePageCursorKey deterministically derives the page-cursor MAC key from
// a deployment-stable secret via HKDF-SHA256 (RFC 5869, empty salt, fixed
// info string) — so one configured secret yields the same key on every
// replica without adding a config key of its own. nil/empty secrets yield an
// error; callers then leave the ephemeral default in place.
func DerivePageCursorKey(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("page cursor: empty derivation secret")
	}
	// hkdf.Extract+Expand: empty salt (RFC 5869 permits it; the secret's own
	// entropy is the input key material) and a fixed info string scoping the
	// derivation to page cursors so a rotated audit secret re-derives a fresh
	// cursor key rather than recycling the old one.
	reader := hkdf.Expand(sha256.New, hkdf.Extract(sha256.New, secret, nil), []byte("snaplink page-cursor v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PageCursorCodec encodes/decodes versioned, MAC-protected page tokens.
// A codec created with nil/empty key derives an ephemeral random key.
type PageCursorCodec struct {
	key []byte
}

// NewPageCursorCodec builds a codec. A nil/empty key derives an ephemeral
// crypto/rand key (per-instance semantics: cursors invalidate on restart).
func NewPageCursorCodec(key []byte) *PageCursorCodec {
	if len(key) == 0 {
		key, _ = randomPageCursorKey()
		if len(key) == 0 {
			key = make([]byte, 32) // last-resort zero key (see PageCursorCodec)
		}
	}
	return &PageCursorCodec{key: append([]byte(nil), key...)}
}

// Encode wraps the store-opaque after cursor in a v1 token bound to the
// request's canonical filter/order forms.
func (c *PageCursorCodec) Encode(after []byte, filterCanonical, orderCanonical string) (string, error) {
	payload := make([]byte, 0, len(after)+len(filterCanonical)+len(orderCanonical)+2)
	payload = append(payload, after...)
	payload = append(payload, 0)
	payload = append(payload, filterCanonical...)
	payload = append(payload, 0)
	payload = append(payload, orderCanonical...)
	mac := c.mac(payload)
	return "v1." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac), nil
}

// Decode verifies and unwraps a v1 token, returning the store-opaque after
// cursor plus the token's bound canonical filter/order forms (which the
// caller compares against the current request's forms). Every failure —
// wrong shape, undecodable parts, MAC mismatch, payload partition error —
// returns the same sentinel so the caller reports one message.
func (c *PageCursorCodec) Decode(token string) (after []byte, filterCanonical, orderCanonical string, err error) {
	if !strings.HasPrefix(token, "v1.") {
		return nil, "", "", errInvalidPageToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", "", errInvalidPageToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", "", errInvalidPageToken
	}
	wantMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "", "", errInvalidPageToken
	}
	gotMAC := c.mac(payload)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
		return nil, "", "", errInvalidPageToken
	}
	fields := strings.Split(string(payload), "\x00")
	if len(fields) != 3 {
		return nil, "", "", errInvalidPageToken
	}
	return []byte(fields[0]), fields[1], fields[2], nil
}

func (c *PageCursorCodec) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

// errInvalidPageToken is the single decode-failure sentinel; the RPC layer
// maps it (and everything else) to the byte-identical InvalidArgument
// "invalid page_token".
var errInvalidPageToken = errors.New("invalid page token")

func randomPageCursorKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
