package sso

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// DefaultDPoPNonceTTL is the validity window of an HMAC-signed nonce.
// Long enough that a client's natural retry cadence reuses the same
// nonce; short enough that a stolen nonce expires before it could be
// pre-computed at scale.
const DefaultDPoPNonceTTL = 5 * time.Minute

// HeaderDPoPNonce is the RFC 9449 §8 response header carrying a
// fresh server-issued nonce to a client. Clients read this from a
// `use_dpop_nonce` challenge response and copy it into the `nonce`
// claim of the next DPoP proof JWT.
const HeaderDPoPNonce = "DPoP-Nonce"

// DPoPNonceProvider issues and verifies short-lived nonces used in
// RFC 9449 §8 nonce-bound DPoP proofs. Stateless implementations
// (HMAC-signed) are recommended; stateful (random + store) is also
// valid but pays a lookup per verify.
//
// Issue returns a fresh nonce suitable for emission via the
// `DPoP-Nonce` header. Verify returns nil when the nonce is valid
// and within its freshness window; the returned error is opaque to
// the caller, which only branches on nil / non-nil.
type DPoPNonceProvider interface {
	Issue() (string, error)
	Verify(nonce string) error
}

// HMACNonceProvider is the default stateless DPoPNonceProvider.
// Nonces encode `random[16] || timestamp_unix_seconds[8 big-endian]`
// followed by a `HMAC-SHA256(key, payload)` tag, base64url-encoded
// without padding. Verify recomputes the tag with constant-time
// compare and checks the timestamp window.
//
// Stateless = no store, no replay defense (DPoP's `jti` already
// covers replay). The key is process-local; restart rotates it, which
// invalidates all outstanding nonces but is harmless — clients just
// see a fresh challenge on their next request.
type HMACNonceProvider struct {
	key []byte
	ttl time.Duration
}

// NewHMACNonceProvider builds a provider keyed by a process-local
// 32-byte secret derived from crypto/rand. ttl <= 0 falls back to
// DefaultDPoPNonceTTL.
func NewHMACNonceProvider(ttl time.Duration) (*HMACNonceProvider, error) {
	if ttl <= 0 {
		ttl = DefaultDPoPNonceTTL
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &HMACNonceProvider{key: key, ttl: ttl}, nil
}

// NewHMACNonceProviderWithKey is the same as NewHMACNonceProvider but
// uses the supplied secret. Use in multi-replica deployments so
// nonces issued by one replica are verifiable by every other; key
// MUST be >= 16 bytes.
func NewHMACNonceProviderWithKey(key []byte, ttl time.Duration) (*HMACNonceProvider, error) {
	if len(key) < 16 {
		return nil, errors.New("dpop nonce: key must be >= 16 bytes")
	}
	if ttl <= 0 {
		ttl = DefaultDPoPNonceTTL
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &HMACNonceProvider{key: dup, ttl: ttl}, nil
}

const (
	dpopNonceRandomLen = 16
	dpopNonceTSLen     = 8
	dpopNonceMACLen    = 32
	dpopNonceTotalLen  = dpopNonceRandomLen + dpopNonceTSLen + dpopNonceMACLen
)

// Issue generates a fresh nonce with the current timestamp
// (nanosecond resolution so sub-second TTLs work for tests; real
// deployments use minute-scale TTLs and don't care about precision).
func (p *HMACNonceProvider) Issue() (string, error) {
	var payload [dpopNonceRandomLen + dpopNonceTSLen]byte
	if _, err := rand.Read(payload[:dpopNonceRandomLen]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(payload[dpopNonceRandomLen:], uint64(time.Now().UnixNano()))
	mac := hmac.New(sha256.New, p.key)
	mac.Write(payload[:])
	tag := mac.Sum(nil)
	out := make([]byte, 0, dpopNonceTotalLen)
	out = append(out, payload[:]...)
	out = append(out, tag...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Verify rejects a nonce that is malformed, tag-invalid, or expired.
// Returned errors are descriptive for logs but the wire response only
// cares whether the call returned nil.
func (p *HMACNonceProvider) Verify(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return errors.New("dpop nonce: base64 decode")
	}
	if len(raw) != dpopNonceTotalLen {
		return errors.New("dpop nonce: wrong length")
	}
	payload := raw[:dpopNonceRandomLen+dpopNonceTSLen]
	tag := raw[dpopNonceRandomLen+dpopNonceTSLen:]
	mac := hmac.New(sha256.New, p.key)
	mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(want, tag) {
		return errors.New("dpop nonce: tag mismatch")
	}
	ts := int64(binary.BigEndian.Uint64(payload[dpopNonceRandomLen:]))
	now := time.Now().UnixNano()
	if ts > now+int64(dpopProofClockSkew) {
		return errors.New("dpop nonce: issued in the future")
	}
	if ts < now-int64(p.ttl) {
		return errors.New("dpop nonce: expired")
	}
	return nil
}

// ErrDPoPNonceRequired is returned by verifyDPoPProof when a nonce
// provider is wired and the proof either lacks a `nonce` claim or
// carries one Verify rejects. Handlers MUST detect this sentinel
// (via errors.Is) and respond with a fresh `DPoP-Nonce` header +
// `use_dpop_nonce` error code at the appropriate HTTP status.
var ErrDPoPNonceRequired = errors.New("dpop: nonce required")

// WithJWKSCacheTTL overrides the Cache-Control max-age advertised
// on /.well-known/jwks.json. Default is [DefaultJWKSCacheMaxAge]
// (5 minutes). Lower this when key rotation must propagate faster;
// raise it when RP traffic strains the JWKS endpoint.
//
// Note: many RP libraries cache the JWKS in-process past the
// max-age signal, so the practical lower bound depends on the RP
// fleet's behavior. Validating-side ETag + 304 keeps the round
// trips cheap, so an aggressive low value (30s-60s) is usually
// safe without flooding origins.
func WithJWKSCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.jwksCacheTTL = ttl }
}

// WithMetadataSigner enables RFC 8414 §2.1 signed_metadata on the
// discovery document. When wired, every /.well-known/openid-configuration
// response carries a `signed_metadata` field whose value is a JWS over
// the same claims as the surrounding document; RPs verify the
// signature against JWKS before trusting any endpoint. Defends
// against a tampering proxy substituting endpoints — a security
// improvement that's a one-line opt-in.
//
// Both the default Ed25519JWTIssuer and IDTokenIssuer satisfy
// MetadataSigner — pass either, typically the same instance already
// wired as TokenIssuer / IDTokenIssuer so JWKS continues to cover
// metadata signing with one key.
func WithMetadataSigner(s MetadataSigner) Option {
	return func(srv *Server) { srv.metadataSigner = s }
}

// WithDPoPNonceProvider enables RFC 9449 §8 nonce-bound DPoP proofs.
// When set, /token rejects DPoP-bearing requests that lack a fresh
// `nonce` claim with 400 `use_dpop_nonce` + a `DPoP-Nonce` response
// header carrying a server-issued nonce the client must echo on
// retry. /userinfo applies the same gate with 401 instead of 400.
//
// Trade-off: every DPoP request now requires a prior nonce
// challenge, which adds one round-trip the first time. Clients
// SHOULD cache and rotate the nonce per server's freshness window.
// Skip this option to keep the original two-step flow.
func WithDPoPNonceProvider(p DPoPNonceProvider) Option {
	return func(s *Server) { s.dpopNonceProvider = p }
}

// stampDPoPNonce writes a fresh DPoP-Nonce header on the current
// response. Silently no-ops when no provider is wired (which also
// means the caller should never have invoked stamp in the first
// place — defensive).
func (s *Server) stampDPoPNonce(ctx HandlerContext) {
	if s.dpopNonceProvider == nil {
		return
	}
	n, err := s.dpopNonceProvider.Issue()
	if err != nil {
		s.logger.Error("dpop nonce issue failed", "error", err)
		return
	}
	ctx.ResponseWriter().Header().Set(HeaderDPoPNonce, n)
}
