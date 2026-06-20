package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

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
//
// Strict() decoding rejects encodings whose trailing 2 unused bits
// of the final base64 char are non-zero. The standard encoder always
// emits zero there, so issued nonces decode fine; the strictness
// blocks the trivial mutation where a tamperer flips only the unused
// bits of the last char — that would decode to the same payload and
// pass the MAC check, breaking the one-string-one-nonce invariant
// this primitive depends on.
func (p *HMACNonceProvider) Verify(nonce string) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
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
	// ts + now are UnixNano, and time.Duration is already nanoseconds, so
	// int64(dpopProofClockSkewDefault) is the correct nanosecond bound here
	// (no .Seconds() — that would shrink the skew to 60ns). The nonce
	// provider is a standalone component with its own lifecycle (own ttl,
	// own key); it is not Server-coupled, so it tolerates the same default
	// future-skew as proof iat rather than reaching into a Server field.
	if ts > now+int64(dpopProofClockSkewDefault) {
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

// DefaultDPoPNonceTTL is the validity window of an HMAC-signed nonce.
const DefaultDPoPNonceTTL = 5 * time.Minute

// dpopProofClockSkewDefault tolerates clients whose clocks are slightly
// ahead of or behind the server — 60s matches the server's own DPoP
// proof iat window so a nonce issued near the end of its TTL never
// falsely rejects a valid proof.
const dpopProofClockSkewDefault = 60 * time.Second
