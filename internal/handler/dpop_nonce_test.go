package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// TestHMACNonceProvider_IssueVerifyRoundTrip locks the happy path: a freshly
// issued nonce verifies cleanly under the same provider.
func TestHMACNonceProvider_IssueVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	p, err := NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}
	nonce, err := p.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if nonce == "" {
		t.Fatal("Issue returned empty nonce")
	}
	if err := p.Verify(nonce); err != nil {
		t.Fatalf("Verify of freshly issued nonce: %v", err)
	}
}

// TestHMACNonceProvider_TTLFallback locks the ttl<=0 fallback to the default.
func TestHMACNonceProvider_TTLFallback(t *testing.T) {
	t.Parallel()
	p, err := NewHMACNonceProvider(0)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}
	if p.ttl != DefaultDPoPNonceTTL {
		t.Fatalf("ttl = %v, want default %v", p.ttl, DefaultDPoPNonceTTL)
	}
	p2, err := NewHMACNonceProvider(-time.Second)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider(neg): %v", err)
	}
	if p2.ttl != DefaultDPoPNonceTTL {
		t.Fatalf("negative ttl: ttl = %v, want default %v", p2.ttl, DefaultDPoPNonceTTL)
	}
}

// TestNewHMACNonceProviderWithKey covers the shared-key constructor: short keys
// are rejected, the key is defensively copied so a later caller mutation can't
// silently rotate the signing secret, and ttl<=0 still falls back to default.
func TestNewHMACNonceProviderWithKey(t *testing.T) {
	t.Parallel()
	if _, err := NewHMACNonceProviderWithKey(make([]byte, 15), time.Minute); err == nil {
		t.Fatal("expected error for key < 16 bytes")
	}

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	p, err := NewHMACNonceProviderWithKey(key, 0)
	if err != nil {
		t.Fatalf("NewHMACNonceProviderWithKey: %v", err)
	}
	if p.ttl != DefaultDPoPNonceTTL {
		t.Fatalf("ttl = %v, want default", p.ttl)
	}

	nonce, err := p.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Mutating the caller's key buffer must not change verification: the
	// provider holds its own copy.
	key[0] ^= 0xFF
	if err := p.Verify(nonce); err != nil {
		t.Fatalf("Verify after mutating caller key copy: %v (key not defensively copied?)", err)
	}
}

// TestHMACNonceProvider_MultiKeyVerify locks the multi-replica contract: a
// nonce issued by one replica verifies on a peer sharing the same key, and a
// peer with a DIFFERENT key rejects it (tag mismatch).
func TestHMACNonceProvider_MultiKeyVerify(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	replicaA, err := NewHMACNonceProviderWithKey(key, time.Minute)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	replicaB, err := NewHMACNonceProviderWithKey(append([]byte(nil), key...), time.Minute)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	nonce, err := replicaA.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := replicaB.Verify(nonce); err != nil {
		t.Fatalf("peer with shared key rejected nonce: %v", err)
	}

	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(255 - i)
	}
	stranger, err := NewHMACNonceProviderWithKey(otherKey, time.Minute)
	if err != nil {
		t.Fatalf("stranger: %v", err)
	}
	if err := stranger.Verify(nonce); err == nil {
		t.Fatal("provider with a different key must reject the nonce (tag mismatch)")
	}
}

// TestHMACNonceProvider_VerifyRejectsMalformed covers the structural rejections
// before the MAC check: bad base64, wrong length, and the strict-decoding guard
// against flipping the unused trailing bits of the final base64 char.
func TestHMACNonceProvider_VerifyRejectsMalformed(t *testing.T) {
	t.Parallel()
	p, err := NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}

	if err := p.Verify("!!!not base64!!!"); err == nil {
		t.Fatal("expected base64 decode error")
	}
	// Valid base64 but wrong decoded length.
	short := base64.RawURLEncoding.EncodeToString([]byte("too short"))
	if err := p.Verify(short); err == nil {
		t.Fatal("expected wrong-length rejection")
	}

	// Tampering with the trailing unused bits of the last char must be rejected
	// by Strict() decoding even though it would decode to an identical payload.
	nonce, err := p.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mutated := flipLastCharUnusedBits(t, nonce)
	if mutated != nonce {
		if err := p.Verify(mutated); err == nil {
			t.Fatal("strict decode must reject a nonce with non-zero trailing unused bits")
		}
	}
}

// TestHMACNonceProvider_VerifyRejectsTampered locks the MAC check: flipping a
// payload byte invalidates the tag.
func TestHMACNonceProvider_VerifyRejectsTampered(t *testing.T) {
	t.Parallel()
	p, err := NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}
	nonce, err := p.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[0] ^= 0xFF // corrupt the random prefix (part of the MAC'd payload)
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if err := p.Verify(tampered); err == nil {
		t.Fatal("expected tag mismatch on corrupted payload")
	}
}

// TestHMACNonceProvider_VerifyExpired locks the TTL lower bound: a nonce older
// than ttl is rejected as expired. A sub-second TTL keeps the test fast.
func TestHMACNonceProvider_VerifyExpired(t *testing.T) {
	t.Parallel()
	p, err := NewHMACNonceProvider(20 * time.Millisecond)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}
	nonce, err := p.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := p.Verify(nonce); err != nil {
		t.Fatalf("freshly issued nonce should verify: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := p.Verify(nonce); err == nil {
		t.Fatal("expected expired rejection after ttl elapsed")
	}
}

// TestHMACNonceProvider_VerifyFutureSkew locks the upper bound: a nonce whose
// timestamp is beyond now + clock skew is rejected as "issued in the future".
// We forge a nonce far in the future by re-MACing a future timestamp under a
// known key (so it passes the tag check and reaches the skew gate).
func TestHMACNonceProvider_VerifyFutureSkew(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	p, err := NewHMACNonceProviderWithKey(key, time.Minute)
	if err != nil {
		t.Fatalf("NewHMACNonceProviderWithKey: %v", err)
	}
	// Timestamp well beyond the 60s skew tolerance.
	future := time.Now().Add(10 * time.Minute).UnixNano()
	forged := forgeNonce(key, future)
	if err := p.Verify(forged); err == nil {
		t.Fatal("expected future-skew rejection for a far-future timestamp")
	}

	// A timestamp within the skew window must still verify (proves the gate is
	// a tolerance, not a hard now() comparison).
	withinSkew := time.Now().Add(30 * time.Second).UnixNano()
	if err := p.Verify(forgeNonce(key, withinSkew)); err != nil {
		t.Fatalf("nonce within clock-skew tolerance should verify: %v", err)
	}
}

// flipLastCharUnusedBits returns nonce with the final base64url char swapped
// for one differing only in its unused low bits, or the original if no such
// swap exists. RawURLEncoding's alphabet means many chars share a 6-bit prefix.
func flipLastCharUnusedBits(t *testing.T, nonce string) string {
	t.Helper()
	if nonce == "" {
		return nonce
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := nonce[len(nonce)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx < 0 {
		return nonce
	}
	// The decoded payload is a whole number of bytes (52 bytes -> no leftover
	// bits in this layout), so flip the lowest bit of the final symbol; Strict()
	// rejects it if those bits are unused. This is a best-effort mutation: when
	// the symbol carries no unused bits the caller skips the assertion.
	if idx%2 == 0 && idx+1 < len(alphabet) {
		return nonce[:len(nonce)-1] + string(alphabet[idx+1])
	}
	return nonce[:len(nonce)-1] + string(alphabet[idx-1])
}

// forgeNonce reproduces the on-wire layout (16 random || 8 ts || 32 mac) for a
// chosen timestamp under a known key so tests can drive the skew/expiry gates
// past the MAC check. NOT exported; mirrors Issue's encoding exactly.
func forgeNonce(key []byte, tsUnixNano int64) string {
	payload := make([]byte, dpopNonceRandomLen+dpopNonceTSLen)
	// Random prefix can be anything; the MAC binds it regardless.
	for i := 0; i < dpopNonceRandomLen; i++ {
		payload[i] = byte(i)
	}
	binary.BigEndian.PutUint64(payload[dpopNonceRandomLen:], uint64(tsUnixNano))
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	out := append(append([]byte(nil), payload...), mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(out)
}
