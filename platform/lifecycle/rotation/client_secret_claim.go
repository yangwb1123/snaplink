package rotation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sync"
	"time"
)

// ClientSecretWarningClaim identifies one warning opportunity. SecretExpiresAt
// is the expiry generation: a changed expiry creates a new opportunity without
// putting secret material into the claim store.
type ClientSecretWarningClaim struct {
	ClientID        string
	Window          time.Duration
	Day             time.Time
	SecretExpiresAt time.Time
}

// ClientSecretWarningClaimStore atomically claims a warning opportunity. A
// true result means the caller owns emission; false means another scanner has
// already claimed the same client, window, UTC day, and expiry generation.
type ClientSecretWarningClaimStore interface {
	Claim(context.Context, ClientSecretWarningClaim) (bool, error)
}

// Fingerprint returns a fixed-size identity for a warning claim. Stores use it
// when they need a bounded key; the raw client ID and expiry are never part of
// the returned value.
func (c ClientSecretWarningClaim) Fingerprint() string {
	h := sha256.New()
	_, _ = h.Write([]byte("sso:client-secret-warning:v1"))
	writeClaimString(h, c.ClientID)
	writeClaimInt64(h, int64(c.Window))
	writeClaimInt64(h, clientSecretWarningDay(c.Day).Unix())
	writeClaimInt64(h, c.SecretExpiresAt.UTC().UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

func writeClaimString(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

func writeClaimInt64(h hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = h.Write(encoded[:])
}

func clientSecretWarningDay(day time.Time) time.Time {
	return day.UTC().Truncate(24 * time.Hour)
}

// MemoryClientSecretWarningClaimStore is the default-quality in-memory claim
// implementation for embedders and tests. The mutex makes a claim atomic when
// several scanner goroutines or replicas share one instance.
type MemoryClientSecretWarningClaimStore struct {
	mu       sync.Mutex
	claims   map[string]struct{}
	claimDay time.Time
}

// NewMemoryClientSecretWarningClaimStore constructs a concurrency-safe local
// warning claim store.
func NewMemoryClientSecretWarningClaimStore() *MemoryClientSecretWarningClaimStore {
	return &MemoryClientSecretWarningClaimStore{
		claims: make(map[string]struct{}),
	}
}

// Claim implements ClientSecretWarningClaimStore.
func (s *MemoryClientSecretWarningClaimStore) Claim(_ context.Context, claim ClientSecretWarningClaim) (bool, error) {
	if s == nil {
		return false, errors.New("client secret warning claim store is nil")
	}
	day := clientSecretWarningDay(claim.Day)
	key := claim.Fingerprint()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims == nil {
		s.claims = make(map[string]struct{})
	}
	if s.claimDay.IsZero() || day.After(s.claimDay) {
		clear(s.claims)
		s.claimDay = day
	}
	if _, exists := s.claims[key]; exists {
		return false, nil
	}
	s.claims[key] = struct{}{}
	return true, nil
}

var _ ClientSecretWarningClaimStore = (*MemoryClientSecretWarningClaimStore)(nil)

// ClientSecretExpiryScannerOption configures an expiry scanner without
// changing the compatibility of its original constructor arguments.
type ClientSecretExpiryScannerOption func(*ClientSecretExpiryScanner)

// WithClientSecretWarningClaimStore adds an optional shared warning claim
// store. A nil store preserves the scanner's local-only behavior.
func WithClientSecretWarningClaimStore(store ClientSecretWarningClaimStore) ClientSecretExpiryScannerOption {
	return func(s *ClientSecretExpiryScanner) {
		if store != nil {
			s.claimStore = store
		}
	}
}
