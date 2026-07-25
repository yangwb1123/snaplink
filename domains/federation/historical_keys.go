// Package federation — OpenID Federation 1.0 historical signing keys (§8.5).
//
// The historical_keys endpoint exposes previously-published signing keys that
// have been rotated out of the active JWKS but may still be needed by relying
// parties to verify signatures on old entity statements, trust marks, or
// assertions issued while those keys were active. Without this endpoint, an RP
// that cached an OP's keys at issuance time and sees a rotated key on
// re-fetch would reject the previously-valid signature.
//
// §8.5: "The historical_keys endpoint [...] returns a JWKS containing all
// signing keys that have been used by this entity in the past."
//
// The endpoint is served at the URL advertised in the entity configuration's
// metadata.federation_op.historical_keys_endpoint.
package federation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// HistoricalKey records one previously-used signing key.
type HistoricalKey struct {
	// KID is the key identifier that was used in the JWK.
	KID string `json:"kid"`

	// JWK is the JSON Web Key (public portion only).
	JWK map[string]any `json:"jwk"`

	// ActiveFrom is when this key was first published.
	ActiveFrom time.Time `json:"active_from"`

	// ActiveUntil is when this key was rotated out (zero = still potentially active).
	ActiveUntil time.Time `json:"active_until,omitempty"`

	// RetiredAt is when this key was formally retired.
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// HistoricalKeyStore persists retired signing keys.
type HistoricalKeyStore interface {
	// RecordKey persists a newly-retired key alongside its active window.
	RecordKey(ctx context.Context, key *HistoricalKey) error

	// HistoricalKeys returns all recorded historical keys ordered by
	// active_from descending (most recent first).
	HistoricalKeys(ctx context.Context) ([]*HistoricalKey, error)

	// HistoricalKeysByKID returns a specific historical key by its KID.
	HistoricalKeysByKID(ctx context.Context, kid string) (*HistoricalKey, error)
}

// ErrKeyNotFound is returned when a historical key is not found.
var ErrKeyNotFound = errors.New("federation: historical key not found")

// MemoryHistoricalKeyStore is an in-memory HistoricalKeyStore.
type MemoryHistoricalKeyStore struct {
	mu    sync.RWMutex
	keys  map[string]*HistoricalKey
	order []string // KID order by active_from desc
}

// NewMemoryHistoricalKeyStore returns an empty in-memory historical key store.
func NewMemoryHistoricalKeyStore() *MemoryHistoricalKeyStore {
	return &MemoryHistoricalKeyStore{
		keys: make(map[string]*HistoricalKey),
	}
}

func (s *MemoryHistoricalKeyStore) RecordKey(_ context.Context, key *HistoricalKey) error {
	if key.KID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		key.KID = "hk_" + hex.EncodeToString(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KID] = key
	s.rebuildOrder()
	return nil
}

func (s *MemoryHistoricalKeyStore) HistoricalKeys(_ context.Context) ([]*HistoricalKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*HistoricalKey, 0, len(s.order))
	for _, kid := range s.order {
		if k, ok := s.keys[kid]; ok {
			out = append(out, k)
		}
	}
	return out, nil
}

func (s *MemoryHistoricalKeyStore) HistoricalKeysByKID(_ context.Context, kid string) (*HistoricalKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (s *MemoryHistoricalKeyStore) rebuildOrder() {
	s.order = make([]string, 0, len(s.keys))
	for kid := range s.keys {
		s.order = append(s.order, kid)
	}
	sort.Slice(s.order, func(i, j int) bool {
		return s.keys[s.order[i]].ActiveFrom.After(s.keys[s.order[j]].ActiveFrom)
	})
}

// compile-time interface checks.
var (
	_ HistoricalKeyStore = (*MemoryHistoricalKeyStore)(nil)
)
