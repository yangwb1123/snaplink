package defaultimpl

import (
	"context"
	"sort"
	"sync"

	"github.com/snaplink/sso/core"
)

// MemoryConsentStore is an in-memory implementation of [core.ConsentStore].
// Suitable for tests and single-process deployments; not durable across
// restarts. Thread-safe.
type MemoryConsentStore struct {
	mu     sync.RWMutex
	grants map[string]core.ConsentGrant // key: userID + ":" + clientID
}

// NewMemoryConsentStore returns an empty MemoryConsentStore.
func NewMemoryConsentStore() *MemoryConsentStore {
	return &MemoryConsentStore{
		grants: make(map[string]core.ConsentGrant),
	}
}

func consentKey(userID, clientID string) string {
	return userID + ":" + clientID
}

// RecordConsent upserts the grant for (userID, clientID), normalizing
// the scope list to a sorted, deduplicated slice.
func (m *MemoryConsentStore) RecordConsent(_ context.Context, grant core.ConsentGrant) error {
	grant.Scopes = normalizeScopes(grant.Scopes)
	m.mu.Lock()
	m.grants[consentKey(grant.UserID, grant.ClientID)] = grant
	m.mu.Unlock()
	return nil
}

// GetConsent returns the stored grant for (userID, clientID), or
// ErrNoConsentGrant when none exists.
func (m *MemoryConsentStore) GetConsent(_ context.Context, userID, clientID string) (core.ConsentGrant, error) {
	m.mu.RLock()
	g, ok := m.grants[consentKey(userID, clientID)]
	m.mu.RUnlock()
	if !ok {
		return core.ConsentGrant{}, core.ErrNoConsentGrant
	}
	return g, nil
}

// RevokeConsent removes the grant for (userID, clientID). Idempotent.
func (m *MemoryConsentStore) RevokeConsent(_ context.Context, userID, clientID string) error {
	m.mu.Lock()
	delete(m.grants, consentKey(userID, clientID))
	m.mu.Unlock()
	return nil
}

// ListByUser returns all grants for userID in descending GrantedAt order.
// Returns an empty slice (not an error) when none exist.
func (m *MemoryConsentStore) ListByUser(_ context.Context, userID string) ([]core.ConsentGrant, error) {
	m.mu.RLock()
	var out []core.ConsentGrant
	for _, g := range m.grants {
		if g.UserID == userID {
			out = append(out, g)
		}
	}
	m.mu.RUnlock()
	// Descending GrantedAt (most recent first) for stable output.
	sort.Slice(out, func(i, j int) bool {
		return out[i].GrantedAt.After(out[j].GrantedAt)
	})
	return out, nil
}

// normalizeScopes deduplicates and sorts a scope slice so the stored
// representation is canonical regardless of caller order.
func normalizeScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

var _ core.ConsentStore = (*MemoryConsentStore)(nil)
