package webhook

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemorySubscriptionStore is the process-local, non-durable
// SubscriptionStore reference implementation (AGENTS.md "no mocks" — every
// SDK concern is an interface plus a real memory impl). A restart loses
// every registered subscription; pair with a durable backend for
// production if that matters to the deployment.
type MemorySubscriptionStore struct {
	mu   sync.RWMutex
	byID map[string]EventSubscription
}

var _ SubscriptionStore = (*MemorySubscriptionStore)(nil)

// NewMemorySubscriptionStore returns an empty store — the default,
// zero-subscription state that produces zero webhook traffic.
func NewMemorySubscriptionStore() *MemorySubscriptionStore {
	return &MemorySubscriptionStore{byID: make(map[string]EventSubscription)}
}

// Create validates sub, assigns ID/CreatedAt/UpdatedAt (any caller-supplied
// ID is ignored — every subscription is server-minted), and stores it.
func (m *MemorySubscriptionStore) Create(_ context.Context, sub EventSubscription) (EventSubscription, error) {
	if err := sub.Validate(); err != nil {
		return EventSubscription{}, err
	}
	now := time.Now().UTC()
	sub.ID = newID()
	sub.CreatedAt = now
	sub.UpdatedAt = now

	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[sub.ID] = sub
	return sub, nil
}

// Get returns the subscription by id, or ErrSubscriptionNotFound.
func (m *MemorySubscriptionStore) Get(_ context.Context, id string) (EventSubscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sub, ok := m.byID[id]
	if !ok {
		return EventSubscription{}, ErrSubscriptionNotFound
	}
	return sub, nil
}

// List returns every registered subscription (enabled and disabled alike —
// callers that only want live delivery targets filter via Matches),
// ordered oldest-first for stable pagination-free display.
func (m *MemorySubscriptionStore) List(_ context.Context) ([]EventSubscription, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EventSubscription, 0, len(m.byID))
	for _, sub := range m.byID {
		out = append(out, sub)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Delete removes the subscription. Idempotent — deleting an unknown id
// returns nil, matching platform/netpolicy.Store's discipline so a
// reconciliation loop never churns on already-clean state.
func (m *MemorySubscriptionStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}
