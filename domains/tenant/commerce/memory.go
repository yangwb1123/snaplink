package commerce

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"time"
)

// MemoryStore is the reference implementation for embedded deployments and
// tests. It has the same atomicity and idempotency semantics as durable stores,
// but intentionally offers no restart durability or cross-replica sharing.
type MemoryStore struct {
	mu                  sync.RWMutex
	now                 func() time.Time
	plans               map[planKey]*Plan
	subscriptions       map[string]*Subscription
	tenantSubscriptions map[string][]string
	currentSubscription map[string]string
	renewalClaims       map[string]renewalLease
	entitlements        map[string]*EntitlementSnapshot
	wallets             map[walletKey]*Wallet
	entries             map[walletKey][]*LedgerEntry
	ledgerKeys          map[string]*LedgerEntry
	ledgerByID          map[string]*LedgerEntry
	paymentOrders       map[string]*PaymentOrder
	paymentOrderKeys    map[string]string
	paymentEvents       map[string]*PaymentEvent
	orderPaymentEvents  map[string][]string
	outbox              map[string]*OutboxEvent
	outboxKeys          map[string]string
	quotaOutbox         map[string]*OutboxEvent
}

type planKey struct {
	id      string
	version uint64
}

type walletKey struct {
	tenantID string
	currency string
}

type renewalLease struct {
	owner string
	until time.Time
}

type MemoryStoreOption func(*MemoryStore)

// WithMemoryStoreClock supplies the trusted lease clock used by the reference
// store. It exists for deterministic conformance tests; production callers
// normally use the default wall clock.
func WithMemoryStoreClock(now func() time.Time) MemoryStoreOption {
	return func(store *MemoryStore) {
		if now != nil {
			store.now = now
		}
	}
}

func NewMemoryStore(options ...MemoryStoreOption) *MemoryStore {
	store := &MemoryStore{
		now:   time.Now,
		plans: make(map[planKey]*Plan), subscriptions: make(map[string]*Subscription),
		tenantSubscriptions: make(map[string][]string), currentSubscription: make(map[string]string),
		renewalClaims: make(map[string]renewalLease),
		entitlements:  make(map[string]*EntitlementSnapshot), wallets: make(map[walletKey]*Wallet),
		entries: make(map[walletKey][]*LedgerEntry), ledgerKeys: make(map[string]*LedgerEntry),
		ledgerByID:    make(map[string]*LedgerEntry),
		paymentOrders: make(map[string]*PaymentOrder), paymentOrderKeys: make(map[string]string),
		paymentEvents: make(map[string]*PaymentEvent), orderPaymentEvents: make(map[string][]string),
		outbox: make(map[string]*OutboxEvent), outboxKeys: make(map[string]string),
		quotaOutbox: make(map[string]*OutboxEvent),
	}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store
}

func (s *MemoryStore) PutPlan(ctx context.Context, plan *Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	key := planKey{id: plan.ID, version: plan.Version}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.plans[key]; ok {
		if reflect.DeepEqual(current, plan) {
			return nil
		}
		return ErrPlanConflict
	}
	s.plans[key] = clonePlan(plan)
	return nil
}

func (s *MemoryStore) GetPlan(ctx context.Context, id string, version uint64) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, ok := s.plans[planKey{id: id, version: version}]
	if !ok {
		return nil, ErrPlanNotFound
	}
	return clonePlan(plan), nil
}

func (s *MemoryStore) ListPlans(ctx context.Context) ([]*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	plans := make([]*Plan, 0, len(s.plans))
	for _, plan := range s.plans {
		plans = append(plans, clonePlan(plan))
	}
	sort.Slice(plans, func(left, right int) bool {
		if plans[left].ID == plans[right].ID {
			return plans[left].Version < plans[right].Version
		}
		return plans[left].ID < plans[right].ID
	})
	return plans, nil
}

func commerceKey(parts ...string) string {
	result := ""
	for _, part := range parts {
		result += "\x00" + part
	}
	return result
}

var _ Store = (*MemoryStore)(nil)
