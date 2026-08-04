package rebac

import (
	"context"
	"sync"
)

// MemoryStore is a process-local RelationTupleStore backed by a plain tuple
// set plus one secondary index. Suitable for dev, single-node deployments,
// and as the reference impl a database-backed Store can be modeled on —
// same role domains/permissions.MemoryProvider and conditionalaccess's
// in-memory Store play for their respective SPIs.
//
// Data model:
//
//	tuples[key]                 = Tuple   (key = Object+Relation+Subject,
//	                               the canonical set — Write/Delete dedup)
//	byObjectRelation[Object+Relation] = []key
//	                               (Engine.Check's hot path: every Check call
//	                               reads by a concrete Object+Relation pair)
//
// Read with BOTH Object and Relation set (Engine.Check's shape) is an O(1)
// index lookup plus O(k) filter over that pair's tuples. Any sparser filter
// (e.g. Subject-only, for an admin "what can alice reach" query) falls back
// to an O(n) scan of the full tuple set — acceptable for a reference/dev
// store; a production-scale backend would add a by-subject index too (see
// package doc's "tuple-to-userset caching" deferral).
type MemoryStore struct {
	mu               sync.RWMutex
	tuples           map[tupleKey]Tuple
	byObjectRelation map[objectRelationKey][]tupleKey
}

type tupleKey string
type objectRelationKey string

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tuples:           make(map[tupleKey]Tuple),
		byObjectRelation: make(map[objectRelationKey][]tupleKey),
	}
}

func keyOf(t Tuple) tupleKey {
	return tupleKey(t.Object + "\x00" + t.Relation + "\x00" + t.Subject)
}

func objectRelationKeyOf(object, relation string) objectRelationKey {
	return objectRelationKey(object + "\x00" + relation)
}

// Write upserts t, after Validate. Idempotent: re-writing an already-stored
// tuple is a no-op (the index is only appended to on first insert).
func (m *MemoryStore) Write(_ context.Context, t Tuple) error {
	if err := t.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeLocked(t)
	return nil
}

func (m *MemoryStore) writeLocked(t Tuple) {
	k := keyOf(t)
	if _, exists := m.tuples[k]; exists {
		return
	}
	m.tuples[k] = t
	orKey := objectRelationKeyOf(t.Object, t.Relation)
	m.byObjectRelation[orKey] = append(m.byObjectRelation[orKey], k)
}

// Delete removes t. Idempotent: deleting an absent tuple is a no-op.
func (m *MemoryStore) Delete(_ context.Context, t Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLocked(t)
	return nil
}

func (m *MemoryStore) deleteLocked(t Tuple) {
	k := keyOf(t)
	if _, exists := m.tuples[k]; !exists {
		return
	}
	delete(m.tuples, k)
	orKey := objectRelationKeyOf(t.Object, t.Relation)
	m.byObjectRelation[orKey] = deleteKey(m.byObjectRelation[orKey], k)
}

// ApplyBatch validates the whole request before taking the mutation lock, then
// applies it as one critical section. Since the in-memory writes cannot fail
// after validation, readers observe either the old or the complete new set.
func (m *MemoryStore) ApplyBatch(_ context.Context, writes, deletes []Tuple) error {
	for _, t := range writes {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	for _, t := range deletes {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range writes {
		m.writeLocked(t)
	}
	for _, t := range deletes {
		m.deleteLocked(t)
	}
	return nil
}

// Read returns every tuple matching filter. See the type doc for the
// indexed-vs-scan performance split.
func (m *MemoryStore) Read(_ context.Context, filter TupleFilter) ([]Tuple, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if filter.Object != "" && filter.Relation != "" {
		return m.readIndexed(filter), nil
	}
	return m.readScan(filter), nil
}

// readIndexed serves the Object+Relation-set shape (Engine.Check's hot
// path) off byObjectRelation, filtering the (typically tiny) hit list by any
// remaining Subject constraint. Caller holds m.mu (at least RLock).
func (m *MemoryStore) readIndexed(filter TupleFilter) []Tuple {
	keys := m.byObjectRelation[objectRelationKeyOf(filter.Object, filter.Relation)]
	out := make([]Tuple, 0, len(keys))
	for _, k := range keys {
		if t, ok := m.tuples[k]; ok && filter.matches(t) {
			out = append(out, t)
		}
	}
	return out
}

// readScan serves a sparser filter (no Object, no Relation, or only one of
// the two) by linear scan — the admin/debug reverse-query path.
func (m *MemoryStore) readScan(filter TupleFilter) []Tuple {
	out := make([]Tuple, 0)
	for _, t := range m.tuples {
		if filter.matches(t) {
			out = append(out, t)
		}
	}
	return out
}

// deleteKey removes the first occurrence of target from keys, preserving
// order. Safe to mutate the backing array in place: every caller holds
// m.mu's write lock, and Read (under the read lock) always copies elements
// out of byObjectRelation's slices rather than returning them directly, so
// no other goroutine can be mid-iteration over keys.
func deleteKey(keys []tupleKey, target tupleKey) []tupleKey {
	for i, k := range keys {
		if k == target {
			return append(keys[:i], keys[i+1:]...)
		}
	}
	return keys
}

// Compile-time proof that *MemoryStore satisfies RelationTupleStore.
var _ RelationTupleStore = (*MemoryStore)(nil)
