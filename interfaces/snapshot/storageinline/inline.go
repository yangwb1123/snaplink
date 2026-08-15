// Package inline is an in-memory snapshot.Storage. Useful for tests,
// CLI pipes (export → process → restore in the same binary), and as the
// dummy backend a Pipeline can use when the caller only wants the
// SealedEnvelope bytes back without a side-effecting write.
package inline

import (
	"context"
	"sort"
	"sync"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Storage holds snapshots in a process-local map. Safe for concurrent use.
type Storage struct {
	mu    sync.RWMutex
	items map[string][]byte
}

// New constructs an empty Storage.
func New() *Storage {
	return &Storage{items: make(map[string][]byte)}
}

// Bytes returns a copy of the data stored under name, or nil + false
// when name is missing. Avoids forcing callers to wrap a context just
// to peek at in-memory state.
func (s *Storage) Bytes(name string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.items[name]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(d))
	copy(out, d)
	return out, true
}

// Len reports how many snapshots are currently stored.
func (s *Storage) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

func (s *Storage) Put(_ context.Context, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.items[name] = cp
	return nil
}

func (s *Storage) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.items[name]
	if !ok {
		return nil, snapshot.ErrSnapshotNotFound
	}
	out := make([]byte, len(d))
	copy(out, d)
	return out, nil
}

func (s *Storage) List(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.items))
	for k := range s.items {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Storage) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, name)
	return nil
}

// ListPage implements snapshot.PaginatedSnapshotStorage: keyset pagination
// over a snapshot of names sorted ascending (the fixed sort both the
// fallback path and this page share). totalHint is the exact row count.
func (s *Storage) ListPage(_ context.Context, q core.PageQuery) ([]string, []byte, int, error) {
	s.mu.RLock()
	names := make([]string, 0, len(s.items))
	for name := range s.items {
		names = append(names, name)
	}
	s.mu.RUnlock()
	keyID := func(n string) (string, string) { return n, n }
	core.SortKeyset(names, q.Desc, keyID)
	return core.KeysetSlice(names, q, keyID)
}

// Compile-time interface checks.
var (
	_ snapshot.Storage                  = (*Storage)(nil)
	_ snapshot.PaginatedSnapshotStorage = (*Storage)(nil)
)
