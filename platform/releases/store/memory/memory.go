// Package memory is an in-process releases.ReleaseStore. State is
// lost on restart — fine for tests and ephemeral demos, NOT for real
// deployments where the current pointer must survive a reboot.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/snaplink/sso/platform/releases"
)

// Store holds Releases in a process-local map plus a "current" pointer.
// Safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	items   map[string]*releases.Release
	current string
}

// New constructs an empty Store.
func New() *Store {
	return &Store{items: make(map[string]*releases.Release)}
}

func (s *Store) Register(_ context.Context, r *releases.Release) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[r.ID]; exists {
		return releases.ErrReleaseExists
	}
	cp := *r
	s.items[r.ID] = &cp
	return nil
}

func (s *Store) Get(_ context.Context, id string) (*releases.Release, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.items[id]
	if !ok {
		return nil, releases.ErrReleaseNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *Store) List(_ context.Context) ([]*releases.Release, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*releases.Release, 0, len(s.items))
	for _, r := range s.items {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	if s.current == id {
		s.current = ""
	}
	return nil
}

func (s *Store) SetCurrent(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return releases.ErrReleaseNotFound
	}
	s.current = id
	return nil
}

func (s *Store) Current(_ context.Context) (*releases.Release, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == "" {
		return nil, releases.ErrNoCurrent
	}
	r, ok := s.items[s.current]
	if !ok {
		return nil, releases.ErrNoCurrent
	}
	cp := *r
	return &cp, nil
}

func (s *Store) ClearCurrent(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = ""
	return nil
}

// Compile-time interface check.
var _ releases.ReleaseStore = (*Store)(nil)
