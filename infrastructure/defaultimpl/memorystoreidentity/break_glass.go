package memorystoreidentity

import (
	"context"
	"sort"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryBreakGlassStore is an in-process, non-persistent break-glass admin
// session store. Suitable for single-replica dev and test.
type MemoryBreakGlassStore struct {
	mu       sync.RWMutex
	sessions map[string]core.AdminSession
}

// NewMemoryBreakGlassStore returns an empty MemoryBreakGlassStore.
func NewMemoryBreakGlassStore() *MemoryBreakGlassStore {
	return &MemoryBreakGlassStore{sessions: make(map[string]core.AdminSession)}
}

// lazyExpireAdminSession folds wall-clock expiry into the reported status so
// no reader ever observes a stale-active grant between sweeper passes. Pure:
// operates on the copy, never mutates the stored record (the sweeper owns the
// authoritative transition + its cascade).
func lazyExpireAdminSession(a core.AdminSession) core.AdminSession {
	if (a.Status == core.AdminSessionPending || a.Status == core.AdminSessionActive) && a.IsExpired() {
		a.Status = core.AdminSessionExpired
	}
	return a
}

func (s *MemoryBreakGlassStore) Create(_ context.Context, a core.AdminSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[a.ID] = a
	return nil
}

func (s *MemoryBreakGlassStore) Get(_ context.Context, id string) (core.AdminSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.sessions[id]
	if !ok {
		return core.AdminSession{}, core.ErrAdminSessionNotFound
	}
	return lazyExpireAdminSession(a), nil
}

func (s *MemoryBreakGlassStore) List(_ context.Context) ([]core.AdminSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]core.AdminSession, 0, len(s.sessions))
	for _, a := range s.sessions {
		a = lazyExpireAdminSession(a)
		if a.Status == core.AdminSessionPending || a.Status == core.AdminSessionActive {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryBreakGlassStore) Approve(_ context.Context, id, approverID string, sessionIDs []string) (core.AdminSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.sessions[id]
	if !ok {
		return core.AdminSession{}, core.ErrAdminSessionNotFound
	}
	if lazyExpireAdminSession(a).Status != core.AdminSessionPending {
		return core.AdminSession{}, core.ErrAdminSessionNotPending
	}
	// The self-approval rejection lives here (not only in the handler) so
	// the two-person rule holds for every caller of the SPI.
	if approverID == "" || approverID == a.AdminUserID {
		return core.AdminSession{}, core.ErrAdminSessionSelfApproval
	}
	a.Status = core.AdminSessionActive
	a.ApprovedBy = approverID
	a.SessionIDs = append(a.SessionIDs, sessionIDs...)
	s.sessions[id] = a
	return a, nil
}

func (s *MemoryBreakGlassStore) Revoke(_ context.Context, id string) (core.AdminSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.sessions[id]
	if !ok {
		return core.AdminSession{}, core.ErrAdminSessionNotFound
	}
	a.Status = core.AdminSessionRevoked
	s.sessions[id] = a
	return a, nil
}

func (s *MemoryBreakGlassStore) DeleteExpired(_ context.Context) ([]core.AdminSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []core.AdminSession
	for id, a := range s.sessions {
		if !a.IsExpired() {
			continue
		}
		delete(s.sessions, id)
		// Only grants that were still pending/active need the caller's
		// cascade + expiry audit; a revoked grant's cascade already ran.
		if a.Status == core.AdminSessionPending || a.Status == core.AdminSessionActive {
			a.Status = core.AdminSessionExpired
			out = append(out, a)
		}
	}
	return out, nil
}

var _ core.BreakGlassStore = (*MemoryBreakGlassStore)(nil)
