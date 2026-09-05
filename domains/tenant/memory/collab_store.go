// ExternalUserStore/CollaborationStore below are the in-process reference
// implementations of [tenant.ExternalUserStore] and [tenant.CollaborationStore]
// (the cross-tenant B2B collaboration SPIs). Single-replica only — a
// multi-replica deployment wanting cluster-shared guest registrations/trust
// rows should back these interfaces with a durable store instead.
package memory

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// guestKey builds the (guestTenantID, externalSubjectID) composite key.
// NUL-separated: tenant/subject IDs are operator-controlled opaque strings
// that could otherwise collide across the join (e.g. tenant "a-b" + subject
// "c" vs tenant "a" + subject "b-c").
func guestKey(guestTenantID, externalSubjectID string) string {
	return guestTenantID + "\x00" + externalSubjectID
}

// ExternalUserStore is the in-memory [tenant.ExternalUserStore].
type ExternalUserStore struct {
	mu      sync.RWMutex
	records map[string]*tenant.GuestRecord
}

// NewExternalUserStore returns an empty store.
func NewExternalUserStore() *ExternalUserStore {
	return &ExternalUserStore{records: make(map[string]*tenant.GuestRecord)}
}

// Add implements [tenant.ExternalUserStore]. Stores a defensive copy so
// a caller mutating the passed-in GuestRecord afterward can't corrupt the
// store's view.
func (s *ExternalUserStore) Add(_ context.Context, g *tenant.GuestRecord) error {
	if err := g.Validate(); err != nil {
		return err
	}
	cp := cloneGuestRecord(g)
	s.mu.Lock()
	s.records[guestKey(g.GuestTenantID, g.ExternalSubjectID)] = cp
	s.mu.Unlock()
	return nil
}

// Remove implements [tenant.ExternalUserStore]. Idempotent.
func (s *ExternalUserStore) Remove(_ context.Context, guestTenantID, externalSubjectID string) error {
	s.mu.Lock()
	delete(s.records, guestKey(guestTenantID, externalSubjectID))
	s.mu.Unlock()
	return nil
}

// Get implements [tenant.ExternalUserStore].
func (s *ExternalUserStore) Get(_ context.Context, guestTenantID, externalSubjectID string) (*tenant.GuestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.records[guestKey(guestTenantID, externalSubjectID)]
	if !ok {
		return nil, tenant.ErrNoGuestRecord
	}
	return cloneGuestRecord(g), nil
}

// ListByGuestTenant implements [tenant.ExternalUserStore]. Order is
// unspecified.
func (s *ExternalUserStore) ListByGuestTenant(_ context.Context, guestTenantID string) ([]*tenant.GuestRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tenant.GuestRecord, 0, len(s.records))
	for _, g := range s.records {
		if g.GuestTenantID == guestTenantID {
			out = append(out, cloneGuestRecord(g))
		}
	}
	return out, nil
}

var _ tenant.ExternalUserStore = (*ExternalUserStore)(nil)

func cloneGuestRecord(g *tenant.GuestRecord) *tenant.GuestRecord {
	cp := *g
	cp.Roles = slices.Clone(g.Roles)
	cp.Attributes = maps.Clone(g.Attributes)
	return &cp
}

// collabKey builds the (guestTenantID, homeTenantID) composite key.
func collabKey(guestTenantID, homeTenantID string) string {
	return guestTenantID + "\x00" + homeTenantID
}

// CollaborationStore is the in-memory [tenant.CollaborationStore].
type CollaborationStore struct {
	mu    sync.RWMutex
	trust map[string]*tenant.TenantCollaboration
}

// NewCollaborationStore returns an empty store — NO tenant trusts any other
// tenant until Put is called (fail-closed default, AGENTS.md §3).
func NewCollaborationStore() *CollaborationStore {
	return &CollaborationStore{trust: make(map[string]*tenant.TenantCollaboration)}
}

// Put implements [tenant.CollaborationStore].
func (s *CollaborationStore) Put(_ context.Context, c *tenant.TenantCollaboration) error {
	if err := c.Validate(); err != nil {
		return err
	}
	cp := *c
	s.mu.Lock()
	s.trust[collabKey(c.GuestTenantID, c.HomeTenantID)] = &cp
	s.mu.Unlock()
	return nil
}

// Remove implements [tenant.CollaborationStore]. Idempotent.
func (s *CollaborationStore) Remove(_ context.Context, guestTenantID, homeTenantID string) error {
	s.mu.Lock()
	delete(s.trust, collabKey(guestTenantID, homeTenantID))
	s.mu.Unlock()
	return nil
}

// IsTrusted implements [tenant.CollaborationStore]. Never returns an
// error — the in-memory matcher is pure and can't fail; still typed to
// return one so callers wired against the interface behave identically
// against a future I/O-backed Store.
func (s *CollaborationStore) IsTrusted(_ context.Context, guestTenantID, homeTenantID string) (bool, error) {
	s.mu.RLock()
	_, ok := s.trust[collabKey(guestTenantID, homeTenantID)]
	s.mu.RUnlock()
	return ok, nil
}

// ListByGuestTenant implements [tenant.CollaborationStore]. Order is
// unspecified.
func (s *CollaborationStore) ListByGuestTenant(_ context.Context, guestTenantID string) ([]*tenant.TenantCollaboration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tenant.TenantCollaboration, 0, len(s.trust))
	for _, c := range s.trust {
		if c.GuestTenantID == guestTenantID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ tenant.CollaborationStore = (*CollaborationStore)(nil)
