// Package memory is the in-memory reference [identitylink.Store]. Suitable
// for single-node and dev; mirrors the copy-on-read discipline of the other
// domains/*/memory stores in this codebase (e.g. domains/tokenexchange/memory)
// — no external dependency, no mocks.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/identitylink"
)

// Store is the in-memory implementation of [identitylink.Store]. Safe for
// concurrent use. Revoked links are retained (Status flips to StatusRevoked)
// rather than deleted, so ListByUser/FindByProviderSubject history stays
// available for audit even though they only ever surface active links.
type Store struct {
	mu   sync.RWMutex
	byID map[string]identitylink.Identity
}

// New returns an empty Store.
func New() *Store {
	return &Store{byID: make(map[string]identitylink.Identity)}
}

// ListByUser implements [identitylink.Store].
func (s *Store) ListByUser(_ context.Context, userID string) ([]identitylink.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitylink.Identity, 0)
	for _, id := range s.byID {
		if id.UserID == userID && id.Status == identitylink.StatusActive {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LinkedAt.Before(out[j].LinkedAt) })
	return out, nil
}

// Link implements [identitylink.Store]. Idempotent for an already-active
// (userID, provider, subject) triple — see the interface doc.
func (s *Store) Link(_ context.Context, userID, provider, subject string) (identitylink.Identity, error) {
	if err := identitylink.ValidateLinkInput(userID, provider, subject); err != nil {
		return identitylink.Identity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.byID {
		if id.Provider == provider && id.Subject == subject && id.Status == identitylink.StatusActive {
			if id.UserID == userID {
				return id, nil
			}
			return identitylink.Identity{}, identitylink.ErrAccountConflict
		}
	}
	rec := identitylink.Identity{
		ID:       newLinkID(),
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
		Status:   identitylink.StatusActive,
		LinkedAt: time.Now().UTC(),
	}
	s.byID[rec.ID] = rec
	return rec, nil
}

// Unlink implements [identitylink.Store]. Ownership + active-status are
// checked together so a stale id, a foreign id, and an already-revoked id
// all collapse to the SAME ErrNotFound (oracle-safe).
func (s *Store) Unlink(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok || rec.UserID != userID || rec.Status != identitylink.StatusActive {
		return identitylink.ErrNotFound
	}
	rec.Status = identitylink.StatusRevoked
	rec.UnlinkedAt = time.Now().UTC()
	s.byID[id] = rec
	return nil
}

// FindByProviderSubject implements [identitylink.Store].
func (s *Store) FindByProviderSubject(_ context.Context, provider, subject string) (identitylink.Identity, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range s.byID {
		if id.Provider == provider && id.Subject == subject && id.Status == identitylink.StatusActive {
			return id, true, nil
		}
	}
	return identitylink.Identity{}, false, nil
}

// MergeUserLinks implements [identitylink.AtomicMerger]. The conflict is
// revalidated while holding the same lock used by Link and Unlink, making the
// winner selection and all losing-link reassignments one atomic operation.
func (s *Store) MergeUserLinks(_ context.Context, conflict identitylink.Conflict) error {
	if err := identitylink.ValidateConflict(conflict); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.conflictStillOwned(conflict) {
		return identitylink.ErrAccountConflict
	}
	for id, rec := range s.byID {
		if rec.UserID == conflict.IncomingUserID && rec.Status == identitylink.StatusActive {
			rec.UserID = conflict.ExistingUserID
			s.byID[id] = rec
		}
	}
	return nil
}

func (s *Store) conflictStillOwned(conflict identitylink.Conflict) bool {
	for _, rec := range s.byID {
		if rec.Provider == conflict.Provider &&
			rec.Subject == conflict.Subject &&
			rec.Status == identitylink.StatusActive {
			return rec.UserID == conflict.ExistingUserID
		}
	}
	return false
}

// newLinkID mints an opaque per-link handle. Not a security token (it is
// never used as a bearer credential) — random purely to avoid collisions and
// sequential enumeration of the admin-visible id.
func newLinkID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var _ identitylink.Store = (*Store)(nil)
var _ identitylink.AtomicMerger = (*Store)(nil)
