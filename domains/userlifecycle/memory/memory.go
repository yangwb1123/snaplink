// Package memory is the in-process userlifecycle.Store plus a companion
// last-active tracker. State is lost on restart — fine for tests and small
// embedded deployments; a multi-replica production deploy should swap in a
// SQL-backed peer implementing the same userlifecycle.Store contract.
package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
)

// Store holds per-user lifecycle records in a process-local map. Safe for
// concurrent use.
type Store struct {
	mu      sync.RWMutex
	records map[string]userlifecycle.Record
	now     func() time.Time
}

// New constructs an empty Store.
func New() *Store {
	return &Store{
		records: make(map[string]userlifecycle.Record),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Get returns userID's record, or {State: DefaultState} with empty history when
// none is stored (a user with no explicit lifecycle is implicitly active).
func (s *Store) Get(_ context.Context, userID string) (userlifecycle.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[userID]
	if !ok {
		return userlifecycle.Record{UserID: userID, State: userlifecycle.DefaultState}, nil
	}
	return cloneRecord(rec), nil
}

// GetState returns only the current state for authentication and sweep paths.
func (s *Store) GetState(_ context.Context, userID string) (userlifecycle.State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[userID]
	if !ok {
		return userlifecycle.DefaultState, nil
	}
	return rec.State, nil
}

// Append applies t under the store lock, enforcing optimistic concurrency: a
// seed (t.From == StateNone) requires no existing record; any other transition
// requires t.From to equal the account's live state (DefaultState when no
// record exists yet). A mismatch returns userlifecycle.ErrStateConflict.
func (s *Store) Append(_ context.Context, userID string, t userlifecycle.Transition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, exists := s.records[userID]
	if t.From == userlifecycle.StateNone {
		if exists {
			return userlifecycle.ErrStateConflict
		}
		rec = userlifecycle.Record{UserID: userID}
	} else {
		current := userlifecycle.DefaultState
		if exists {
			current = rec.State
		}
		if t.From != current {
			return userlifecycle.ErrStateConflict
		}
		rec.UserID = userID
	}
	rec.State = t.To
	rec.History = append(rec.History, t)
	rec.UpdatedAt = s.now()
	s.records[userID] = rec
	return nil
}

// ListByState returns the ids of users whose current stored state is state.
// Users with no record (implicitly DefaultState) are not returned.
func (s *Store) ListByState(_ context.Context, state userlifecycle.State) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, rec := range s.records {
		if rec.State == state {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out, nil
}

func cloneRecord(rec userlifecycle.Record) userlifecycle.Record {
	rec.History = slices.Clone(rec.History)
	return rec
}

var _ userlifecycle.StateReader = (*Store)(nil)

// ActivityTracker is an in-process userlifecycle.LastActiveSource that records
// an explicit "last active" instant per user — the precise, session-lifetime-
// independent alternative to deriving activity from live sessions. Wire it into
// the login path (call Touch on a successful authentication) so dormancy
// detection sees real activity even after every session has expired. Safe for
// concurrent use.
type ActivityTracker struct {
	mu   sync.RWMutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewActivityTracker constructs an empty tracker.
func NewActivityTracker() *ActivityTracker {
	return &ActivityTracker{
		seen: make(map[string]time.Time),
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// Touch records that userID was active now. Call it on a successful login.
func (a *ActivityTracker) Touch(userID string) {
	a.TouchAt(userID, a.now())
}

// TouchAt records that userID was active at the given instant, advancing the
// stored value only when at is newer (so out-of-order calls never regress it).
func (a *ActivityTracker) TouchAt(userID string, at time.Time) {
	if userID == "" || at.IsZero() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if at.After(a.seen[userID]) {
		a.seen[userID] = at
	}
}

// LastActive returns the recorded last-active instant for userID, or the zero
// time when the user has never been seen (IsDormant treats zero as "unknown,
// do not deprovision").
func (a *ActivityTracker) LastActive(_ context.Context, userID string) (time.Time, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.seen[userID], nil
}
