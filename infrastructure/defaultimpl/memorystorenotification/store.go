// Package memorystorenotification provides bounded, concurrency-safe inbox
// and preference stores for single-process deployments and tests.
package memorystorenotification

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	defaultSubjectCap = 1000
	defaultReadTTL    = 90 * 24 * time.Hour
)

// Store implements both core.NotificationStore and its secure paging extensions.
type Store struct {
	mu      sync.RWMutex
	events  map[string]*core.NotificationEvent
	byUser  map[string][]string
	prefs   map[string]core.NotificationPreference
	cap     int
	readTTL time.Duration
	now     func() time.Time
}

func New() *Store {
	return &Store{events: map[string]*core.NotificationEvent{}, byUser: map[string][]string{},
		prefs: map[string]core.NotificationPreference{}, cap: defaultSubjectCap, readTTL: defaultReadTTL, now: time.Now}
}

func (s *Store) Create(_ context.Context, event *core.NotificationEvent) error {
	if event == nil || event.SubjectID == "" {
		return core.ErrNotificationInvalid
	}
	copyEvent := cloneEvent(event)
	if copyEvent.ID == "" {
		copyEvent.ID = newID()
	}
	if copyEvent.CreatedAt.IsZero() {
		copyEvent.CreatedAt = s.now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(copyEvent.SubjectID)
	s.events[copyEvent.ID] = copyEvent
	s.byUser[copyEvent.SubjectID] = append([]string{copyEvent.ID}, s.byUser[copyEvent.SubjectID]...)
	s.enforceCapLocked(copyEvent.SubjectID)
	event.ID, event.CreatedAt = copyEvent.ID, copyEvent.CreatedAt
	return nil
}

func (s *Store) ListBySubject(_ context.Context, subjectID string, since time.Time, limit int) ([]*core.NotificationEvent, error) {
	return s.list(subjectID, "", false, since, limit)
}

func (s *Store) ListPage(_ context.Context, subjectID, beforeID string, unreadOnly bool, limit int) ([]*core.NotificationEvent, bool, error) {
	items, err := s.list(subjectID, beforeID, unreadOnly, time.Time{}, limit+1)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

func (s *Store) list(subjectID, beforeID string, unreadOnly bool, since time.Time, limit int) ([]*core.NotificationEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, started := s.byUser[subjectID], beforeID == ""
	out := make([]*core.NotificationEvent, 0, limit)
	for _, id := range ids {
		if !started {
			started = id == beforeID
			continue
		}
		e := s.events[id]
		if e == nil || (!since.IsZero() && e.CreatedAt.Before(since)) || (unreadOnly && e.ReadAt != nil) {
			continue
		}
		out = append(out, cloneEvent(e))
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *Store) MarkRead(ctx context.Context, id string) error {
	return s.MarkReadForSubject(ctx, "", id)
}

func (s *Store) MarkReadForSubject(_ context.Context, subjectID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.events[id]
	if e == nil || (subjectID != "" && e.SubjectID != subjectID) {
		return core.ErrNotificationNotFound
	}
	if e.ReadAt == nil {
		now := s.now().UTC()
		e.ReadAt = &now
	}
	return nil
}

func (s *Store) UnreadCount(_ context.Context, subjectID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, id := range s.byUser[subjectID] {
		if e := s.events[id]; e != nil && e.ReadAt == nil {
			count++
		}
	}
	return count, nil
}

func (s *Store) DeleteForSubject(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.byUser[subjectID] {
		delete(s.events, id)
	}
	delete(s.byUser, subjectID)
	for key, p := range s.prefs {
		if p.SubjectID == subjectID {
			delete(s.prefs, key)
		}
	}
	return nil
}

func (s *Store) ListPreferences(_ context.Context, subjectID string) ([]core.NotificationPreference, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]core.NotificationPreference, 0)
	for _, p := range s.prefs {
		if p.SubjectID == subjectID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Channel < out[j].Channel
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// PreferenceStore returns a view implementing core.NotificationPreferenceStore.
func (s *Store) PreferenceStore() core.NotificationPreferenceStore { return preferenceView{s} }

type preferenceView struct{ store *Store }

func (v preferenceView) ListBySubject(ctx context.Context, subjectID string) ([]core.NotificationPreference, error) {
	return v.store.ListPreferences(ctx, subjectID)
}

func (v preferenceView) Put(_ context.Context, p core.NotificationPreference) error {
	if p.SubjectID == "" || p.Type == "" || p.Channel == "" {
		return core.ErrNotificationInvalid
	}
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	v.store.prefs[prefKey(p)] = p
	return nil
}

func (v preferenceView) DeleteForSubject(ctx context.Context, subjectID string) error {
	_ = ctx
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	for key, p := range v.store.prefs {
		if p.SubjectID == subjectID {
			delete(v.store.prefs, key)
		}
	}
	return nil
}

func (s *Store) SendNotification(ctx context.Context, event *core.NotificationEvent) error {
	return s.Create(ctx, event)
}

func (s *Store) pruneLocked(subjectID string) {
	cutoff := s.now().Add(-s.readTTL)
	kept := s.byUser[subjectID][:0]
	for _, id := range s.byUser[subjectID] {
		e := s.events[id]
		if e != nil && e.ReadAt != nil && e.ReadAt.Before(cutoff) {
			delete(s.events, id)
			continue
		}
		kept = append(kept, id)
	}
	s.byUser[subjectID] = kept
}

func (s *Store) enforceCapLocked(subjectID string) {
	ids := s.byUser[subjectID]
	for len(ids) > s.cap {
		delete(s.events, ids[len(ids)-1])
		ids = ids[:len(ids)-1]
	}
	s.byUser[subjectID] = ids
}

func cloneEvent(in *core.NotificationEvent) *core.NotificationEvent {
	if in == nil {
		return nil
	}
	out := *in
	if in.ReadAt != nil {
		read := *in.ReadAt
		out.ReadAt = &read
	}
	return &out
}

func prefKey(p core.NotificationPreference) string {
	return p.SubjectID + "\x00" + string(p.Type) + "\x00" + string(p.Channel)
}

func newID() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	return base64.RawURLEncoding.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
}
