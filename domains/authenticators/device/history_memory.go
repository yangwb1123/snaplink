package device

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// MemoryHistoryStore is an in-memory login history store.
type MemoryHistoryStore struct {
	mu   sync.RWMutex
	recs []*LoginRecord
}

func NewMemoryHistoryStore() *MemoryHistoryStore {
	return &MemoryHistoryStore{}
}

func (s *MemoryHistoryStore) Record(r *LoginRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		r.ID = "lr_" + hex.EncodeToString(b)
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	s.recs = append(s.recs, r)
	return nil
}

func (s *MemoryHistoryStore) RecentByUser(userID string, limit int) ([]*LoginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*LoginRecord
	for _, r := range s.recs {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []*LoginRecord{}
	}
	return out, nil
}

func (s *MemoryHistoryStore) RecentByDevice(deviceID string, limit int) ([]*LoginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*LoginRecord
	for _, r := range s.recs {
		if r.DeviceID == deviceID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []*LoginRecord{}
	}
	return out, nil
}
