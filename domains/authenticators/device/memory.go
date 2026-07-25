package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-process Store backed by a map.
type MemoryStore struct {
	mu          sync.RWMutex
	byID        map[string]*Device
	byFingerprint map[string]string // "userID\x00fingerprint" → deviceID
}

// NewMemoryStore returns an empty in-memory device store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:          make(map[string]*Device),
		byFingerprint: make(map[string]string),
	}
}

func (m *MemoryStore) Upsert(_ context.Context, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if fingerprint already exists for this user.
	fpKey := d.UserID + "\x00" + d.Fingerprint
	if existingID, ok := m.byFingerprint[fpKey]; ok {
		// Update existing device. Atomically increment login count.
		existing, ok := m.byID[existingID]
		if ok {
			cp := d.Clone()
			cp.ID = existing.ID
			cp.FirstSeenAt = existing.FirstSeenAt
			cp.LastSeenAt = time.Now()
			// Preserve and atomically increment login count on update path
			// (the caller always sets LoginCount=1; we override with existing+1).
			cp.LoginCount = existing.LoginCount + 1
			m.byID[cp.ID] = cp
			// Set ID on the input so the caller can read it after Upsert.
			d.ID = existing.ID
			return nil
		}
	}

	// New device.
	if d.ID == "" {
		d.ID = generateID()
	}
	cp := d.Clone()
	now := time.Now()
	if cp.FirstSeenAt.IsZero() {
		cp.FirstSeenAt = now
	}
	cp.LastSeenAt = now
	m.byID[cp.ID] = cp
	m.byFingerprint[fpKey] = cp.ID
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id string) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d, ok := m.byID[id]
	if !ok {
		return nil, ErrNoSuchDevice
	}
	return d.Clone(), nil
}

func (m *MemoryStore) GetByFingerprint(_ context.Context, userID, fingerprint string) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fpKey := userID + "\x00" + fingerprint
	deviceID, ok := m.byFingerprint[fpKey]
	if !ok {
		return nil, ErrNoSuchDevice
	}
	d, ok := m.byID[deviceID]
	if !ok {
		return nil, ErrNoSuchDevice
	}
	return d.Clone(), nil
}

func (m *MemoryStore) ListAll(_ context.Context) ([]*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Device, 0, len(m.byID))
	for _, d := range m.byID {
		out = append(out, d.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func (m *MemoryStore) ListByUser(_ context.Context, userID string) ([]*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*Device
	for _, d := range m.byID {
		if d.UserID == userID {
			out = append(out, d.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	if out == nil {
		out = []*Device{}
	}
	return out, nil
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.byID[id]
	if !ok {
		return nil
	}
	delete(m.byID, id)
	fpKey := d.UserID + "\x00" + d.Fingerprint
	delete(m.byFingerprint, fpKey)
	return nil
}

func (m *MemoryStore) DeleteByUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, d := range m.byID {
		if d.UserID == userID {
			delete(m.byID, id)
			fpKey := userID + "\x00" + d.Fingerprint
			delete(m.byFingerprint, fpKey)
		}
	}
	return nil
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "dev_" + hex.EncodeToString(b)
}

// Compile-time interface check.
var _ Store = (*MemoryStore)(nil)
