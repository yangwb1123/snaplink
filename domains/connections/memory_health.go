package connections

import (
	"context"
	"errors"
)

// Health implements Store. Never a store-miss: an id with no recorded probe
// yet reads back DefaultConnectionHealth (status HealthUnknown), matching the
// sqlite backend's ON CONFLICT-free "no row" case.
func (m *MemoryStore) Health(_ context.Context, id string) (*ConnectionHealth, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.health[id]
	if !ok {
		return DefaultConnectionHealth(id), nil
	}
	cp := *h
	return &cp, nil
}

// RecordHealth implements Store.
func (m *MemoryStore) RecordHealth(_ context.Context, id string, h *ConnectionHealth) error {
	if h == nil {
		return errors.New("connections: health record required")
	}
	cp := *h
	cp.ConnectionID = id
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health[id] = &cp
	return nil
}
