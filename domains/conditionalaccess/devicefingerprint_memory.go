package conditionalaccess

import (
	"context"
	"sync"
)

// MemoryDeviceFingerprint is the in-process DeviceFingerprint. Like
// MemoryStore, state is lost on restart — fine for tests/dev and for a
// single-replica deployment that re-learns posture quickly from a fast
// out-of-band source (an MDM webhook that re-syncs on boot).
type MemoryDeviceFingerprint struct {
	mu       sync.RWMutex
	postures map[string]DevicePosture
}

var _ DeviceFingerprint = (*MemoryDeviceFingerprint)(nil)

// NewMemoryDeviceFingerprint returns an empty in-process device-posture
// store.
func NewMemoryDeviceFingerprint() *MemoryDeviceFingerprint {
	return &MemoryDeviceFingerprint{postures: make(map[string]DevicePosture)}
}

// Lookup returns the recorded posture; ok=false when fingerprint was never
// Recorded (never an error — Memory has no external data source to fail).
// A blank fingerprint always misses (nothing to key on).
func (m *MemoryDeviceFingerprint) Lookup(_ context.Context, fingerprint string) (DevicePosture, bool, error) {
	if fingerprint == "" {
		return PostureUnknown, false, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.postures[fingerprint]
	return p, ok, nil
}

// Record upserts the posture for fingerprint. A blank fingerprint is a no-op.
func (m *MemoryDeviceFingerprint) Record(_ context.Context, fingerprint string, posture DevicePosture) error {
	if fingerprint == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.postures[fingerprint] = posture
	return nil
}
