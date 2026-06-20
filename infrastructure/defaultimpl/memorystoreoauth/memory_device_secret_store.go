package memorystoreoauth

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryDeviceSecretStore is an in-memory core.DeviceSecretStore for the
// OpenID Connect Native SSO flow. Single-process only; multi-replica needs the
// sqlite peer. Consume is destructive (single-use-on-exchange).
type MemoryDeviceSecretStore struct {
	mu      sync.Mutex
	secrets map[string]*core.DeviceSecret
}

// NewMemoryDeviceSecretStore returns an empty store.
func NewMemoryDeviceSecretStore() *MemoryDeviceSecretStore {
	return &MemoryDeviceSecretStore{secrets: make(map[string]*core.DeviceSecret)}
}

// Issue stores a copy of the binding keyed by its secret.
func (m *MemoryDeviceSecretStore) Issue(_ context.Context, ds *core.DeviceSecret) error {
	cp := *ds
	m.mu.Lock()
	m.secrets[ds.Secret] = &cp
	m.mu.Unlock()
	return nil
}

// Consume atomically deletes and returns the binding. Missing or expired
// entries return core.ErrDeviceSecretNotFound (expired rows are deleted).
func (m *MemoryDeviceSecretStore) Consume(_ context.Context, secret string) (*core.DeviceSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, ok := m.secrets[secret]
	if !ok {
		return nil, core.ErrDeviceSecretNotFound
	}
	delete(m.secrets, secret)
	if ds.IsExpired() {
		return nil, core.ErrDeviceSecretNotFound
	}
	return ds, nil
}

// RevokeBySubject deletes every binding for subject (admin lockout of a lost or
// compromised device's Native SSO access). Returns the count removed.
func (m *MemoryDeviceSecretStore) RevokeBySubject(_ context.Context, subject string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, ds := range m.secrets {
		if ds.Subject == subject {
			delete(m.secrets, k)
			n++
		}
	}
	return n, nil
}

var (
	_ core.DeviceSecretStore   = (*MemoryDeviceSecretStore)(nil)
	_ core.DeviceSecretRevoker = (*MemoryDeviceSecretStore)(nil)
)
