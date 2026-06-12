package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
)


// MemoryClientStore stores client applications in memory. Implements the full
// sso.ClientStore including the admin extensions (List/Update/Delete/Rotate).
type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*sso.Client
}

func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{clients: make(map[string]*sso.Client)}
}

// AddSeed inserts a client without the duplicate-check that Add enforces.
// Used by the YAML loader to populate the store at boot — duplicates in the
// config file should fail explicitly via validation, not collide here.
// Hashes the plaintext Secret and RegistrationAccessToken at insertion so the
// in-memory store has the same hash-at-rest guarantees as the SQLite backend.
func (m *MemoryClientStore) AddSeed(client *sso.Client) {
	if client.Secret != "" && !isBcryptHash(client.Secret) {
		if h, err := hashClientSecret(client.Secret); err == nil {
			client.Secret = h
		}
	}
	if client.RegistrationAccessToken != "" && !isBcryptHash(client.RegistrationAccessToken) {
		if h, err := hashClientSecret(client.RegistrationAccessToken); err == nil {
			client.RegistrationAccessToken = h
		}
	}
	m.mu.Lock()
	m.clients[client.ID] = client
	m.mu.Unlock()
}

func (m *MemoryClientStore) Get(_ context.Context, clientID string) (*sso.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[clientID]
	if !ok {
		return nil, sso.ErrNoSuchClient
	}
	return c, nil
}

func (m *MemoryClientStore) ValidateSecret(_ context.Context, clientID, clientSecret string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[clientID]
	if !ok {
		return sso.ErrNoSuchClient
	}
	// compareClientSecret uses bcrypt.CompareHashAndPassword when the stored
	// value starts with "$2" (a bcrypt hash), falling back to constant-time
	// string compare for plaintext secrets in pre-migration / hand-authored
	// stores. See client_secret.go.
	if !compareClientSecret(c.Secret, clientSecret) {
		return fmt.Errorf("invalid client secret")
	}
	if !c.Active {
		return fmt.Errorf("client is inactive")
	}
	return nil
}

func (m *MemoryClientStore) List(_ context.Context) ([]*sso.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*sso.Client, 0, len(m.clients))
	for _, c := range m.clients {
		out = append(out, c)
	}
	return out, nil
}

// ListByTenant satisfies sso.TenantScopedClientStore: returns
// every client whose TenantID matches. Empty tenantID returns
// every client whose TenantID is also empty (the "no-tenant"
// bucket — useful for single-tenant deployments and the
// platform-admin client).
func (m *MemoryClientStore) ListByTenant(_ context.Context, tenantID string) ([]*sso.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*sso.Client
	for _, c := range m.clients {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}

// Stats satisfies sso.ClientStoreStats: a cheap, order-independent
// fingerprint of the client set so the discovery-doc cache can skip its
// full List() + re-projection when nothing discovery-relevant changed.
// The map snapshot under RLock is the only allocation; the digest is
// pure CPU. The hash covers exactly the fields the discovery document
// derives from a client (see core.ClientSetFingerprint), so a scope
// edit or a new client flips it while a secret rotation does not.
func (m *MemoryClientStore) Stats(_ context.Context) (int, string, error) {
	m.mu.RLock()
	clients := make([]*sso.Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	m.mu.RUnlock()
	return len(clients), core.ClientSetFingerprint(clients), nil
}

func (m *MemoryClientStore) Add(_ context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("defaultimpl: client.ID required")
	}
	if c.Secret != "" && !isBcryptHash(c.Secret) {
		h, err := hashClientSecret(c.Secret)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash secret: %w", err)
		}
		c.Secret = h
	}
	if c.RegistrationAccessToken != "" && !isBcryptHash(c.RegistrationAccessToken) {
		h, err := hashClientSecret(c.RegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash registration token: %w", err)
		}
		c.RegistrationAccessToken = h
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.clients[c.ID]; exists {
		return sso.ErrClientExists
	}
	m.clients[c.ID] = c
	return nil
}

func (m *MemoryClientStore) Update(_ context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("defaultimpl: client.ID required")
	}
	if c.Secret != "" && !isBcryptHash(c.Secret) {
		h, err := hashClientSecret(c.Secret)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash secret: %w", err)
		}
		c.Secret = h
	}
	if c.RegistrationAccessToken != "" && !isBcryptHash(c.RegistrationAccessToken) {
		h, err := hashClientSecret(c.RegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash registration token: %w", err)
		}
		c.RegistrationAccessToken = h
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.clients[c.ID]; !exists {
		return sso.ErrNoSuchClient
	}
	m.clients[c.ID] = c
	return nil
}

func (m *MemoryClientStore) Delete(_ context.Context, clientID string) error {
	m.mu.Lock()
	delete(m.clients, clientID)
	m.mu.Unlock()
	return nil
}

func (m *MemoryClientStore) RotateSecret(_ context.Context, clientID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[clientID]
	if !ok {
		return "", sso.ErrNoSuchClient
	}
	plaintext, err := generateSecret(32)
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plaintext)
	if err != nil {
		return "", fmt.Errorf("defaultimpl: hash rotated secret: %w", err)
	}
	// Store the hash; return the plaintext (one-time reveal).
	c.Secret = hashed
	return plaintext, nil
}

// Compile-time interface checks.
var (
	_ sso.ClientStore             = (*MemoryClientStore)(nil)
	_ sso.TenantScopedClientStore = (*MemoryClientStore)(nil)
	_ core.ClientStoreStats       = (*MemoryClientStore)(nil)
)

// generateSecret returns a base64url-encoded random string. 32 bytes ≈ 256
// bits of entropy — comfortable for client secrets that may be long-lived.
func generateSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("defaultimpl: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
