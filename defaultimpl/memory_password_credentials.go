package defaultimpl

import (
	"context"
	"sync"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"golang.org/x/crypto/bcrypt"
)

// MemoryPasswordCredentialStore is an in-memory sso.PasswordCredentialStore.
// Suitable for single-node and dev; a database peer (defaultimpl/sqlite) backs
// multi-replica. Passwords are bcrypt-hashed at rest.
type MemoryPasswordCredentialStore struct {
	mu     sync.RWMutex
	hashes map[string]string // userID -> bcrypt hash
	dummy  []byte            // cost-matched dummy for unknown-user timing parity
}

// NewMemoryPasswordCredentialStore returns an empty store. The dummy hash is
// generated once at bcrypt.DefaultCost so VerifyPassword spends a comparable
// amount of time on the unknown-user path as on a real compare (the same
// anti-enumeration shape the password authenticator uses).
func NewMemoryPasswordCredentialStore() *MemoryPasswordCredentialStore {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), bcrypt.DefaultCost)
	return &MemoryPasswordCredentialStore{hashes: make(map[string]string), dummy: dummy}
}

func (m *MemoryPasswordCredentialStore) SetPassword(_ context.Context, userID, newPassword string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.hashes[userID] = string(h)
	m.mu.Unlock()
	return nil
}

func (m *MemoryPasswordCredentialStore) VerifyPassword(_ context.Context, userID, plaintext string) error {
	m.mu.RLock()
	hash, ok := m.hashes[userID]
	dummy := m.dummy
	m.mu.RUnlock()
	if !ok {
		// Unknown user: run a compare against the dummy so the timing is
		// indistinguishable from a real mismatch, then collapse to the same
		// error (anti-enumeration).
		_ = bcrypt.CompareHashAndPassword(dummy, []byte(plaintext))
		return core.ErrPasswordMismatch
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) != nil {
		return core.ErrPasswordMismatch
	}
	return nil
}

var _ sso.PasswordCredentialStore = (*MemoryPasswordCredentialStore)(nil)
