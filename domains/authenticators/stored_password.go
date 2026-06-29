package authenticators

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/snaplink/sso/interfaces/sso"
)

// ErrStoredPasswordAuthFailed is returned when the username cannot be resolved
// OR the password does not match. One error for both cases — the caller must
// not distinguish (anti-enumeration).
var ErrStoredPasswordAuthFailed = errors.New("authenticators: password authentication failed")

// UserIDResolver maps a login username to the stable user ID a
// PasswordCredentialStore is keyed by — the same id the bearer's sub carries,
// so POST /me/password and login operate on one credential. A resolver
// typically looks the username up via the UserProvider (by email/external id)
// or, in the simplest deployments, returns the username unchanged.
type UserIDResolver func(ctx context.Context, username string) (userID string, err error)

// NewStoredPasswordVerifier returns a PasswordVerifier backed by a
// sso.PasswordCredentialStore. It resolves the username to a userID, then
// verifies the password against the store; on success it returns
// AuthResult{UserID, Provider: password}.
func NewStoredPasswordVerifier(store sso.PasswordCredentialStore, resolve UserIDResolver) PasswordVerifier {
	return PasswordVerifierFunc(func(ctx context.Context, username, password string) (*sso.AuthResult, error) {
		userID, err := resolve(ctx, username)
		if err != nil || userID == "" {
			_ = store.VerifyPassword(ctx, "", password) // timing parity on unknown user
			return nil, ErrStoredPasswordAuthFailed
		}
		if verr := store.VerifyPassword(ctx, userID, password); verr != nil {
			return nil, ErrStoredPasswordAuthFailed
		}
		return &sso.AuthResult{UserID: userID, Provider: MethodPassword}, nil
	})
}

// PasswordHistoryStore persists a bounded ring of previous password hashes for
// each user so CheckHistory can reject password reuse. The interface is
// separate from PasswordPolicyValidator because the store is deployment-
// specific and the validator is an SPI contract.
type PasswordHistoryStore interface {
	// Record stores a hashed password for a user, retaining at most n entries.
	Record(ctx context.Context, userID, hashedPassword string) error
	// CheckHistory returns true if the new password matches any of the stored
	// history entries (i.e. it has been used before and should be rejected).
	CheckHistory(ctx context.Context, userID, newPassword string) (bool, error)
}

// MemoryPasswordHistoryStore is an in-memory PasswordHistoryStore that retains
// the last N password hashes per user. N=MaxHistory from PasswordPolicyConfig.
type MemoryPasswordHistoryStore struct {
	mu    sync.Mutex
	rings map[string][]string // userID -> ring of bcrypt hashes
	max   int
}

// NewMemoryPasswordHistoryStore creates a MemoryPasswordHistoryStore retaining
// at most max entries per user. max <= 0 disables history (no-op).
func NewMemoryPasswordHistoryStore(max int) *MemoryPasswordHistoryStore {
	return &MemoryPasswordHistoryStore{
		rings: make(map[string][]string),
		max:   max,
	}
}

func (m *MemoryPasswordHistoryStore) Record(_ context.Context, userID, hashedPassword string) error {
	if m.max <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ring := m.rings[userID]
	if len(ring) >= m.max {
		ring = ring[1:] // drop oldest
	}
	m.rings[userID] = append(ring, hashedPassword)
	return nil
}

func (m *MemoryPasswordHistoryStore) CheckHistory(_ context.Context, userID, newPassword string) (bool, error) {
	if m.max <= 0 {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, hash := range m.rings[userID] {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) == nil {
			return true, nil
		}
	}
	return false, nil
}
