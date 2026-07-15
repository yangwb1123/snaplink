package memorystorecredential

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/shared/core"
	"golang.org/x/crypto/bcrypt"
)

// MemoryPasswordCredentialStore is an in-memory core.PasswordCredentialStore.
// Suitable for single-node and dev; a database peer (defaultimpl/sqlite) backs
// multi-replica. Passwords are bcrypt-hashed at rest.
type MemoryPasswordCredentialStore struct {
	mu        sync.RWMutex
	hashes    map[string]string    // userID -> bcrypt hash
	changedAt map[string]time.Time // userID -> time the current hash was set (core.PasswordAgeReader)
	dummy     []byte               // cost-matched dummy for unknown-user timing parity
	dummyCost int                  // bcrypt cost the current dummy was minted at
}

// NewMemoryPasswordCredentialStore returns an empty store. The dummy hash is
// generated at bcrypt.DefaultCost so VerifyPassword spends a comparable amount
// of time on the unknown-user path as on a real compare (the same
// anti-enumeration shape the password authenticator uses). When a higher-cost
// hash is later imported via SetPasswordHash the dummy is re-minted to that
// cost (see raiseDummyCost) so the miss path stays comparable to the SLOWEST
// real verify — otherwise a cost-10 dummy would finish faster than a cost-12
// imported hash and leak "this username is unknown" as a timing oracle.
func NewMemoryPasswordCredentialStore() *MemoryPasswordCredentialStore {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), bcrypt.DefaultCost)
	return &MemoryPasswordCredentialStore{
		hashes:    make(map[string]string),
		changedAt: make(map[string]time.Time),
		dummy:     dummy,
		dummyCost: bcrypt.DefaultCost,
	}
}

// raiseDummyCost re-mints the timing-equalization dummy at cost when cost
// exceeds the current dummy cost, so the unknown-user path stays comparable to
// the slowest stored hash. Caller MUST hold m.mu. A bcrypt.GenerateFromPassword
// failure leaves the existing dummy in place (best-effort timing parity).
func (m *MemoryPasswordCredentialStore) raiseDummyCost(cost int) {
	if cost <= m.dummyCost || cost > bcrypt.MaxCost {
		return
	}
	if d, err := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), cost); err == nil {
		m.dummy = d
		m.dummyCost = cost
	}
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
	m.changedAt[userID] = time.Now()
	m.mu.Unlock()
	return nil
}

// SetPasswordHash seeds a pre-computed bcrypt hash for userID (satisfies
// core.PasswordHashImporter). Rejects a non-bcrypt value so a plaintext can
// never be stored masquerading as a hash.
func (m *MemoryPasswordCredentialStore) SetPasswordHash(_ context.Context, userID, bcryptHash string) error {
	if userID == "" {
		return core.ErrPasswordMismatch
	}
	if !strings.HasPrefix(bcryptHash, "$2") {
		return errors.New("defaultimpl: SetPasswordHash requires a bcrypt hash")
	}
	m.mu.Lock()
	m.hashes[userID] = bcryptHash
	m.changedAt[userID] = time.Now()
	// Keep the miss-path dummy as slow as the slowest imported hash so an
	// unknown-username login isn't measurably faster (enumeration timing
	// oracle). A malformed hash yields cost 0 from bcrypt.Cost, which is a
	// no-op against the >= DefaultCost dummy.
	if cost, err := bcrypt.Cost([]byte(bcryptHash)); err == nil {
		m.raiseDummyCost(cost)
	}
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

// HasPassword implements identitylink.PasswordPresenceChecker: reports
// whether userID has a stored credential, WITHOUT the timing-equalization
// VerifyPassword performs. Safe to expose directly — this is a
// governance/guard query (the self-service identity-unlink "don't lock
// yourself out" check) on the CALLER's OWN authenticated subject, not a login
// path, so there is no anti-enumeration concern to preserve.
func (m *MemoryPasswordCredentialStore) HasPassword(_ context.Context, userID string) (bool, error) {
	m.mu.RLock()
	_, ok := m.hashes[userID]
	m.mu.RUnlock()
	return ok, nil
}

// PasswordChangedAt implements core.PasswordAgeReader: returns the time
// userID's current credential was set (via SetPassword or SetPasswordHash).
// Returns an error for an unknown user so the login-time expiry gate
// (interfaces/sso rejectExpiredPassword) fails open rather than treating a
// zero time as "always expired".
func (m *MemoryPasswordCredentialStore) PasswordChangedAt(_ context.Context, userID string) (time.Time, error) {
	m.mu.RLock()
	t, ok := m.changedAt[userID]
	m.mu.RUnlock()
	if !ok {
		return time.Time{}, errors.New("defaultimpl: no password credential for user")
	}
	return t, nil
}

// DeletePassword implements core.PasswordCredentialDeleter: removes userID's
// stored hash (if any), used by the admin user-CRUD delete path so a deleted
// user's credential doesn't linger as an orphaned, unreachable hash. Idempotent
// — an unknown userID is a no-op, matching SetPassword's create-or-replace
// shape rather than erroring on "nothing to delete".
func (m *MemoryPasswordCredentialStore) DeletePassword(_ context.Context, userID string) error {
	m.mu.Lock()
	delete(m.hashes, userID)
	delete(m.changedAt, userID)
	m.mu.Unlock()
	return nil
}

var (
	_ core.PasswordCredentialStore         = (*MemoryPasswordCredentialStore)(nil)
	_ core.PasswordHashImporter            = (*MemoryPasswordCredentialStore)(nil)
	_ core.PasswordAgeReader               = (*MemoryPasswordCredentialStore)(nil)
	_ core.PasswordCredentialDeleter       = (*MemoryPasswordCredentialStore)(nil)
	_ identitylink.PasswordPresenceChecker = (*MemoryPasswordCredentialStore)(nil)
)
