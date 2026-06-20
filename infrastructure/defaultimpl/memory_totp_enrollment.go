package defaultimpl

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// MemoryTOTPEnrollmentStore is an in-process store that plays THREE roles for
// TOTP self-service: it is the authenticators.TOTPStore the login-time TOTP
// authenticator reads secrets from, the sso.MFAEnrollmentStore the /me/mfa
// list+unbind view uses, and the sso.TOTPEnrollmentWriter the enrollment
// confirm handler commits to. Wiring ONE instance as BOTH the TOTP
// authenticator's store and the server's MFAEnrollmentStore is what makes a
// freshly enrolled factor immediately usable at login — the secret the
// confirm step persists is the secret the verifier reads.
//
// Suitable for dev/tests/single-process. Secrets are MUST-encrypt material;
// production multi-replica deployments use the SQLite (or an operator) peer.
//
// One TOTP secret per user: TOTP verification keys on the user (GetSecret takes
// a userID), so a second enrollment REPLACES the prior secret + factor rather
// than accumulating a second secret that login could never reach.
type MemoryTOTPEnrollmentStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte                 // userID -> raw secret
	factors map[string]core.MFAEnrolledFactor // userID -> the single TOTP factor
}

func NewMemoryTOTPEnrollmentStore() *MemoryTOTPEnrollmentStore {
	return &MemoryTOTPEnrollmentStore{
		secrets: make(map[string][]byte),
		factors: make(map[string]core.MFAEnrolledFactor),
	}
}

// AddTOTPFactor commits a verified secret and records the factor. Replaces any
// prior TOTP factor for userID (see type doc). Caller-supplied bytes are copied
// so post-call mutation can't leak into stored state.
func (m *MemoryTOTPEnrollmentStore) AddTOTPFactor(_ context.Context, userID, factorID, label string, secret []byte) error {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[userID] = cp
	m.factors[userID] = core.MFAEnrolledFactor{
		ID:      factorID,
		Method:  authenticators.MethodTOTP,
		Label:   label,
		AddedAt: time.Now(),
	}
	return nil
}

// GetSecret satisfies authenticators.TOTPStore for the login-time verifier.
// A copy is returned so callers can't mutate stored state.
func (m *MemoryTOTPEnrollmentStore) GetSecret(_ context.Context, userID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.secrets[userID]
	if !ok {
		return nil, authenticators.ErrTOTPNoSecret
	}
	cp := make([]byte, len(s))
	copy(cp, s)
	return cp, nil
}

// ListFactors returns the user's TOTP factor (0 or 1 element).
func (m *MemoryTOTPEnrollmentStore) ListFactors(_ context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.factors[userID]
	if !ok {
		return []core.MFAEnrolledFactor{}, nil
	}
	return []core.MFAEnrolledFactor{f}, nil
}

// RemoveFactor unbinds the user's TOTP factor when factorID matches, clearing
// the secret too. Idempotent; a non-matching factorID is a no-op — ownership is
// enforced by the handler via ListFactors before it calls here.
func (m *MemoryTOTPEnrollmentStore) RemoveFactor(_ context.Context, userID, factorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.factors[userID]; ok && f.ID == factorID {
		delete(m.factors, userID)
		delete(m.secrets, userID)
	}
	return nil
}

var (
	_ sso.MFAEnrollmentStore   = (*MemoryTOTPEnrollmentStore)(nil)
	_ sso.TOTPEnrollmentWriter = (*MemoryTOTPEnrollmentStore)(nil)
	_ authenticators.TOTPStore = (*MemoryTOTPEnrollmentStore)(nil)
)
