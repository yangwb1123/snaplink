package defaultmfa

import (
	"context"
	"sync"

	"github.com/yangwb1123/snaplink/shared/core"
)

// MemoryMFAEnrollmentStore is an in-memory core.MFAEnrollmentStore for the
// self-service MFA management view. Suitable for dev/tests; an operator with
// concrete TOTP/WebAuthn backends implements the interface over those.
type MemoryMFAEnrollmentStore struct {
	mu      sync.RWMutex
	factors map[string][]core.MFAEnrolledFactor // userID -> factors
}

func NewMemoryMFAEnrollmentStore() *MemoryMFAEnrollmentStore {
	return &MemoryMFAEnrollmentStore{factors: make(map[string][]core.MFAEnrolledFactor)}
}

// AddFactor registers a factor for userID (test/seed helper — registration
// proper happens in the operator's factor backend).
func (m *MemoryMFAEnrollmentStore) AddFactor(userID string, f core.MFAEnrolledFactor) {
	m.mu.Lock()
	m.factors[userID] = append(m.factors[userID], f)
	m.mu.Unlock()
}

func (m *MemoryMFAEnrollmentStore) ListFactors(_ context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src := m.factors[userID]
	out := make([]core.MFAEnrolledFactor, len(src))
	copy(out, src)
	return out, nil
}

func (m *MemoryMFAEnrollmentStore) RemoveFactor(_ context.Context, userID, factorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.factors[userID]
	out := src[:0:0] // new backing array; idempotent when factorID is absent
	for _, f := range src {
		if f.ID != factorID {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		delete(m.factors, userID)
	} else {
		m.factors[userID] = out
	}
	return nil
}

var _ core.MFAEnrollmentStore = (*MemoryMFAEnrollmentStore)(nil)
