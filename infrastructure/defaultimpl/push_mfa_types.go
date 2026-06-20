package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// MethodPush is the canonical wire name for the push-notification
// factor in /auth/mfa request bodies and mfa_methods arrays.
const MethodPush = "push"

// PushApprovalStatus is the lifecycle a single push approval flows
// through.
type PushApprovalStatus string

const (
	PushApprovalPending  PushApprovalStatus = "pending"
	PushApprovalApproved PushApprovalStatus = "approved"
	PushApprovalDenied   PushApprovalStatus = "denied"
)

// PushApproval is one in-flight push approval.
type PushApproval struct {
	ID        string
	SubjectID string
	Status    PushApprovalStatus
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PushApprovalStore persists push approvals between Begin and Verify.
type PushApprovalStore interface {
	Put(ctx context.Context, a *PushApproval) error
	Get(ctx context.Context, id string) (*PushApproval, error)
	SetStatus(ctx context.Context, id string, status PushApprovalStatus) error
	Delete(ctx context.Context, id string) error
}

// PushTransport is the operator-supplied push delivery shim.
type PushTransport interface {
	Send(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error
}

// PushTransportFunc is a function adapter for PushTransport.
type PushTransportFunc func(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error

func (f PushTransportFunc) Send(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error {
	return f(ctx, approvalID, subjectID, metadata)
}

// Sentinel errors.
var (
	ErrPushUnsupportedMethod = errors.New("push_mfa: unsupported method")
	ErrPushMissingSubject    = errors.New("push_mfa: missing subject")
	ErrPushMissingApprovalID = errors.New("push_mfa: missing approval id")
	ErrPushSubjectMismatch   = errors.New("push_mfa: subject mismatch")
	ErrPushApprovalNotFound  = errors.New("push_mfa: approval not found")
	ErrPushApprovalDenied    = errors.New("push_mfa: approval denied")
	ErrPushApprovalTimeout   = errors.New("push_mfa: approval timed out")
	ErrPushApprovalInvalid   = errors.New("push_mfa: invalid approval entry")
	ErrPushApprovalResolved  = errors.New("push_mfa: approval already resolved")
)

// Interface guards.
var (
	_ PushApprovalStore = (*MemoryPushApprovalStore)(nil)
	_ PushTransport     = PushTransportFunc(nil)
)

// MemoryPushApprovalStore is a process-local PushApprovalStore.
type MemoryPushApprovalStore struct {
	mu      sync.Mutex
	entries map[string]*PushApproval
}

func NewMemoryPushApprovalStore() *MemoryPushApprovalStore {
	return &MemoryPushApprovalStore{entries: make(map[string]*PushApproval)}
}

func (m *MemoryPushApprovalStore) Put(_ context.Context, a *PushApproval) error {
	if a == nil || a.ID == "" || a.SubjectID == "" {
		return ErrPushApprovalInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *a
	m.entries[a.ID] = &cp
	return nil
}

func (m *MemoryPushApprovalStore) Get(_ context.Context, id string) (*PushApproval, error) {
	if id == "" {
		return nil, ErrPushApprovalNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok {
		return nil, ErrPushApprovalNotFound
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(m.entries, id)
		return nil, ErrPushApprovalNotFound
	}
	cp := *entry
	return &cp, nil
}

func (m *MemoryPushApprovalStore) SetStatus(_ context.Context, id string, status PushApprovalStatus) error {
	if id == "" {
		return ErrPushApprovalNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok {
		return ErrPushApprovalNotFound
	}
	if entry.Status == status {
		return nil
	}
	if entry.Status != PushApprovalPending {
		return ErrPushApprovalResolved
	}
	entry.Status = status
	return nil
}

func (m *MemoryPushApprovalStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, id)
	return nil
}

// newPushApprovalID mints a 32-byte crypto/rand identifier.
func newPushApprovalID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
