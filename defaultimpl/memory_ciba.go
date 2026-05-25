package defaultimpl

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// cibaIDBytes is the random suffix size for auth_req_id tokens. 32
// bytes / 256 bits matches the entropy floor of the MFA challenge +
// push approval ids so the audit trail looks uniform.
const cibaIDBytes = 32

// MemoryCIBAStore is an in-process [oauth.CIBAStore]. Single-replica
// dev / tests; cluster deploys MUST ship the SQLite (or Redis) peer so
// an Issue on replica A is resolvable by the callback hitting replica
// B and the poll hitting replica C.
type MemoryCIBAStore struct {
	mu      sync.Mutex
	entries map[string]*oauth.CIBARequest
}

// NewMemoryCIBAStore returns an empty in-process store.
func NewMemoryCIBAStore() *MemoryCIBAStore {
	return &MemoryCIBAStore{entries: make(map[string]*oauth.CIBARequest)}
}

// Issue mints an auth_req_id, persists a PENDING request. SubjectID +
// ClientID required; either empty → ErrCIBARequestInvalid.
func (m *MemoryCIBAStore) Issue(_ context.Context, req *oauth.CIBARequest) (string, error) {
	if req == nil || req.SubjectID == "" || req.ClientID == "" {
		return "", oauth.ErrCIBARequestInvalid
	}
	id, err := GenerateCIBAAuthReqID()
	if err != nil {
		return "", err
	}
	stored := &oauth.CIBARequest{
		AuthReqID:               id,
		ClientID:                req.ClientID,
		SubjectID:               req.SubjectID,
		Provider:                req.Provider,
		Scopes:                  append([]string(nil), req.Scopes...),
		ACRValues:               req.ACRValues,
		BindingMessage:          req.BindingMessage,
		Resources:               append([]string(nil), req.Resources...),
		Nonce:                   req.Nonce,
		ClientNotificationToken: req.ClientNotificationToken,
		RequestContext:          cloneRawBytes(req.RequestContext),
		Status:                  oauth.CIBAPending,
		Interval:                req.Interval,
		CreatedAt:               req.CreatedAt,
		ExpiresAt:               req.ExpiresAt,
	}
	m.mu.Lock()
	m.entries[id] = stored
	m.mu.Unlock()
	return id, nil
}

// Get returns the request; missing / expired → ErrCIBARequestNotFound.
func (m *MemoryCIBAStore) Get(_ context.Context, authReqID string) (*oauth.CIBARequest, error) {
	if authReqID == "" {
		return nil, oauth.ErrCIBARequestNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[authReqID]
	if !ok {
		return nil, oauth.ErrCIBARequestNotFound
	}
	if entry.IsExpired() {
		delete(m.entries, authReqID)
		return nil, oauth.ErrCIBARequestNotFound
	}
	cp := *entry
	cp.Scopes = append([]string(nil), entry.Scopes...)
	cp.Resources = append([]string(nil), entry.Resources...)
	cp.RequestContext = cloneRawBytes(entry.RequestContext)
	return &cp, nil
}

// SetStatus transitions Pending → Approved/Denied. Same-status no-op;
// refuses re-resolution (ErrCIBARequestResolved); missing →
// ErrCIBARequestNotFound.
func (m *MemoryCIBAStore) SetStatus(_ context.Context, authReqID string, status oauth.CIBAStatus) error {
	if authReqID == "" {
		return oauth.ErrCIBARequestNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[authReqID]
	if !ok {
		return oauth.ErrCIBARequestNotFound
	}
	if entry.Status == status {
		return nil
	}
	if entry.Status != oauth.CIBAPending {
		return oauth.ErrCIBARequestResolved
	}
	entry.Status = status
	return nil
}

// UpdateLastPoll records the most recent poll for slow_down.
func (m *MemoryCIBAStore) UpdateLastPoll(_ context.Context, authReqID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[authReqID]; ok {
		entry.LastPoll = t
	}
	return nil
}

// Delete drops the entry. Idempotent (missing id → nil).
func (m *MemoryCIBAStore) Delete(_ context.Context, authReqID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, authReqID)
	return nil
}

// GenerateCIBAAuthReqID mints a crypto/rand auth_req_id with the
// oauth.AuthReqIDPrefix namespace. Exposed so custom oauth.CIBAStore
// implementations reuse the same shape.
func GenerateCIBAAuthReqID() (string, error) {
	buf := make([]byte, cibaIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return oauth.AuthReqIDPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

var _ oauth.CIBAStore = (*MemoryCIBAStore)(nil)
